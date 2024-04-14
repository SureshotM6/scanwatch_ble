#!/usr/bin/env python3

from binascii import crc32
from pathlib import Path
import struct
from typing import Any, Dict
from Crypto.Signature import eddsa

SIGNATURE_KEYS = {
    'ScanWatch':
    eddsa.import_public_key(
        b'\x20\x92\x76\x4b\x15\x2b\xe4\x13\xeb\xb5\x61\x25\x48\x3f\x39\xc5\x7d\x7f\x8e\x87\xb9\x49\x8b\x95\xa7\x6a\x41\x89\xbe\xf1\x38\x18'
    ),
    'ScanWatch 2':
    eddsa.import_public_key(
        b'\x3e\x17\xdd\xac\x39\x89\xe1\x68\xf2\x12\xc2\x6f\x55\x35\xba\x42\xcd\x4f\x31\xb9\x0f\xdb\xf1\x0c\xb2\x07\x28\xbe\xa6\x24\x80\xc7'
    ),
    'Body Scan':
    eddsa.import_public_key(
        b'\x03\xdd\xbd\x7d\xb5\x33\xa5\x71\x7e\xad\x6d\xe5\x42\x74\x05\xa6\xf5\x60\xd2\xca\x9d\xff\x64\x17\x32\xeb\xb2\xfb\x6b\xaf\x09\xf7'
    ),
}

FW_IE_TO_NAME = {
    1: "appl",  # application @ 0x27000 (NRF52840) or 0x4000 (MK24F12)
    4: "bl",  # bootloader  @ 0xfc000 (NRF52840) or 0 (MK24F12)
    8: "sd",  # mbr and soft device @ 0 (NRF52840)
    10: "sig",  # signature (type 1 is ed25519)
    # unused for scanwatch
    2: "wifi",
    3: "bluetooth",
    5: "cpld",
    7: "analog_frontend",
    12: "st wcopro",
    13: "wifi2",
    14: "bluetooth2",
}

FwInfo = Dict[str, Dict[str, Any]]


def parse_fw_hdr(buf: bytes, off: int = 0) -> FwInfo:
    """Parses the firmware header (ext table) from bytes
    Header format:
        u16 version (must be 1)
        u16 length (must be 0x4c)
        Array of ext table entries:
            u16 ie
            u16 entry_len
            u32 addr
            u32 fw_len
            Either for normal firmwares:
                u32 crc
                u32 version
            Or for a signature
                u32 signature_type
    """
    buf = buf[off:]
    version, hdrlen = struct.unpack_from("<HH", buf)
    assert version == 1
    hdrlen += 4 + 4
    assert len(buf) >= hdrlen
    buf = buf[:hdrlen]
    crc = int.from_bytes(buf[-4:], byteorder="little")
    buf = buf[:-4]
    assert crc32(buf) == crc

    fws = {}

    off = 4
    while off < len(buf):
        ie, length = struct.unpack_from("<HH", buf, off)
        off += 4

        if ie not in FW_IE_TO_NAME or length not in (12, 16):
            print(f"unknown ie {ie} {length}")
            off += length
            continue

        addr, fwlen = struct.unpack_from("<II", buf, off)
        fws[FW_IE_TO_NAME[ie]] = {"addr": addr, "len": fwlen}

        if ie == 10:
            (sign_type, ) = struct.unpack_from("<I", buf, off + 8)
            fws[FW_IE_TO_NAME[ie]]["sign_type"] = sign_type
        else:
            crc, ver = struct.unpack_from("<II", buf, off + 8)
            fws[FW_IE_TO_NAME[ie]].update({'crc': crc, 'version': ver})

        off += length

    return fws


def parse_v0_fw_hdr(buf: bytes) -> FwInfo:
    """Parse the wrapped header used on older scales"""
    # total_len 8C 06 0E 00
    # hdrver 01 00 00 00
    # version 73 06 00 00
    # addr 84 00 00 00 len 28 AD 07 00 crc 55 C8 3C 0E
    # addr AC AD 07 00 len 1D 8D 05 00
    # addr CC 3A 0D 00 len B9 8B 00 00
    # hdrcrc F8 FF 49 93
    # ...
    # datacrc 4C 97 02 EC

    totlen, hdrver, ver = struct.unpack_from("<III", buf)
    if totlen != len(buf):
        raise ValueError('not a length')

    if hdrver != 1:
        raise ValueError('unknown header version')

    crc = int.from_bytes(buf[:], byteorder="little")

    crc = int.from_bytes(buf[0x28:0x2c], byteorder="little")
    assert crc32(buf[:0x28]) == crc

    info = parse_fw_hdr(buf, 0x2c)

    info['hdr'] = {
        'addr': 0,
        'len': 0x2c,
        'version': ver,
    }

    return info


def total_fw_len(info: FwInfo) -> int:
    return max(x["addr"] + x["len"] for x in info.values())


def verify_fw_crcs(data: bytes, info: FwInfo):
    for name, attrs in info.items():
        if 'crc' not in attrs:
            continue
        addr = attrs['addr']
        length = attrs['len']
        print(f'verifying {name} @ {addr:x} +{length:x}')

        # align length to 4 bytes
        length = (length + 3) & ~3

        crc = crc32(data[addr:addr + length])
        if crc != attrs['crc']:
            raise ValueError(
                f'CRC for {name}: {crc:08x} != {attrs["crc"]:08x}')


def verify_signature(data: bytes, info: FwInfo) -> str:
    if 'sig' not in info:
        return 'no signature'

    sig = info['sig']
    assert total_fw_len(info) == sig['addr'] + sig['len']
    assert sig['sign_type'] == 1
    assert sig['len'] == 64

    s = data[sig['addr']:sig['addr'] + 64]

    # ed25519
    for name, key in SIGNATURE_KEYS.items():
        verifier = eddsa.new(key, 'rfc8032')
        try:
            verifier.verify(data[:sig['addr']], s)
            return name
        except Exception:
            pass

    raise ValueError('No valid signature')


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    parser.add_argument("--extract", type=str)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    if (args.extract is None) ^ (args.out is None):
        parser.error('--extract and --out must be used together')

    data = args.file.read_bytes()
    try:
        info = parse_v0_fw_hdr(data)
    except ValueError:
        info = parse_fw_hdr(data)
    print(info)
    print(f"total len: {total_fw_len(info)}")

    try:
        verify_fw_crcs(data, info)
        if 'sig' in info:
            model = verify_signature(data, info)
            print(f'signature is valid for {model}')
    except ValueError as e:
        print(f'ERR: verification failed: {e}')

    if args.extract is not None:
        addr = info[args.extract]["addr"]
        length = info[args.extract]["len"]
        args.out.write_bytes(data[addr:addr + length])


if __name__ == "__main__":
    main()
