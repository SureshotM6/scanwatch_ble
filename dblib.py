from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum, unique
import json
from pathlib import Path
import pprint
import struct
from typing import ClassVar, Dict, List, Tuple, Type
from ctypes import LittleEndianStructure, c_uint32, c_uint16


@unique
class IE(Enum):
    MAC = 0x1 # 00:24:e4:xx:xx:xx
    WSTARGET = 0x2 #
    KL_SECRET = 0x3 # 128-bit hex
    TIMEZONE = 0x4 # 0xc
    LOCALE = 0x7 #
    MFGID = 0xb # 80001f00
    TIME_DELTA = 0xf # 4 b
    FMODE = 0x11 # 4 b
    TRACE_ENABLED = 0x13 # empty
    BAT_AVG = 0x19 #
    BANK_RECOVER_CNT = 0x32 #
    ACCEL_CALIB = 0x43 #
    USER = 0x48 # user id in first long, 0x52 bytes
    UNITS = 0x4a # 0100000000000000
    FACTORY_FW = 0x4c #
    BAT_HISTORY = 0x55 #
    DEBUG_MASK = 0x5b #
    SCREEN_ORDER = 0x68 # 0x180
    STEP_GOAL = 0x6f # 5000
    SLEEP_GOAL = 0x70 # 480 (=8 hours)
    ALARMCLOCK = 0x75 # 0x50 long
    QUARTZ_MILLLIHZ = 0x76 # nominally 32768000
    UNK_WITH_SOFT_VER = 0x77 # 0x16c
    AUTH_DATA = 0x79 #
    UPDATE_INFO = 0x7c # 0x14 long
    PLS_DB_0x800B = 0x7d #
    STEP_MOTOR_PH = 0x81 # 8 bytes
    SWIM_PARAMS = 0x85 # 25 meters
    BT_DISCONNECT = 0x86 # 0x10
    ADXL_TEST_RESULT = 0x88 #
    SWIM_STATUS_DISABLED = 0x90 #
    PUBKEY = 0x98 #
    SESSION_NONCE = 0x99 #
    WALK_PARAMS = 0x9a #
    RUN_PARAMS = 0x9b #
    FACTORY_STATE = 0xa2 # 0
    MCU_TEMP_CAL = 0xa5 #
    EVENT_WITH_TIME = 0xa7 # 0x12 len
    BAT_CHARGE_LIMIT = 0xa8 # not set?
    ANCS_ENABLED_CONFIG = 0xab #
    PAIRING_INFO = 0xaf #
    CAL_LIGHT_SENSOR = 0xb0 #
    THERMISTANCE = 0xb1 #
    OFE_TIA = 0xb2 #
    BATTERY_CAL = 0xb5 # 4193 mV == 985 ADC
    UNITS_12H_CLOCK = 0xb6 # 1 b
    CUST = 0xb8 # 0x88
    STEP_MOTOR_CAL = 0xb9 # 4 b
    ANCS_0xba = 0xba # typo?
    CONTRAST = 0xbb #
    DEMO_MODE = 0xbc #
    OFE_PRESENT = 0xbd #
    ACTIVITY_VASISTAS_MIGRATION_BASE = 0xc0 #
    FEATURE_MASK = 0xc1 # 4 b
    PART_ID = 0xe3 #
    WFTL_ERRORS = 0xe4 # 1 b
    RESET_INFO = 0xe6 # 8 bytes
    ALARM_ENABLED = 0xe8 #
    WFTL_CACHE = 0xed # 4 b
    WLOG_DISPLAY_LEVEL = 0xeb #
    FW_VERSION = 0xf6 # 0100000000000000b50a0000
    NOTIFICATION_DISPLAY = 0xfd # 1 b, tristate
    NOTIFICATION_CACHE = 0x101 # 2
    WFTL_POST_UPDATE2 = 0x102 # 0x48
    VAS_CACHE = 0x103 # 4 b
    ADXL367_MODE = 0x104 # 1 byte, set to 1 if quicklook enabled
    RAW_CACHE = 0x106 # 0xc
    FLASH_CACHE = 0x107 # 4 b
    GAP_PRIVACY_ENABLED = 0x108
    OLED_CONSUMPTION = 0x109 #
    OLED_LUMINANCE = 0x10a #
    ALARMCLOCK_UNKNOWN = 0x112 # size 0x28
    VIB_TEST_TIME = 0x11b # 0x18
    CLASSIFICATION_REGION = 0x11f # 1B
    WRIST_POS = 0x120 # 1 B
    GSS_CACHE = 0x124 # 4 b
    CROWN_CAL = 0x129 #
    CRT = 0x12b # device certificate
    CSR = 0x12c # certificate signing request
    GLYPH_CACHE = 0x130 # 3 b
    ADXL_FIFO_DELAY = 0x131 # 8 bytes
    GSS = 0x132 # 4 b
    WUP_DEVICE = 0x133 #
    SHORTCUT_ACTION = 0x136 # 1 b
    WORKOUT_CACHE = 0x137 # 012014141c1c
    FEATURE_TAGS = 0x13b #
    UNK2 = 0x145 # 8 bytes
    THRESHOLDS = 0x146 # 0x34 long
    LOCAL_NOTIFICATIONS_CONFIG = 0x147 # 0x20
    WORKOUT_SCREEN_ALWAYS_ON = 0x148 #
    COUNTER = 0x149 # 0xc long
    UNK3 = 0x14b # 4 bytes
    UPDATE_STATS = 0x152 #
    ALGO_PARAM = 0x155 #
    MOVE_HANDS = 0x156 # 1B
    RESET_EVENT = 0x15b # 0x2c long
    RAW_DATA_BACKUP = 0x15e # 2
    WPP_TRACE_ENABLED = 0x167 # empty
    GREENTEG_SENSITIVITY_BIN = 0x16a # 1 b
    MENSTRAL_CYCLE_INFO = 0x170 # size 0x1c, up to 3
    MENSTRAL_CYCLE_UNK = 0x174 # size 4
    END = 0xffff


class DbLibEntry(ABC):
    IE_VAL: ClassVar[IE]
    IE_MAP: ClassVar[Dict[IE, Type["DbLibEntry"]]] = {}
    REPR: ClassVar[LittleEndianStructure]

    def __init_subclass__(cls, **kwargs):
        DbLibEntry.IE_MAP[cls.IE_VAL] = cls
        return super().__init_subclass__(**kwargs)

    def __init__(self, repr: LittleEndianStructure) -> None:
        super().__init__()

    @classmethod
    def parse(cls, raw_ie: int, data: bytes) -> "DbLibEntry":
        subcls = cls.IE_MAP[IE(raw_ie)]
        kwargs = {}

        return subcls(subcls.REPR.from_buffer_copy(data))


class BatHistoryIe(DbLibEntry):
    IE_VAL = IE.BAT_HISTORY
    class REPR(LittleEndianStructure):
        _fields_ = [
            ("index", c_uint32),
            ("time", c_uint32 * 32),
            ("bat_i", c_uint16 * 32),
            ("bat_a", c_uint16 * 32),
        ]

    def __init__(self, repr: LittleEndianStructure) -> None:
        self.history: Dict[datetime, tuple[int, int]] = {}
        for i in range(repr.index, repr.index + 32):
            i %= 32
            if repr.time[i] == 0:
                continue
            self.history[datetime.utcfromtimestamp(repr.time[i])] = (repr.bat_i[i], repr.bat_a[i])

    def __str__(self) -> str:
        return str(self.history)


    # for file in sys.argv[1:]:
    #     info, cksum_valid = dblib.parse_dblib(Path(file).read_bytes(), False)
    #     for _, data in filter(lambda x: x[0] == 0x55, info):
    #         x = BatHistoryIe.from_buffer_copy(data)
    #         for i in range(x.index, x.index + 32):
    #             i %= 32
    #             if x.time[i] == 0:
    #                 continue
    #             history[datetime.utcfromtimestamp(x.time[i])] = (x.bat_i[i], x.bat_a[i])

    # for time, (bat_i, bat_a) in sorted(history.items()):
    #     print(time, bat_i, bat_a, sep=", ", end=",\n")



# align for sw1, not for sw2
def parse_dblib(buf: bytes, align: bool) -> Tuple[List[Tuple[int, bytes]], bool]:
    info = []

    off = 0
    while off < len(buf):
        ie, length = struct.unpack_from(f"<HH", buf, off)
        off += 4

        if ie == 0xffff:
            off -= 2
            # update count
            info.append((ie, buf[off : off + 4]))
            # checksum
            cksum, = struct.unpack_from(f"<H", buf, off + 4)
            cksum_valid = sum(buf[:off + 4]) % 0x10000 == cksum
            return info, cksum_valid

        info.append((ie, buf[off : off + length]))
        off += length
        if align:
            # align off
            off = (off + 3) // 4 * 4

    # didn't find proper end!
    return info, False


def maybe_string_value(val: bytes) -> bool:
    return val != b'\x00' and all(map(lambda x: x >= 0x20 and x < 0x7f, val.removesuffix(b'\x00')))


def decode(raw_ie: int, val: bytes):
    try:
        entry = DbLibEntry.parse(raw_ie, val)
        # print(json.dumps(entry))
        # pprint.pprint(entry)
        print(entry.IE_VAL, entry)
    except KeyError:
        ie = IE(raw_ie)
        print(ie, val.hex())
    except ValueError:
        print(f'unknown 0x{raw_ie:x}: {val.hex()}')


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--align', action='store_true')
    parser.add_argument('--decode', action='store_true')
    parser.add_argument("file", type=Path)
    parser.add_argument("ie", type=lambda x: int(x, 0), nargs='*')
    args = parser.parse_args()

    data = args.file.read_bytes()
    info, cksum_valid = parse_dblib(data, args.align)
    for key, val in info:
        if args.ie and key not in args.ie:
            continue

        if args.decode:
            decode(key, val)
        else:
            if maybe_string_value(val):
                print(f'{key:04x}: (s) "{val.decode()}" ({val.hex()})')
            else:
                print(f"{key:04x}: (b) {val.hex()}")

    print(f'Checksum valid: {cksum_valid}')
