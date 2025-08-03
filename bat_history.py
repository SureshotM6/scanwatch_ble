#!/usr/bin/env python3

from typing import Dict
import dblib
import sys
from pathlib import Path
from datetime import datetime
from ctypes import LittleEndianStructure, c_uint32, c_uint16


class BatHistoryIe(LittleEndianStructure):
    _fields_ = [
        ("index", c_uint32),
        ("time", c_uint32 * 32),
        ("bat_i", c_uint16 * 32),
        ("bat_a", c_uint16 * 32),
    ]


history: Dict[datetime, tuple[int, int]] = {}

for file in sys.argv[1:]:
    info, cksum_valid = dblib.parse_dblib(Path(file).read_bytes(), False)
    for _, data in filter(lambda x: x[0] == 0x55, info):
        x = BatHistoryIe.from_buffer_copy(data)
        for i in range(x.index, x.index + 32):
            i %= 32
            if x.time[i] == 0:
                continue
            history[datetime.utcfromtimestamp(x.time[i])] = (x.bat_i[i], x.bat_a[i])

for time, (bat_i, bat_a) in sorted(history.items()):
    print(time, bat_i, bat_a, sep=", ", end=",\n")
