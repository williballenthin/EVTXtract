#!/bin/python
#    This file is part of recover-evtx.
#
#   Copyright 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Version v0.1
import os
import logging
import mmap
import contextlib
import struct

from Evtx.Evtx import ChunkHeader
from Evtx.BinaryParser import OverrunBufferException


def offset_seems_like_record(buf, offset):
    """
    Return True if the offset appears to be an EVTX record.

    @type buf: bytestring
    @type offset: int
    @rtype boolean
    """
    logger = logging.getLogger("find_evtx_records")
    logger.debug("Checking for a record at %s", hex(offset))
    try:
        magic, size = struct.unpack_from("<II", buf, offset)
        if magic != 0x00002a2a:
            logger.debug("Bad magic")
            return False
        if not (0x30 <= size <= 0x10000):
            logger.debug("Bad size")
            return False
        try:
            size2 = struct.unpack_from("<I", buf, offset + size - 4)[0]
        except struct.error:
            logger.debug("Bad buffer size")
            return False
        if size != size2:
            logger.debug("Bad size2 (%s vs %s)", hex(size), hex(size2))
            return False
    except OverrunBufferException:
        logger.debug("Bad buffer size")
        return False
    logger.debug("Looks good")
    return True


def find_lost_evtx_records(buf, ranges):
    """
    Generates offsets of apparent EVTX records from the given buffer
      that fall within the given ranges.

    @type buf: bytestring
    @type ranges: list of (int, int)
    @rtype: generator of int
    """
    logger = logging.getLogger("find_evtx_records")
    for range_ in ranges:

        start, end = range_
        logger.debug("Searching for records in the range (%s, %s)",
                     hex(start), hex(end))
        index = buf.find("\x2a\x2a\x00\x00", start, end)
        while index != -1:
            if offset_seems_like_record(buf, index):
                yield index
            index = buf.find("\x2a\x2a\x00\x00", index + 1, end)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Find offsets of EVTX records.")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug logging.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("chunk_list", type=str,
                        help="Path to the file containing list of chunks")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s %(levelname)s %(name)s %(message)s")

    ranges = []
    with open(args.chunk_list, "rb") as f:
        range_start = 0
        for line in f.read().split("L\n"):
            if "CHUNK_VALID" in line:
                _, __, offset = line.partition("\t")
                offset = offset.rstrip("\r")
                offset = int(offset, 0x10)
                ranges.append((range_start, offset))
                range_start = offset + 0x10000
        # TODO(wb): is os.stat platform dependent?
        ranges.append((range_start, os.stat(args.evtx).st_size))

    with open(args.evtx, "rb") as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            for offset in find_lost_evtx_records(buf, ranges):
                print("%s\t%s" % ("LOST_RECORD", hex(offset)))


if __name__ == "__main__":
    main()
