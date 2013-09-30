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
import logging
import mmap
import contextlib
import struct

from Evtx.Evtx import ChunkHeader
from Evtx.BinaryParser import OverrunBufferException

EVTX_HEADER_MAGIC = "ElfChnk"


def does_offset_seems_like_chunk_header(buf, offset):
    """
    Return True if the offset appears to be an EVTX Chunk header.
    Implementation note: Simply checks the magic header and size field for reasonable values.

    @type buf: bytestring
    @type offset: int
    @rtype boolean
    """
    logger = logging.getLogger("find_evtx_chunks")
    logger.debug("Chunk header check: Checking for a chunk at %s", hex(offset))
    try:
        if struct.unpack_from("<7s", buf, offset)[0] != EVTX_HEADER_MAGIC:
            logger.debug("Chunk header check: Failed: Bad magic")
            return False
        if not (0x80 <= struct.unpack_from("<I", buf, offset + 0x28)[0] <= 0x200):
            logger.debug("Chunk header check: Failed: Bad size")
            return False
    except OverrunBufferException:
        logger.debug("Chunk header check: Failed: Bad buffer size")
        return False
    logger.debug("Chunk header check: Success")
    return True


#noinspection PyClassHasNoInit,PyPep8Naming
class CHUNK_HIT_TYPE:
    """
    Enumeration of types of chunk hits.
    """
    CHUNK_VALID = 0       # The chunk appears to be valid
    CHUNK_BAD_HEADER = 1  # The chunk has a bad header valid
    CHUNK_BAD_DATA = 2    # The chunk's data checksum does not validate
    CHUNK_BAD_SIZE = 3    # The chunk's data has the wrong size


def find_evtx_chunks(buf):
    """
    Generates tuples (CHUNK_HIT_TYPE, offset) from the given buffer.

    @type buf: bytestring
    @rtype: generator of (int, int)
    """
    index = buf.find(EVTX_HEADER_MAGIC)
    while index != -1:
        if does_offset_seems_like_chunk_header(buf, index):
            chunk = ChunkHeader(buf, index)

            if len(buf) - index < 0x10000:
                yield (CHUNK_HIT_TYPE.CHUNK_BAD_SIZE, index)
            elif chunk.calculate_header_checksum() != chunk.header_checksum():
                yield (CHUNK_HIT_TYPE.CHUNK_BAD_HEADER, index)
            elif chunk.calculate_data_checksum() != chunk.data_checksum():
                yield (CHUNK_HIT_TYPE.CHUNK_BAD_DATA, index)
            else:
                yield (CHUNK_HIT_TYPE.CHUNK_VALID, index)
        index = buf.find(EVTX_HEADER_MAGIC, index + 1)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Find offsets of EVTX chunk headers.")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug logging.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    with open(args.evtx, "rb") as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            for hit_type, offset in find_evtx_chunks(buf):
                if hit_type == CHUNK_HIT_TYPE.CHUNK_BAD_HEADER:
                    print("%s\t%s" % ("CHUNK_BAD_HEADER", hex(offset)))
                elif hit_type == CHUNK_HIT_TYPE.CHUNK_BAD_DATA:
                    print("%s\t%s" % ("CHUNK_BAD_DATA", hex(offset)))
                elif hit_type == CHUNK_HIT_TYPE.CHUNK_BAD_SIZE:
                    print("%s\t%s" % ("CHUNK_BAD_SIZE", hex(offset)))
                elif hit_type == CHUNK_HIT_TYPE.CHUNK_VALID:
                    print("%s\t%s" % ("CHUNK_VALID", hex(offset)))
                else:
                    raise "Unknown CHUNK_HIT_TYPE: %d" % hit_type

if __name__ == "__main__":
    main()
