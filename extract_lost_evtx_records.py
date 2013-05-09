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
import struct
import logging
import mmap
import contextlib
from datetime import datetime


valid_substitution_types = [False for _ in xrange(256)]
for i in xrange(22):
    valid_substitution_types[i] = True
valid_substitution_types[33] = True
valid_substitution_types[129] = True


class MaxOffsetReached(Exception):
    def __init__(self, value):
        super(MaxOffsetReached, self).__init__(value)


def root_has_resident_template(buf, offset, max_offset):
    """
    Guess whether an RootNode has a resident template
      from the given buffer and offset, not parsing
      beyond the given max_offset.

    @type buf: bytestring
    @type offset: int
    @type max_offset: int
    @rtype: boolean
    """
    logger = logging.getLogger("extract_lost_records")
    ofs = offset
    token = struct.unpack_from("<b", buf, ofs)[0]
    if token == 0x0F:  # stream start
        ofs += 4

    ofs += 6  # template offset

    # now, since we don't know where the chunk header is
    #  for this record, we can't use the template offset
    #  to decide if its resident or not
    # instead, we assume that if the template is resident,
    #  then it begins immediately. if this is true, and the
    #  template is resident, then the next fields are:
    #    DWORD next_offset  (range 0-0x10000?, length 0x4)
    #    GUID  template_id (length 0x16, essentially random bytes)
    #    DWORD template_length (range 0-0x10000?, length 0x4)
    # if the template is non-resident, then the fields are:
    #    DWORD num_subs (range 0-100?)
    #    WORD size                            \
    #    BYTE type (value one of 0-21,33,129)  | repeat num_subs times
    #    BYTE zero (value 0)                  /
    # the key takeaway is that we can test
    #   *(ofs + 6 + 4i) (with 0 < i < min(num_subs, 4))
    #  is in the set {0-21, 33, 129}, and that
    #   *(ofs + 7 + 4i) (0 < i < min(num_subs, 4))
    #  is 0.  If these conditions hold, then the template is probably
    #  non-resident.
    #
    # TODO(wb): what if num_subs == 1 or 2?

    ofs += 4  # next_offset or num_subs
    maybe_num_subs = struct.unpack_from("<I", buf, ofs)[0]
    if maybe_num_subs > 100:
        logger.debug("More than 100 subs, resident template")
        return True
    ofs += 4  # template_id or size

    if max_offset < ofs + 4 + (4 * min(maybe_num_subs or 2, 4)):
        return False
    for i in xrange(min(maybe_num_subs or 2, 4)):
        byte = struct.unpack_from("<B", buf, ofs + 3 + (i * 4))[0]
        if byte != 0:
            logger.debug("Non-zero zero field, resident template")
            return True
    for i in xrange(min(maybe_num_subs or 2, 4)):
        byte = struct.unpack_from("<B", buf, ofs + 2 + (i * 4))[0]
        if not valid_substitution_types[byte]:
            logger.debug("Type field not a valid type, resident template")
            return True
    logger.debug("All conditions satisfied, non-resident template")
    return False


def extract_root_substitutions(buf, offset, max_offset):
    """
    Parse a RootNode into a list of its substitutions, not parsing beyond
      the max offset.

    @type buf: bytestring
    @type offset: int
    @type max_offset: int
    @rtype: list of (int, str)
    """
    logger = logging.getLogger("extract_lost_records")
    logger.debug("Extracting RootNode at %s", hex(offset))

    ofs = offset
    token = struct.unpack_from("<b", buf, ofs)[0]
    if token == 0x0F:  # stream start
        ofs += 4

    ofs += 6  # template offset

    if root_has_resident_template(buf, offset, max_offset):
        # have to hope that the template begins immediately
        # template_offset = struct.unpack_from("<I", buf, ofs)[0]
        logger.debug("resident template")
        ofs += 4  # next offset
        ofs += 4  # guid
        ofs += 0x10  # template_length
        template_length = struct.unpack_from("<I", buf, ofs)[0]
        ofs += 4
        ofs += template_length  # num_subs
    else:
        logger.debug("non-resident template")
        ofs += 4  # num_subs

    num_subs = struct.unpack_from("<I", buf, ofs)[0]
    if num_subs > 100:
        raise Exception("Unexpected number of substitutions: %d at %s" % 
                        (num_subs, hex(ofs)))
    ofs += 4  # begin sub list
    logger.debug("There are %d substitutions", num_subs)

    substitutions = []
    for _ in xrange(num_subs):
        size, type_ = struct.unpack_from("<HB", buf, ofs)
        if not valid_substitution_types[type_]:
            raise "Unexpected substitution type: %s" % hex(type_)
        substitutions.append((type_, size))
        ofs += 4

    ret = []
    for i, pair in enumerate(substitutions):
        type_, size = pair
        if ofs > max_offset:
            raise MaxOffsetReached("Substitutions overran record buffer.")
        logger.debug("[%d/%d] substitution type %s at %s length %s", 
                     i + 1, num_subs, hex(type_), hex(ofs), hex(size))
        value = None
        #[0] = parse_null_type_node,
        if type_ == 0x0:
            value = None
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[1] = parse_wstring_type_node,
        elif type_ == 0x1:
            s = buf[ofs:ofs + size]
            value = s.decode("utf-16le").replace("<", "&gt;").replace(">", "&lt;")
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[2] = parse_string_type_node,
        elif type_ == 0x2:
            s = buf[ofs:ofs + size]
            value = s.decode("utf-8").replace("<", "&gt;").replace(">", "&lt;")
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[3] = parse_signed_byte_type_node,
        elif type_ == 0x3:
            value = struct.unpack_from("<b", buf, ofs)[0]
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[4] = parse_unsigned_byte_type_node,
        elif type_ == 0x4:
            value = struct.unpack_from("<B", buf, ofs)[0]
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[5] = parse_signed_word_type_node,
        elif type_ == 0x5:
            value = struct.unpack_from("<h", buf, ofs)[0]
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[6] = parse_unsigned_word_type_node,
        elif type_ == 0x6:
            value = struct.unpack_from("<H", buf, ofs)[0]
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[7] = parse_signed_dword_type_node,
        elif type_ == 0x7:
            value = struct.unpack_from("<i", buf, ofs)[0]
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[8] = parse_unsigned_dword_type_node,
        elif type_ == 0x8:
            value = struct.unpack_from("<I", buf, ofs)[0]
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[9] = parse_signed_qword_type_node,
        elif type_ == 0x9:
            value = struct.unpack_from("<q", buf, ofs)[0]
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[10] = parse_unsigned_qword_type_node,
        elif type_ == 0xA:
            value = struct.unpack_from("<Q", buf, ofs)[0]
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[11] = parse_float_type_node,
        elif type_ == 0xB:
            value = struct.unpack_from("<f", buf, ofs)[0]
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[12] = parse_double_type_node,
        elif type_ == 0xC:
            value = struct.unpack_from("<d", buf, ofs)[0]
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[13] = parse_boolean_type_node,
        elif type_ == 0xD:
            value = struct.unpack_from("<I", buf, ofs)[0] > 1
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[14] = parse_binary_type_node,
        elif type_ == 0xE:
            value = buf[ofs:ofs + size]
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[15] = parse_guid_type_node,
        elif type_ == 0xF:
            _bin = buf[offset:offset + 16]
            h = map(ord, _bin)
            value = "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x" % \
            (h[3], h[2], h[1], h[0],
             h[5], h[4],
             h[7], h[6],
             h[8], h[9],
             h[10], h[11], h[12], h[13], h[14], h[15])
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[16] = parse_size_type_node,
        elif type_ == 0x10:
            if size == 0x4:
                value = struct.unpack_from("<I", buf, ofs)[0]
            elif size == 0x8:
                value = struct.unpack_from("<Q", buf, ofs)[0]
            else:
                raise "Unexpected size for SizeTypeNode: %s" % hex(size)
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[17] = parse_filetime_type_node,
        elif type_ == 0x11:
            qword = struct.unpack_from("<Q", buf, ofs)[0]
            value = datetime.utcfromtimestamp(float(qword) * 1e-7 - 11644473600)
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[18] = parse_systemtime_type_node,
        elif type_ == 0x12:
            parts = struct.unpack_from("<WWWWWWWW", buf, ofs)
            value = datetime.datetime(parts[0], parts[1],
                                      parts[3],  # skip part 2 (day of week)
                                      parts[4], parts[5],
                                      parts[6], parts[7])
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[19] = parse_sid_type_node,  -- SIDTypeNode, 0x13
        elif type_ == 0x13:
            version, num_elements = struct.unpack_from("<BB", buf, ofs)
            id_high, id_low = struct.unpack_from(">IH", buf, ofs + 2)
            value = "S-%d-%d" % (version, (id_high << 16) ^ id_low)
            for i in xrange(num_elements):
                val = struct.unpack_from("<I", buf, ofs + 8 + (4 * i))
                value += "-%d" % val
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[20] = parse_hex32_type_node,  -- Hex32TypeNoe, 0x14
        elif type_ == 0x14:
            value = "0x"
            for c in buf[ofs:ofs + size][::-1]:
                value += "%02x" % ord(c)
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[21] = parse_hex64_type_node,  -- Hex64TypeNode, 0x15
        elif type_ == 0x15:
            value = "0x"
            for c in buf[ofs:ofs + size][::-1]:
                value += "%02x" % ord(c)
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        #[33] = parse_bxml_type_node,  -- BXmlTypeNode, 0x21
        elif type_ == 0x21:
            subs = extract_root_substitutions(buf, ofs, max_offset)
            ret.extend(subs)
        #[129] = TODO, -- WstringArrayTypeNode, 0x81
        elif type_ == 0x81:
            value = []
            bin = buf[ofs:ofs + size]
            for apart in bin.split("\x00\x00\x00"):
                for bpart in apart.split("\x00\x00"):
                    if len(bpart) % 2 == 1:
                        value.append((bpart + "\x00").decode("utf-16").rstrip("\x00"))
                    else:
                        value.append(bpart.decode("utf-16").rstrip("\x00"))
            if value[-1].strip("\x00") == "":
                value = value[:-1]
            ret.append((type_, value))
            logger.debug("Value: %s", value)
        else:
            raise "Unexpected type encountered: %s" % hex(type_)
        ofs += size
    return ret


def extract_lost_record(buf, offset):
    """
    Parse an EVTX record into a convenient dictionary of fields.
    Dict schema: {record_num: int, timestamp: datetime, substitutions: list of (int, variant)}

    @type buf: bytestring
    @type offset: int
    @rtype: dict
    """
    logger = logging.getLogger("extract_lost_records")
    record_size, record_num, qword = struct.unpack_from("<IQQ", buf, offset + 0x4)
    timestamp = datetime.utcfromtimestamp(float(qword) * 1e-7 - 11644473600)
    logger.debug("Extracting lost node at %s, num %s, time %se",
                 hex(offset), hex(record_num), timestamp.isoformat("T") + "Z")
    root_offset = offset + 0x18
    substitutions = extract_root_substitutions(buf, root_offset, 
                                               offset + record_size)
    return {
        "offset": offset,
        "record_num": record_num,
        "timestamp": timestamp,
        "substitutions": substitutions,
        }


def format_record(record):
    """
    Turn a Record dict into a readable string.

    @type record: dict
    @rtype: str
    """
    ret = []
    ret.append("RECORD")
    ret.append("offset: %s" % hex(record["offset"]))
    ret.append("timestamp: %s" % record["timestamp"].isoformat("T") + "Z")
    ret.append("record_num: %s" % record["record_num"])
    ret.append("EID: %s" % record["substitutions"][3][1])
    for i, pair in enumerate(record["substitutions"]):
        type_, value = pair
        val_str = None
        if type_ == 0x81:  # wstring array
            val_str = ", ".join(value)
        elif type_ == 0x11 or type_ == 0x12:
            val_str = value.isoformat("T") + "Z"
        else:
            val_str = str(value)
        ret.append("substitution-%i (%s): %s" % (i, hex(type_), val_str))
    return "\n".join(ret)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Extract lost EVTX records.")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debugging output")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("records_list", type=str,
                        help="The path to the file containing a list of "
                        "record offsets")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="# %(asctime)s %(levelname)s %(name)s %(message)s")

    logger = logging.getLogger("extract_lost_records")

    num_extracted = 0
    num_failures = 0
    with open(args.evtx, "rb") as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            with open(args.records_list, "rb") as g:
                for line in g.read().split("\n"):
                    hit_type, _, offset = line.partition("\t")
                    logger.debug("Processing line: %s, %s", hit_type, offset)
                    if hit_type != "LOST_RECORD":
                        logging.debug("Skipping, cause its not a lost record")
                        continue
                    offset = int(offset, 0x10)
                    try:
                        record = extract_lost_record(buf, offset)
                        print format_record(record)
                        print "\n"
                        num_extracted += 1
                    except Exception:
                        logging.warning("Exception encountered processing lost record at %s", hex(offset), exc_info=True)
                        num_failures += 1

    print("# Number of extracted records: %d" % num_extracted)
    print("# Number of failed record extractions: %d" % num_failures)




if __name__ == "__main__":
    main()
