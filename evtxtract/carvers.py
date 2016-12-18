import re
import struct
import logging
import datetime
from collections import namedtuple

import six
import Evtx.Evtx
import Evtx.Views

import evtxtract.templates


logger = logging.getLogger(__name__)


# TODO: this should be part of python-evtx
EVTX_HEADER_MAGIC = b"ElfChnk"
EVTX_RECORD_MAGIC = b"\x2a\x2a\x00\x00"
CHUNK_SIZE = 0x10000
MIN_CHUNK_HEADER_SIZE = 0x80
MAX_CHUNK_HEADER_SIZE = 0x200


class ParseError(RuntimeError): pass


def is_chunk_header(buf, offset):
    """
    Return True if the offset appears to be an EVTX Chunk header.
    Implementation note: Simply checks the magic header and size field for reasonable values.

    Args:
      buf (buffer): the binary data from which to extract structures.
      offset (int): the address of the potential EVTX chunk header.

    Returns:
      bool: if the offset appears to be an EVTX chunk header.
    """
    if len(buf) < offset + 0x2C:
        # our accesses below will overflow
        return False

    magic = struct.unpack_from("<7s", buf, offset)[0]
    if magic != EVTX_HEADER_MAGIC:
        return False

    size = struct.unpack_from("<I", buf, offset + 0x28)[0]
    if not (MIN_CHUNK_HEADER_SIZE <= size <= MAX_CHUNK_HEADER_SIZE):
        return False

    if len(buf) <= offset + size:
        # the chunk overruns the buffer end
        return False

    try:
        chunk = Evtx.Evtx.ChunkHeader(buf, offset)
    except:
        logger.debug('failed to parse chunk header', exc_info=True)
        return False

    if len(buf) < offset + CHUNK_SIZE:
        return False

    if chunk.calculate_header_checksum() != chunk.header_checksum():
        return False

    if chunk.calculate_data_checksum() != chunk.data_checksum():
        return False

    return True


def find_evtx_chunks(buf):
    """
    Scans the given data for valid EVTX chunk structures.

    Args:
      buf (buffer): the binary data from which to extract structures.

    Returns:
      iterable[int]: generator of offsets of chunks
    """
    offset = 0
    while True:
        offset = buf.find(EVTX_HEADER_MAGIC, offset)
        if offset == -1:
            break

        if is_chunk_header(buf, offset):
            yield offset

        offset += 1


def is_record(buf, offset):
    """
    Return True if the offset appears to be an EVTX record.

    Args:
      buf (buffer): the binary data from which to extract structures.
      offset (int): the address of the potential record.

    Returns:
      bool: if its a record.
    """

    if len(buf) < offset + 8:
        return False

    magic, size = struct.unpack_from("<II", buf, offset)
    if magic != 0x00002a2a:
        return False

    if not (0x30 <= size <= 0x10000):
        return False

    if len(buf) < offset + size:
        return False

    size2 = struct.unpack_from("<I", buf, offset + size - 4)[0]
    if size != size2:
        return False

    return True


def find_evtx_records(buf):
    """
    Generates offsets of apparent EVTX records from the given buffer.

    Args:
      buf (buffer): the binary data from which to extract structures.

    Returns:
      iterable[int]: the offsets of EVTX records.
    """
    offset = 0
    while True:
        offset = buf.find(EVTX_RECORD_MAGIC, offset)
        if offset == -1:
            break

        if is_record(buf, offset):
            yield offset

        offset += 1


RecoveredRecord = namedtuple('RecoveredRecord', ['offset', 'eid', 'xml'])


def extract_chunk_records(buf, offset):
    """
    Generates EVTX records from the EVTX chunk at the given offset.

    Args:
      buf (buffer): the binary data from which to extract structures.
      offset (int): offset to EVTX chunk

    Returns:
      iterable[int]: the offsets of EVTX records.
    """
    try:
        chunk = Evtx.Evtx.ChunkHeader(buf, offset)
    except:
        raise ParseError('failed to parse chunk header')

    cache = {}
    for record in chunk.records():
        try:
            record_xml = Evtx.Views.evtx_record_xml_view(record, cache=cache)
            eid = evtxtract.utils.get_eid(record_xml)
            yield RecoveredRecord(record.offset(), eid, record_xml)

        except UnicodeEncodeError:
            logger.info("Unicode encoding issue processing record at 0x%X", record.offset())
            continue

        except UnicodeDecodeError:
            logger.info("Unicode decoding issue processing record at 0x%X", record.offset())
            continue

        except Evtx.Evtx.InvalidRecordException:
            logger.info("EVTX parsing issue processing record at 0x%X", record.offset())
            continue

        except Exception as e:
            logger.info("Unknown exception processing record at 0x%X", record.offset(), exc_info=True)
            continue


def extract_chunk_templates(buf, offset):
    """
    Generates EVTX record templates from the EVTX chunk at the given offset.

    Args:
      buf (buffer): the binary data from which to extract structures.
      offset (int): offset to EVTX chunk.

    Returns:
      iterable[evtxtract.templates.Template]: a generator of the things you asked for.
    """

    try:
        chunk = Evtx.Evtx.ChunkHeader(buf, offset)
    except:
        raise ParseError('failed to parse chunk header')

    cache = {}
    for record in chunk.records():
        try:
            yield evtxtract.templates.get_template(record)
        except UnicodeEncodeError:
            logger.info("Unicode encoding issue processing record at 0x%X", record.offset())
            continue

        except UnicodeDecodeError:
            logger.info("Unicode decoding issue processing record at 0x%X", record.offset())
            continue

        except Evtx.Evtx.InvalidRecordException:
            logger.info("EVTX parsing issue processing record at 0x%X", record.offset())
            continue

        except Exception as e:
            logger.info("Unknown exception processing record at 0x%X", record.offset(), exc_info=True)
            continue


# map from byte value to boolean
# the key values correspond to evtx node types
VALID_SUBSTITUTION_TYPES = [False for _ in range(256)]
for i in range(22):
    VALID_SUBSTITUTION_TYPES[i] = True
VALID_SUBSTITUTION_TYPES[33] = True
VALID_SUBSTITUTION_TYPES[129] = True


class MaxOffsetReached(Exception): pass


def does_root_have_resident_template(buf, offset, max_offset):
    """
    Guess whether an RootNode has a resident template
      from the given buffer and offset, not parsing
      beyond the given max_offset.

    Args:
      buf (buffer): the binary data from which to extract structures.
      offset (int): address of an EVTX record.
      max_offset (int): don't parse beyond this address.

    Returns:
      boolean: if the RootNode has a resident template.

    Raises:
      MaxOffsetReached: if the given max offset was reached while parsing.
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
        return True

    ofs += 4  # template_id or size

    if max_offset < ofs + 4 + (4 * min(maybe_num_subs or 2, 4)):
        return False

    for i in range(min(maybe_num_subs or 2, 4)):
        byte = struct.unpack_from("<B", buf, ofs + 3 + (i * 4))[0]
        if byte != 0:
            return True

    for i in range(min(maybe_num_subs or 2, 4)):
        byte = struct.unpack_from("<B", buf, ofs + 2 + (i * 4))[0]
        if not VALID_SUBSTITUTION_TYPES[byte]:
            return True

    return False


def extract_root_substitutions(buf, offset, max_offset):
    """
    Parse a RootNode into a list of its substitutions, not parsing beyond
      the max offset.

    Args:
      buf (buffer): the binary data from which to extract structures.
      offset (int): address of an EVTX record.
      max_offset (int): don't parse beyond this address.

    Returns:
      list[tuple[int, variant]]: list of substitution tuples (type, value).

    Raises:
      ParseError: for various reasons, including invalid timestamps and overruns.
    """
    ofs = offset
    token = struct.unpack_from("<b", buf, ofs)[0]
    if token == 0x0F:  # stream start
        ofs += 4

    ofs += 6  # template offset

    if does_root_have_resident_template(buf, offset, max_offset):
        # have to hope that the template begins immediately
        # template_offset = struct.unpack_from("<I", buf, ofs)[0]
        logger.debug("0x%x: resident template", offset)
        ofs += 4  # next offset
        ofs += 4  # guid
        ofs += 0x10  # template_length
        template_length = struct.unpack_from("<I", buf, ofs)[0]
        ofs += 4
        ofs += template_length  # num_subs
    else:
        logger.debug("0x%x: non-resident template", offset)
        ofs += 4  # num_subs

    num_subs = struct.unpack_from("<I", buf, ofs)[0]
    if num_subs > 100:
        raise ParseError("Unexpected number of substitutions: %d at %s" %
                         (num_subs, hex(ofs)))

    ofs += 4  # begin sub list

    substitutions = []
    for _ in range(num_subs):
        size, type_ = struct.unpack_from("<HB", buf, ofs)
        if not VALID_SUBSTITUTION_TYPES[type_]:
            raise ParseError('Unexpected substitution type: ' + hex(type_))

        substitutions.append((type_, size))
        ofs += 4

    ret = []
    for i, pair in enumerate(substitutions):
        type_, size = pair
        if ofs > max_offset:
            raise MaxOffsetReached("Substitutions overran record buffer.")

        value = None
        #[0] = parse_null_type_node,
        if type_ == 0x0:
            value = None
            ret.append((type_, value))

        #[1] = parse_wstring_type_node,
        elif type_ == 0x1:
            s = buf[ofs:ofs + size]
            value = s.decode("utf-16le").replace("<", "&gt;").replace(">", "&lt;")
            ret.append((type_, value))

        #[2] = parse_string_type_node,
        elif type_ == 0x2:
            s = buf[ofs:ofs + size]
            value = s.decode("utf-8").replace("<", "&gt;").replace(">", "&lt;")
            ret.append((type_, value))

        #[3] = parse_signed_byte_type_node,
        elif type_ == 0x3:
            value = struct.unpack_from("<b", buf, ofs)[0]
            ret.append((type_, value))

        #[4] = parse_unsigned_byte_type_node,
        elif type_ == 0x4:
            value = struct.unpack_from("<B", buf, ofs)[0]
            ret.append((type_, value))

        #[5] = parse_signed_word_type_node,
        elif type_ == 0x5:
            value = struct.unpack_from("<h", buf, ofs)[0]
            ret.append((type_, value))

        #[6] = parse_unsigned_word_type_node,
        elif type_ == 0x6:
            value = struct.unpack_from("<H", buf, ofs)[0]
            ret.append((type_, value))

        #[7] = parse_signed_dword_type_node,
        elif type_ == 0x7:
            value = struct.unpack_from("<i", buf, ofs)[0]
            ret.append((type_, value))

        #[8] = parse_unsigned_dword_type_node,
        elif type_ == 0x8:
            value = struct.unpack_from("<I", buf, ofs)[0]
            ret.append((type_, value))

        #[9] = parse_signed_qword_type_node,
        elif type_ == 0x9:
            value = struct.unpack_from("<q", buf, ofs)[0]
            ret.append((type_, value))

        #[10] = parse_unsigned_qword_type_node,
        elif type_ == 0xA:
            value = struct.unpack_from("<Q", buf, ofs)[0]
            ret.append((type_, value))

        #[11] = parse_float_type_node,
        elif type_ == 0xB:
            value = struct.unpack_from("<f", buf, ofs)[0]
            ret.append((type_, value))

        #[12] = parse_double_type_node,
        elif type_ == 0xC:
            value = struct.unpack_from("<d", buf, ofs)[0]
            ret.append((type_, value))

        #[13] = parse_boolean_type_node,
        elif type_ == 0xD:
            value = struct.unpack_from("<I", buf, ofs)[0] > 1
            ret.append((type_, value))

        #[14] = parse_binary_type_node,
        elif type_ == 0xE:
            value = buf[ofs:ofs + size]
            ret.append((type_, value))

        #[15] = parse_guid_type_node,
        elif type_ == 0xF:
            _bin = buf[offset:offset + 16]

            # Yeah, this is ugly
            h = [six.indexbytes(_bin, i) for i in range(len(_bin))]
            value = """{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}""".format(
                h[3], h[2], h[1], h[0],
                h[5], h[4],
                h[7], h[6],
                h[8], h[9],
                h[10], h[11], h[12], h[13], h[14], h[15])
            ret.append((type_, value))

        #[16] = parse_size_type_node,
        elif type_ == 0x10:
            if size == 0x4:
                value = struct.unpack_from("<I", buf, ofs)[0]
            elif size == 0x8:
                value = struct.unpack_from("<Q", buf, ofs)[0]
            else:
                raise ParseError('unexpected sizetypenode value: ' + hex(size))

            ret.append((type_, value))

        #[17] = parse_filetime_type_node,
        elif type_ == 0x11:
            qword = struct.unpack_from("<Q", buf, ofs)[0]
            try:
                value = datetime.datetime.utcfromtimestamp(float(qword) * 1e-7 - 11644473600)
            except ValueError:
                raise ParseError('invalid timestamp')

            ret.append((type_, value))

        #[18] = parse_systemtime_type_node,
        elif type_ == 0x12:
            parts = struct.unpack_from("<WWWWWWWW", buf, ofs)
            value = datetime.datetime(parts[0], parts[1],
                                      parts[3],  # skip part 2 (day of week)
                                      parts[4], parts[5],
                                      parts[6], parts[7])
            ret.append((type_, value))

        #[19] = parse_sid_type_node,  -- SIDTypeNode, 0x13
        elif type_ == 0x13:
            version, num_elements = struct.unpack_from("<BB", buf, ofs)
            id_high, id_low = struct.unpack_from(">IH", buf, ofs + 2)
            value = "S-%d-%d" % (version, (id_high << 16) ^ id_low)
            for i in range(num_elements):
                val = struct.unpack_from("<I", buf, ofs + 8 + (4 * i))
                value += "-%d" % val
            ret.append((type_, value))

        #[20] = parse_hex32_type_node,  -- Hex32TypeNoe, 0x14
        elif type_ == 0x14:
            value = "0x"
            for c in buf[ofs:ofs + size][::-1]:
                if not isinstance(c, (int)):
                    c = ord(c)
                value += "%02x" % c
            ret.append((type_, value))

        #[21] = parse_hex64_type_node,  -- Hex64TypeNode, 0x15
        elif type_ == 0x15:
            value = "0x"
            for c in buf[ofs:ofs + size][::-1]:
                if not isinstance(c, (int)):
                    c = ord(c)
                value += "%02x" % c
            ret.append((type_, value))

        #[33] = parse_bxml_type_node,  -- BXmlTypeNode, 0x21
        elif type_ == 0x21:
            subs = extract_root_substitutions(buf, ofs, max_offset)
            ret.extend(subs)

        #[129] = WstringArrayTypeNode, 0x81
        elif type_ == 0x81:

            value = []

            bin = buf[ofs:ofs + size]
            while len(bin) > 0:
                match = re.search(b"((?:[^\x00].)+)", bin)
                if match:
                    frag = match.group()
                    value.append(frag.decode("utf-16"))
                    bin = bin[len(frag) + 2:]
                    if len(bin) == 0:
                        break

                frag = re.search(b"(\x00*)", bin).group()
                if len(frag) % 2 == 0:
                    for _ in range(len(frag) // 2):
                        value.append('')

                else:
                    raise ParseException("Error parsing uneven substring of NULLs")

                bin = bin[len(frag):]

            if value[-1].strip("\x00") == "":
                value = value[:-1]

            ret.append((type_, value))

        else:
            raise ParseError("Unexpected type encountered: " + hex(type_))

        ofs += size
    return ret


ExtractedRecord = namedtuple(
    'ExtractedRecord', ['offset', 'num', 'timestamp', 'substitutions'])


def extract_record(buf, offset):
    """
    Parse an EVTX record into a convenient dictionary of fields.

    Args:
      buf (buffer): the binary data from which to extract structures.
      offset (int): address of the EVTX record.

    Returns:
      ExtractedRecord: the thing you asked for.

    Raises:
      ParseError: for various reasons, including invalid timestamps and overruns.
    """
    if not is_record(buf, offset):
        raise ValueError('not a record')

    record_size, record_num, qword = struct.unpack_from("<IQQ", buf, offset + 0x4)
    timestamp = datetime.datetime.utcfromtimestamp(float(qword) * 1e-7 - 11644473600)
    root_offset = offset + 0x18
    try:
        substitutions = extract_root_substitutions(buf, root_offset, offset + record_size)
    except struct.error:
        raise ParseError('buffer overrun')

    return ExtractedRecord(offset, record_num, timestamp, substitutions)
