import struct
import logging
from collections import namedtuple

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


def is_chunk_header(buf, offset):
    """
    Return True if the offset appears to be an EVTX Chunk header.
    Implementation note: Simply checks the magic header and size field for reasonable values.

    Args:
      buf (buffer):
      offset (int):

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
      buf (buffer):

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
      buf (buffer):
      offset (int):

    Returns:
      bool:
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
      buf (buffer):

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
    try:
        chunk = Evtx.Evtx.ChunkHeader(buf, offset)
    except:
        logger.warn('failed to parse chunk header', exc_info=True)
        return

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
    try:
        chunk = Evtx.Evtx.ChunkHeader(buf, offset)
    except:
        logger.warn('failed to parse chunk header', exc_info=True)
        return

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
