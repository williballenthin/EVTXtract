import logging

import evtxtract
import evtxtract.carvers

from fixtures import *


#logging.basicConfig(level=logging.DEBUG)
#logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_find_chunks(image_mmap):
    # these offsets were empirically collected from the test image
    expected = set([
        0xc7f000,
        0xf0e000,
        0x1374f20,
        0x70cc000,
        0xd727440,
        0xdfe7000,
        0x18851080,
        0x1c31d000,
        0x20b362c0,
        0x276f8000,
        0x2833e000,
        0x28b4e000,
        0x28b68000,
        0x28d5e000,
        0x28ead000,
        0x2986e000,
        0x2998c000,
        0x29a9c000,
        0x2ff30000,
        0x2ffd0000,
        0x3070f000,
        0x30c1f000,
        0x30c8f000,
        0x30dbf000,
        0x30f2f000,
        0x30fff000,
        0x3126f000,
        0x328eac10,
        0x34b75000,
        0x38835000,
        0x39981910,
        0x39cc07a0,
        0x3b91b000,
    ])

    assert expected == set(evtxtract.carvers.find_evtx_chunks(image_mmap))


def first(s):
    for x in s:
        return x


def test_extract_records(image_mmap):
    # these offsets were empirically collected from the test image
    expected_offsets = set([
        0xf0e200,
        0x70cc200,
        0x70cca30,
        0x1c31d200,
        0x1c31d858,
        0x20b364c0,
        0x20b36b80,
        0x276f8200,
        0x276f88c0,
        0x29a9c200,
        0x30dbf200,
        0x30dbf8c8,
        0x30dbfb68,
        0x30dbfde8,
        0x34b75200,
        0x34b758a0,
        0x3b91b200,
    ])

    # these eids were empirically collected from the test image
    expected_eids = set([
        1,
        2,
        5,
        21,
        22,
        100,
        306,
        823,
        1001,
        1002,
        1006,
        1009,
        1020
    ])

    found_offsets = set([])
    found_eids = set([])
    for chunk_offset in evtxtract.carvers.find_evtx_chunks(image_mmap):
        for recovered_record in evtxtract.carvers.extract_chunk_records(image_mmap, chunk_offset):
            found_offsets.add(recovered_record.offset)
            found_eids.add(recovered_record.eid)

    assert expected_offsets == found_offsets
    assert expected_eids == found_eids


def test_extract_templates(image_mmap):
    # these template ids were empirically collected from the test image
    expected_ids = set([
        "1-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]-[4|6|c]-[5|21|c]-[6|17|c]-[7|15|c]-[8|8|c]-[9|8|c]-[10|10|c]-[11|4|c]-[12|19|c]-[13|15|c]-[14|1|c]-[15|15|c]-[16|1|c]-[17|8|n]",
        "2-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]-[4|6|c]-[5|21|c]-[6|17|c]-[7|15|c]-[8|8|c]-[9|8|c]-[10|10|c]-[11|4|c]-[12|19|c]-[13|15|c]-[14|1|c]-[15|15|c]-[16|1|c]-[17|8|n]",
        "21-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]-[4|6|c]-[5|21|c]-[6|17|c]-[7|15|c]-[8|8|c]-[9|8|c]-[10|10|c]-[11|4|c]-[12|19|c]-[13|15|c]-[14|1|c]-[15|15|c]-[16|1|c]-[17|1|n]-[18|8|n]-[19|1|n]",
        "22-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]-[4|6|c]-[5|21|c]-[6|17|c]-[7|15|c]-[8|8|c]-[9|8|c]-[10|10|c]-[11|4|c]-[12|19|c]-[13|15|c]-[14|1|c]-[15|15|c]-[16|1|c]-[17|1|n]-[18|8|n]-[19|1|n]",
        "5-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]-[4|6|c]-[5|21|c]-[6|17|c]-[7|15|c]-[8|8|c]-[9|8|c]-[10|10|c]-[11|4|c]-[12|19|c]-[13|15|c]-[14|1|c]-[15|15|c]-[16|1|c]-[17|1|n]-[18|1|n]",
        "100-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]-[4|6|c]-[5|21|c]-[6|17|c]-[7|15|c]-[8|8|c]-[9|8|c]-[10|10|c]-[11|4|c]-[12|19|c]-[13|15|c]-[14|1|c]-[15|15|c]-[16|1|c]-[17|8|n]-[18|1|n]",
        "306-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]-[4|6|c]-[5|21|c]-[6|17|c]-[7|15|c]-[8|8|c]-[9|8|c]-[10|10|c]-[11|4|c]-[12|19|c]-[13|15|c]-[14|1|c]-[15|15|c]-[16|1|c]",
        "823-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]-[4|6|c]-[5|21|c]-[6|17|c]-[7|15|c]-[8|8|c]-[9|8|c]-[10|10|c]-[11|4|c]-[12|19|c]-[13|15|c]-[14|1|c]-[15|15|c]-[16|1|c]-[17|8|n]-[18|1|n]-[19|1|n]-[20|20|n]-[21|1|n]",
        "1001-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]-[4|6|c]-[5|21|c]-[6|17|c]-[7|15|c]-[8|8|c]-[9|8|c]-[10|10|c]-[11|4|c]-[12|19|c]-[13|15|c]-[14|1|c]-[15|15|c]-[16|1|c]",
        "1002-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]-[4|6|c]-[5|21|c]-[6|17|c]-[7|15|c]-[8|8|c]-[9|8|c]-[10|10|c]-[11|4|c]-[12|19|c]-[13|15|c]-[14|1|c]-[15|15|c]-[16|1|c]",
        "1006-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]-[4|6|c]-[5|21|c]-[6|17|c]-[7|15|c]-[8|8|c]-[9|8|c]-[10|10|c]-[11|4|c]-[12|19|c]-[13|15|c]-[14|1|c]-[15|15|c]-[16|1|c]-[17|8|n]-[18|13|n]-[19|13|n]",
        "1009-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]-[4|6|c]-[5|21|c]-[6|17|c]-[7|15|c]-[8|8|c]-[9|8|c]-[10|10|c]-[11|4|c]-[12|19|c]-[13|15|c]-[14|1|c]-[15|15|c]-[16|1|c]-[17|1|n]-[18|8|n]-[19|8|n]",
        "1020-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]-[4|6|c]-[5|21|c]-[6|17|c]-[7|15|c]-[8|8|c]-[9|8|c]-[10|10|c]-[11|4|c]-[12|19|c]-[13|15|c]-[14|1|c]-[15|15|c]-[16|1|c]-[17|1|n]",
    ])

    found_ids = set([])
    for chunk_offset in evtxtract.carvers.find_evtx_chunks(image_mmap):
        for template in evtxtract.carvers.extract_chunk_templates(image_mmap, chunk_offset):
            found_ids.add(template.get_id())

    assert expected_ids == found_ids


def test_find_records(image_mmap):
    records = list(evtxtract.carvers.find_evtx_records(image_mmap))
    assert records[0] == 0x317198
    assert records[-1] == 0x3D706A88
    assert len(records) == 1674


def test_evtxtract(image_mmap):
    num_complete = 0
    num_incomplete = 0
    for r in evtxtract.extract(image_mmap):
        if isinstance(r, evtxtract.CompleteRecord):
            num_complete += 1
        elif isinstance(r, evtxtract.IncompleteRecord):
            num_incomplete += 1
        else:
            raise RuntimeError('unexpected return type')

    assert num_complete == 52
    assert num_incomplete == 1615
