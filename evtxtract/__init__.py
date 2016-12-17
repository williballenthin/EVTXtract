import logging

import evtxtract.utils
import evtxtract.carvers
import evtxtract.templates


logger = logging.getLogger(__name__)

VALUE = 1


def extract(buf):
    '''
    Args:
      buf (buffer):

    Returns
      ...
    '''
    chunks = set(evtxtract.carvers.find_evtx_chunks(buf))

    valid_record_offsets = set([])
    for chunk in chunks:
        for record in evtxtract.carvers.extract_chunk_records(buf, chunk):
            valid_record_offsets.add(record.offset)

    templates = {}
    for chunk in chunks:
        for template in evtxtract.carvers.extract_chunk_templates(buf, chunk):
            templates[template.get_id()] = template

    for record_offset in evtxtract.carvers.find_evtx_records(buf):
        if record_offset in valid_record_offsets:
            continue

        record = evtxtract.carvers.extract_record(buf, record_offset)

        if len(record.substitutions) < 4:
            continue

        # we just know that the EID is substitution index 3
        eid = record.substitutions[3][VALUE]

        matching_templates = set([])
        for template in templates.values():
            if template.match_substitutions(record.substitutions):
                matching_templates.add(template)

        if len(matching_templates) == 0:
            logger.warn('no matching templates for record at offset: 0x%x', record_offset)
            continue

        if len(matching_templates) > 1:
            logger.warn('too many templates for record at offset: 0x%x', record_offset)
            continue

        template = list(matching_templates)[0]

        record_xml = template.insert_substitutions(record.substitutions)

        yield evtxtract.carvers.RecoveredRecord(offset, eid, record_xml)
