import logging
import collections

import evtxtract.utils
import evtxtract.carvers
import evtxtract.templates


logger = logging.getLogger(__name__)

VALUE = 1


class CompleteRecord(object):
    __slots__ = ('offset', 'eid', 'xml')

    def __init__(self, offset, eid, xml):
        super(CompleteRecord, self).__init__()
        self.offset = offset
        self.eid = eid
        self.xml = xml


class IncompleteRecord(object):
    __slots__ = ('offset', 'eid', 'substitutions')

    def __init__(self, offset, eid, substitutions):
        super(IncompleteRecord, self).__init__()
        self.offset = offset
        self.eid = eid
        self.substitutions = substitutions


def extract(buf):
    '''
    Do the EVTXtract algorithm and reconstruct EVTX records from the given data.

    Args:
      buf (buffer): the binary data from which to extract structures.

    Returns:
      iterable[union[CompleteRecord, IncompleteRecord]]: a generator of either
        CompleteRecord or IncompleteRecord. You'll have to type-switch of these
        classes to decide out how to handle them.
    '''
    # this does a full scan of the file (#1)
    chunks = set(evtxtract.carvers.find_evtx_chunks(buf))

    valid_record_offsets = set([])
    for chunk in chunks:
        for record in evtxtract.carvers.extract_chunk_records(buf, chunk):
            valid_record_offsets.add(record.offset)
            yield CompleteRecord(record.offset, record.eid, record.xml)

    # map from eid to dictionary mapping from templateid to template
    templates = collections.defaultdict(dict)
    for chunk in chunks:
        for template in evtxtract.carvers.extract_chunk_templates(buf, chunk):
            templates[template.eid][template.get_id()] = template

    # this does a full scan of the file (#2).
    # needs to be distinct because we must have collected all the templates
    # first.
    for record_offset in evtxtract.carvers.find_evtx_records(buf):
        if record_offset in valid_record_offsets:
            continue

        try:
            record = evtxtract.carvers.extract_record(buf, record_offset)
        except evtxtract.carvers.ParseError as e:
            logger.info('parse error for record at offset: 0x%x: %s', record_offset, str(e))
            continue

        if len(record.substitutions) < 4:
            logger.info('too few substitutions for record at offset: 0x%x', record_offset)
            continue

        # we just know that the EID is substitution index 3
        eid = record.substitutions[3][VALUE]

        matching_templates = set([])
        for template in templates.get(eid, {}).values():
            if template.match_substitutions(record.substitutions):
                matching_templates.add(template)

        if len(matching_templates) == 0:
            logger.info('no matching templates for record at offset: 0x%x', record_offset)
            yield IncompleteRecord(record_offset, eid, record.substitutions)
            continue

        if len(matching_templates) > 1:
            logger.info('too many templates for record at offset: 0x%x', record_offset)
            yield IncompleteRecord(record_offset, eid, record.substitutions)
            continue

        template = list(matching_templates)[0]

        record_xml = template.insert_substitutions(record.substitutions)

        yield CompleteRecord(record_offset, eid, record_xml)
