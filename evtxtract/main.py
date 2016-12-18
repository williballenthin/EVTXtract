import sys
import logging

import argparse

import evtxtract
import evtxtract.carvers


logger = logging.getLogger(__name__)


def format_incomplete_record(record):
    ret = []

    ret.append('<Record>')
    ret.append('<Offset>0x%x</Offset>' % (record.offset))
    ret.append('<EventID>%d</EventID>' % (record.eid))
    ret.append('<Substitutions>')
    for i, (type_, value) in enumerate(record.substitutions):
        ret.append('  <Substitution index="%d">' % (i))
        ret.append('    <Type>%d</Type>' % (type_))
        if value is None:
            ret.append('    <Value></Value>')
        else:
            ret.append('    <Value>%s</Value>' % (value))
        ret.append('  </Substitution>')
    ret.append('</Substitutions>')
    ret.append('</Record>')

    return '\n'.join(ret)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Reconstruct EVTX event log records from binary data.")
    parser.add_argument("input", type=str,
                        help="Path to binary input file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Disable all output but errors")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    elif args.quiet:
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.INFO)

    with evtxtract.utils.Mmap(args.input) as mm:
        num_complete = 0
        num_incomplete = 0
        for r in evtxtract.extract(mm):
            if isinstance(r, evtxtract.CompleteRecord):
                num_complete += 1

                try:
                    print(r.xml)
                except Exception as e:
                    logger.warn('failed to output record at offset: 0x%x: %s', r.offset, str(e), exc_info=True)

            elif isinstance(r, evtxtract.IncompleteRecord):
                num_incomplete += 1

                try:
                    print(format_incomplete_record(r))
                except Exception as e:
                    logger.warn('failed to output record at offset: 0x%x: %s', r.offset, str(e), exc_info=True)

            else:
                raise RuntimeError('unexpected return type')

        logging.info('recovered %d complete records', num_complete)
        logging.info('recovered %d incomplete records', num_incomplete)


if __name__ == "__main__":
    sys.exit(main())
