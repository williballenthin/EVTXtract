import os
import sys
import logging
import os.path
import argparse

import evtxtract
import evtxtract.carvers


logger = logging.getLogger(__name__)


def output_record(args, r):

    xmlhead = '<?xml version="1.0" encoding="UTF-8"?>\n<evtxtract>'
    xmlfoot = '</evtxtract>'
    if isinstance(r, evtxtract.CompleteRecord):
        try:
            if args.split:
                fname = "{}-{}.xml".format(r.eid, r.offset)
                fpath = os.path.join(args.out, fname)
                with open(fpath, "wb") as f:
                    f.write(xmlhead)
                    f.write(r.xml.encode('utf-8'))
                    f.write(xmlfoot)
            else:
                os.write(sys.stdout.fileno(), r.xml.encode('utf-8'))
        except Exception as e:
            logger.warn('failed to output record at offset: 0x%x: %s', r.offset, str(e), exc_info=True)
        else:
            sys.stdout.flush()

    elif isinstance(r, evtxtract.IncompleteRecord):
        try:
            if args.split:
                fname = "{}-{}-incomplete.xml".format(r.eid, r.offset)
                fpath = os.path.join(args.out, fname)
                with open(fpath, "wb") as f:
                    f.write(xmlhead.encode('utf-8'))
                    f.write(format_incomplete_record(r).encode('utf-8'))
                    f.write(xmlfoot.encode('utf-8'))
            else:
                os.write(sys.stdout.fileno(), format_incomplete_record(r).encode('utf-8'))
        except Exception as e:
            logger.warn('failed to output record at offset: 0x%x: %s', r.offset, str(e), exc_info=True)
        else:
            sys.stdout.flush()


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
    parser.add_argument("-s", "--split", action="store_true",
                        help="split each event into its own file")
    parser.add_argument("-o", "--out", metavar='output-directory', action="store",
                        help="output directory to store split files")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    elif args.quiet:
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.split and not args.out:
        logger.error('Error: the -o argument is required when using -s. please provide an output directory with -o')
        exit(1)

    if args.out and not os.path.isdir(args.out):
        logger.error('Error: {0} is not a directory'.format(args.out))
        exit(1)

    with evtxtract.utils.Mmap(args.input) as mm:
        num_complete = 0
        num_incomplete = 0

        if not args.split:
            print('<?xml version="1.0" encoding="UTF-8"?>')
            print('<evtxtract>')
        for r in evtxtract.extract(mm):
            
            output_record(args, r)

            if isinstance(r, evtxtract.CompleteRecord):
                num_complete += 1

            elif isinstance(r, evtxtract.IncompleteRecord):
                num_incomplete += 1

            else:
                raise RuntimeError('unexpected return type')

        if not args.split:
            print('</evtxtract>')

        logging.info('recovered %d complete records', num_complete)
        logging.info('recovered %d incomplete records', num_incomplete)


if __name__ == "__main__":
    sys.exit(main())
