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

from recovery_utils import TemplateDatabase
from recovery_utils import TemplateEIDConflictError
from recovery_utils import TemplateNotFoundError


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Reconstruct lost EVTX records using recovered templates.")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debugging output")
    parser.add_argument("--assume_first_template", action="store_true",
                        help="Assume first template with ID in file matches."
                        " Warning: Not for forensics.")
    parser.add_argument("templates", type=str,
                        help="Path to the file containing recovered templates")
    parser.add_argument("records", type=str,
                        help="Path to the file containing recovered records")
    parser.add_argument("reconstructed_outfile", type=str,
                        default="reconstructed_records.xml",
                        help="Path to the file that will contain "
                        "reconstructed records")
    parser.add_argument("unreconstructed_outfile", type=str,
                        default="unreconstructed_records.txt",
                        help="Path to the file that will contain "
                        "unreconstructed records")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="# %(asctime)s %(levelname)s %(name)s %(message)s")

    logger = logging.getLogger("reconstruct_lost_records")

    with open(args.templates, "rb") as f:
        templates_txt = f.read()
    templates = TemplateDatabase()
    templates.deserialize(templates_txt,
                          warn_on_conflict=not args.assume_first_template)

    with open(args.records, "rb") as f:
        records_txt = f.read()

    num_reconstructed = 0
    num_unreconstructed = 0
    with open(args.reconstructed_outfile, "wb") as fixed:
        fixed.write("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>")
        fixed.write("<Events>")
        with open(args.unreconstructed_outfile, "wb") as unfixed:
            for record_txt in records_txt.split("RECORD\n"):
                if record_txt == "" or "EID" not in record_txt:
                    continue

                record_lines = record_txt.split("\n")
                eid_line = record_lines[3]
                _, __, eid = eid_line.partition(": ")
                eid = int(eid)

                substitutions = []
                for substitution_line in record_lines[4:]:
                    if "substitution" not in substitution_line:
                        continue
                    index = int(substitution_line.partition("-")[2].partition(" ")[0])
                    type_ = int(substitution_line.partition("(")[2].partition(")")[0], 0x10)
                    substitution = substitution_line.partition(": ")[2]
                    substitutions.append((index, type_, substitution))
#                substitutions = map(lambda p: (p[1], p[2]),
#                                    sorted(substitutions, key=lambda p: p[0]))
                substitutions = sorted(substitutions, key=lambda p: p[0])


                try:
                    logger.debug("Fetching template for EID: %d num_subs: %d" % (eid, len(substitutions)))
                    template = templates.get_template(eid, substitutions,
                                                      exact_match=not args.assume_first_template)
                except TemplateEIDConflictError as e:
                    raise e
                except TemplateNotFoundError as e:
                    unfixed.write("RECORD\n")
                    unfixed.write(record_txt)
                    num_unreconstructed += 1
                    logger.debug("Unable to reconstruct record with EID %d", eid)
                    continue
                fixed.write(template.insert_substitutions(substitutions))
                num_reconstructed += 1
                logger.debug("Reconstructed record with EID %d", eid)
        fixed.write("</Events>")

    print("# Number of reconstructed records: %d" % num_reconstructed)
    print("# Number of records unable to reconstruct: %d" % num_unreconstructed)


if __name__ == "__main__":
    main()
