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

from extract_valid_evtx_records_and_templates import make_replacement


class TemplateEIDConflictError(Exception):
    def __init__(self, value):
        super(TemplateEIDConflictError, self).__init__(value)


def load_templates(templates_txt):
    """
    Parse a string of templates into a dictionary mapping EIDs to their
      templates

    @type templates_txt: str
    @rtype: dict
    @raises: TemplateEIDConflictError
    """
    templates = {}
    for template_txt in templates_txt.split("TEMPLATE\n"):
        if template_txt == "":
            continue
        template_lines = template_txt.split("\n")
        eid_line = template_lines[0]
        _, __, eid = eid_line.partition(": ")
        print eid
        eid = eid.rstrip("\r")
        template = "\n".join(template_lines[3:])
        if eid in templates:
            raise TemplateEIDConflictError("More than one template with EID %d" % eid)
        templates[eid] = template
    return templates


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Reconstruct lost EVTX records using recovered templates.")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debugging output")
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
    templates = load_templates(templates_txt)

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
                try:
                    eid_line = record_lines[3]
                except:
                    print ">>" + record_txt + "<<"
                    return 

                _, __, eid = eid_line.partition(": ")
                eid = eid.rstrip("\r")
                eid = int(eid)

                if eid not in templates:
                    unfixed.write("RECORD\n")
                    unfixed.write(record_txt)
                    num_unreconstructed += 1
                    logger.debug("Unable to reconstruct record with EID %d", eid)
                    continue

                record = templates[eid]
                for substitution_line in record_lines[4:]:
                    if "substitution" not in substitution_line:
                        continue
                    index = substitution_line.partition("-")[2].partition(" ")[0]
                    index = int(index)
                    substitution = substitution_line.partition(": ")[2]
                    record = make_replacement(record, index, substitution)
                fixed.write(record)
                num_reconstructed += 1
                logger.debug("Reconstructed record with EID %d", eid)
        fixed.write("</Events>")

    print("# Number of reconstructed records: %d" % num_reconstructed)
    print("# Number of records unable to reconstruct: %d" % num_unreconstructed)


if __name__ == "__main__":
    main()
