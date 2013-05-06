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
import mmap
import contextlib

# TODO(wb): fallback to standard xml parser
from lxml import etree
from Evtx.Evtx import ChunkHeader
from Evtx.Nodes import BXmlTypeNode

from find_evtx_chunks import CHUNK_HIT_TYPE


def to_lxml(record):
    """
    @type record: Record
    """
    return etree.fromstring("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>%s" %
                            (record.root().xml([]).encode("utf-8")))


def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    """
    @type node: Element
    @type tag: str
    @type ns: str
    """
    return node.find("%s%s" % (ns, tag))


def get_eid(record):
    return get_eid(get_eid(to_lxml(record), "System"), "EventID")


def get_template(root):
    substitutions = root.substitutions()
    fixed_substitutions = []
    for substitution in substitutions:
        if isinstance(substitution, BXmlTypeNode):
            fixed_substitutions.append(get_template(substitution._root))
        else:
            fixed_substitutions.append(substitution.string())


def merge_template(templates, eid, offset, template):
    """
    Merge a new pair of (offset, template) into an existing
      database of templates organized by eid.

    Modifies the parameter `templates`.

    @type templates: {int: [(int, str)]}
    @type eid: int
    @type offset: int
    @type template: str
    @rtype: None
    """
    if eid in templates:
        found_existing = False
        for offset, existing_template in templates[eid]:
            if template == existing_template:
                found_existing = True
                break
        if not found_existing:
            templates[eid].append((offset, template))
    else:
        templates[eid] = [(offset, template)]


def extract_chunk(buf, offset):
    """
    Parse an EVTX chunk into the XML entries and a dict of templates.
    Dict schema: {EID --> [(offset, template)]}

    @type buf: bytestring
    @type offset: int
    @rtype: (str, {int: [(int, str)]})
    """
    logger = logging.getLogger("extract_records")
    chunk = ChunkHeader(buf, offset)

    xml = []
    templates = {}
    for record in chunk.records():
        try:
            template = record.root().template_format()
            eid = get_eid(record)
            merge_template(templates, eid, record.offset(), template)
            xml.append(record.root().xml([]).encode("utf-8"))
        except UnicodeEncodeError:
            logger.info("Unicode encoding issue processing record at %s" % \
                            hex(record.offset()))
            continue
        except UnicodeDecodeError:
            logger.info("Unicode decoding issue processing record at %s" % \
                            hex(record.offset()))
            continue
    return "\n".join(xml), templates


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Find offsets of EVTX chunk records.")
    parser.add_argument("--records_outfile", type=str, default="records.xml",
                        help="The path to the output file for records")
    parser.add_argument("--templates_outfile", type=str, default="templates.xml",
                        help="The path to the output file for templates")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("chunk_hits_file", type=str,
                        help="Path to the file containing output of"
                        " find_evtx_chunks.py")
    args = parser.parse_args()

    with open(args.evtx, "rb") as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            xml = []
            templates = {}
            with open(args.chunk_hits_file, "rb") as g:
                for line in g.read().split("\n"):
                    hit_type, _, offset = line.partition("\n")
                    if hit_type != CHUNK_HIT_TYPE.CHUNK_VALID:
                        continue
                    offset = int(offset, 0x16)
                    new_xml, new_templates = extract_chunk(buf, offset)
                    xml.append(new_xml)

                    # merge new templates into existing templates
                    for eid in new_templates.keys():
                        offset, template = new_templates[eid]
                        merge_template(templates, eid, offset, template)
    with open(args.records_outfile, "wb") as f:
        f.write("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>")
        f.write("<Events>")
        f.write("\n".join(xml))
        f.write("</Events>")
    with open(args.templates_outfile, "wb") as f:
        for eid in sorted(templates.keys()):
            for offset, template in templates[eid]:
                f.write("TEMPLATE\n")
                f.write("EID: %s\n" % hex(eid))
                f.write("OFFSET: %s\n" % (offset))
                f.write("\n%s\n\n" % template)


if __name__ == "__main__":
    main()
