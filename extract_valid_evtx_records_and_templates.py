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
import re
import logging
import mmap
import contextlib

# TODO(wb): fallback to standard xml parser
from lxml import etree
from Evtx.Evtx import ChunkHeader
from Evtx.Nodes import BXmlTypeNode


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
    return get_child(get_child(to_lxml(record), "System"), "EventID").text


class Template(object):
    def __init__(self, eid, xml, offset):
        self._eid = eid
        self._xml = xml
        self._offset = offset

    def get_eid(self):
        return self._eid

    def get_id(self):
        ret = ["%s" % self._eid]
        for index, type_ in self._get_placeholders():
            ret.append("[%s|%s]" % (index, type_))
        return "-".join(ret)

    def get_offset(self):
        return self._offset

    def _get_placeholders(self):
        ret = []
        for part in self._xml.split(" Substitution("):
            if "index=" not in part or "type=" not in part:
                continue
            index = int(part.partition("=")[2].partition(",")[0])
            type_ = int(part.partition("type=")[2].partition(",")[0])
            ret.append((index, type_))
        return sorted(ret, key=lambda p: p[0])

    def insert_substitutions(self, substitutions):
        """
        Return a copy of the template with the given substitutions inserted.

        Implementation is a huge hack that depends on the
        brittle template_format() output.

        substitutions should be a list of (index:int, type:int, value:str)

        @type substitutions: list of (int, int, str)
        @rtype: str
        """
        ret = self._xml
        for index, type_, value in substitutions:
            from_pattern = "\[(Normal|Conditional) Substitution\(index=%d, type=\d+\)\]" % index
            ret = re.sub(from_pattern, value, ret)
        return ret


class TemplateDatabase(object):
    def __init__(self):
        # @type self._templates: {str: [Template]}
        self._templates = {}

    def add_template(self, template):
        """
        Merge a new Template into the database.

        @type template: template
        @rtype: None
        """
        id_ = template.get_id()
        if id_ in self._templates:
            found_existing = False
            for other in self._templates[id_]:
                if template.get_xml() == other.get_xml():
                    found_existing = True
                    break
            if not found_existing:
                self._templates[id_].append(template)
        else:
            self._templates[id_] = [template]

    def serialize(self):
        ret = []
        for id_ in sorted(self._templates.keys()):
            for template in self._templates[id_]:
                ret.append("TEMPLATE\n")
                ret.append("ID: %s\n" % template.get_id())
                ret.append("EID: %s\n" % template.get_eid())
                ret.append("OFFSET: %s\n" % template.get_offset())
                ret.append("%s\n\n\n" % template.get_xml())
        return "\n".join(ret)


def get_template(record):
    def make_replacement(template, index, substitution):
        """
        Makes a substitution given a template as a string.

        Implementation is a huge hack that depends on the
        brittle template_format() output.

        @type template: str
        @type index: int
        @type substitution: str
        @rtype: str
        """
        from_pattern = "\[(Normal|Conditional) Substitution\(index=%d, type=\d+\)\]" % index
        return re.sub(from_pattern, substitution, template)

    def get_complete_template(root, current_index):
        """
        Gets the template from a RootNode while resolving any
        nested templates and fixing up their indices.
        Depth first ordering/indexing.

        Implementation is a huge hack that depends on the
          brittle template_format() output.

        @type root: RootNode
        @type current_index: int
        @rtype: str
        """
        template = root.template_format()
        replacements = []
        for index, substitution in enumerate(root.substitutions()):
            # find all sub-templates
            if not isinstance(substitution, BXmlTypeNode):
                replacements.append(current_index + index)
                continue
            subtemplate = get_complete_template(substitution._root,
                                                current_index=current_index + index)
            replacements.append(subtemplate)
            current_index += subtemplate.count("Substitution(index=")
        replacements.reverse()
        for i, replacement in enumerate(replacements):
            index = len(replacements) - i - 1
            if isinstance(replacement, int):
                # fixup index
                from_pattern = "index=%d," % index
                to_pattern = "index=%d," % replacement
                template = template.replace(from_pattern, to_pattern)
            if isinstance(replacement, basestring):
                # insert sub-template
                template = make_replacement(template, index, replacement)
        return template

    template = get_complete_template(record.root(), current_index=0)
    return Template(get_eid(record), template, record.offset())


def extract_chunk(buf, offset, templates):
    """
    Parse an EVTX chunk into the XML entries
      and extract the templates into a TemplateDatabase

    Modifies parameter `templates`.

    @type buf: bytestring
    @type offset: int
    @rtype: str
    """
    logger = logging.getLogger("extract_records")
    chunk = ChunkHeader(buf, offset)

    xml = []
    for record in chunk.records():
        try:
            template = get_template(record)
            templates.add_template(template)
            xml.append(record.root().xml([]).encode("utf-8"))
        except UnicodeEncodeError:
            logger.info("Unicode encoding issue processing record at %s" % \
                            hex(record.offset()))
            continue
        except UnicodeDecodeError:
            logger.info("Unicode decoding issue processing record at %s" % \
                            hex(record.offset()))
            continue
        except Exception as e:
            logger.info("Unknown exception processing record at %s: %s" % (hex(record.offset()), str(e)))
            continue
    return "\n".join(xml)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Find offsets of EVTX chunk records.")
    parser.add_argument("--records_outfile", type=str, default="records.xml",
                        help="The path to the output file for records")
    parser.add_argument("--templates_outfile", type=str, default="templates.txt",
                        help="The path to the output file for templates")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debugging output")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    parser.add_argument("chunk_hits_file", type=str,
                        help="Path to the file containing output of"
                        " find_evtx_chunks.py")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s %(levelname)s %(name)s %(message)s")

    logger = logging.getLogger("extract_records")

    with open(args.evtx, "rb") as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            xml = []
            templates = TemplateDatabase()
            with open(args.chunk_hits_file, "rb") as g:
                for line in g.read().split("\n"):
                    hit_type, _, offset = line.partition("\t")
                    logger.debug("Processing line: %s, %s", hit_type, offset)
                    if hit_type != "CHUNK_VALID":  # TODO(wb): I dont like string matching
                        logging.debug("Skipping, cause its not a valid chunk")
                        continue
                    offset = int(offset, 0x10)
                    xml.append(extract_chunk(buf, offset, templates))
    with open(args.records_outfile, "wb") as f:
        f.write("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>")
        f.write("<Events>")
        f.write("\n".join(xml))
        f.write("</Events>")
    with open(args.templates_outfile, "wb") as f:
        f.write(templates.serialize())


if __name__ == "__main__":
    main()
