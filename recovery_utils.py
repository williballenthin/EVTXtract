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

# TODO(wb): fallback to standard xml parser
from lxml import etree


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

    def get_xml(self):
        return self._xml

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
            type_ = int(part.partition("type=")[2].partition(")")[0])
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


class TemplateEIDConflictError(Exception):
    def __init__(self, value):
        super(TemplateEIDConflictError, self).__init__(value)


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

    def deserialize(self, txt, warn_on_conflict=True):
        """
        Load a serialized TemplateDatabase into this one.

        Overwrites whats current in this database.

        @type txt: str
        @rtype: None
        @raises: TemplateEIDConflictError
        """
        self._templates = {}
        for template_txt in txt.split("TEMPLATE\n"):
            if template_txt == "":
                continue
            template_lines = template_txt.split("\n")
            id_line = template_lines[0]
            _, __, id_ = id_line.partition(": ")
            template = "\n".join(template_lines[4:])
            if id_ in self._templates and warn_on_conflict:
                raise TemplateEIDConflictError("More than one template with ID %d" % id_)
            # TODO(wb): parse out rest of template
            self._templates[id_] = template
