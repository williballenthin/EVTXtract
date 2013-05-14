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

# TODO(wb): fallback to standard xml parser
from lxml import etree


def to_lxml(record):
    """
    @type record: Record
    """
    return etree.fromstring(
        "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>%s" %
        (record.root().xml([]).encode("utf-8")))


def get_child(node, tag,
              ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    """
    @type node: Element
    @type tag: str
    @type ns: str
    """
    return node.find("%s%s" % (ns, tag))


def get_eid(record):
    return get_child(get_child(to_lxml(record), "System"), "EventID").text


class Template(object):
    substitition_re = re.compile("\[(Conditional|Normal) Substitution\(index=(\d+), type=(\d+)\)\]")

    def __init__(self, eid, xml, offset):
        self._eid = eid
        self._xml = xml
        self._offset = offset

        self._cached_placeholders = None
        self._cached_id = None

    def get_xml(self):
        return self._xml

    def get_eid(self):
        return self._eid

    def get_id(self):
        if self._cached_id is not None:
            return self._cached_id
        ret = ["%s" % self._eid]
        for index, type_, mode in self._get_placeholders():
            if mode:
                mode_str = "c"
            else:
                mode_str = "n"
            ret.append("[%s|%s|%s]" % (index, type_, mode_str))
        self._cached_id = "-".join(ret)
        return self._cached_id

    def get_offset(self):
        return self._offset

    def _get_placeholders(self):
        """
        Get descriptors for each of the substitutions required by this
          template.

        Tuple schema: (index, type, is_conditional)

        @rtype: list of (int, int, boolean)
        """
        if self._cached_placeholders is not None:
            return self._cached_placeholders
        ret = []
        for mode, index, type_ in Template.substitition_re.findall(self._xml):
            ret.append((int(index), int(type_), mode == "Conditional"))
        self._cached_placeholders = sorted(ret, key=lambda p: p[0])
        return self._cached_placeholders

    def match_substitutions(self, substitutions):
        """
        Checks to see if the provided set of substitutions match the
          placeholder values required by this template.

        Note, this is only a best guess.  The number of substitutions
          *may* be greater than the number of available slots. So we
          must only check the slot and substitution types.

        Tuple schema: (index, type, value)

        @type substitutions: list of (int, int, str)
        @rtype: boolean
        """
        logger = logging.getLogger("match_substitutions")
        placeholders = self._get_placeholders()
        if len(placeholders) > len(substitutions):
            logger.debug("Failing on lens: %d vs %d",
                         len(placeholders), len(substitutions))
            return False
        if max(placeholders, key=lambda k: k[0])[0] > max(substitutions, key=lambda k: k[0])[0]:
            logger.debug("Failing on max index: %d vs %d",
                         max(placeholders, key=lambda k: k[0])[0],
                         max(substitutions, key=lambda k: k[0])[0])
            return False
        for index, type_, mode in placeholders:
            sub = substitutions[index]
            # substitutions should be sorted and index-able,
            #  but if not, fallback
            if sub[0] != index:
                for s in substitutions:
                    if s[0] == index:
                        sub = s
                        break
            if mode and sub[1] == 0:
                continue
            if sub[1] != type_:
                logger.debug("Failing on type comparison: %d vs %d (mode: %s)",
                             sub[1], type_, mode)
                return False
        return True

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

    def serialize(self):
        ret = []
        ret.append("TEMPLATE")
        ret.append("ID: %s" % self.get_id())
        ret.append("EID: %s" % self.get_eid())
        ret.append("OFFSET: %s" % self.get_offset())
        ret.append("%s" % self.get_xml())
        return "\n".join(ret)

    @classmethod
    def deserialize(cls, text):
        for requirement in ["TEMPLATE", "EID: ", "ID: ", "<Event "]:
            if requirement not in text:
                return None
        template_lines = text.split("\n")
        #template_line = template_lines[0]
        id_line = template_lines[1]
        eid_line = template_lines[2]
        offset_line = template_lines[3]
        xml = "\n".join(template_lines[4:])
        _, __, id_ = id_line.partition(": ")
        _, __, eid = eid_line.partition(": ")
        _, __, offset = offset_line.partition(": ")
        eid = int(eid)
        offset = int(offset, 0x10)
        return cls(eid, xml, offset)


class TemplateEIDConflictError(Exception):
    def __init__(self, value):
        super(TemplateEIDConflictError, self).__init__(value)


class TemplateNotFoundError(Exception):
    def __init__(self, value):
        super(TemplateNotFoundError, self).__init__(value)


class TemplateDatabase(object):
    def __init__(self):
        # @type self._templates: {str: [Template]}
        # ID --> list matching Templates with the ID
        self._templates = {}
        # @type self._eid_map: {int: [str]}
        # EID --> list of ID
        self._eid_map = {}

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
            if template.get_eid() in self._eid_map:
                self._eid_map[template.get_eid()].append(id_)
            else:
                self._eid_map[template.get_eid()] = [id_]

    def extend(self, other):
        """
        Merge another TemplateDatabase into this one.

        @type other: TemplateDatabase
        @rtype: None
        """
        for template_list in other._templates.values():
            for template in template_list:
                self.add_template(template)

    def get_template(self, eid, substitutions, exact_match=True):
        """
        Given an ID, attempt to pick the appropriate template.

        `exact_match` should only be unset during testing.
          Not for forensics.

        @type eid: int
        @type substitutions: list of (int, str)
        @rtype: Template
        @raises TemplateEIDConflictError
        @raises TemplateNotFoundError
        """
        if eid not in self._eid_map:
            raise TemplateNotFoundError(
                "No loaded templates with EID: %s" % eid)

        potential_templates = []
        for id_ in self._eid_map[eid]:
            potential_templates.extend(self._templates[id_])

        matching_templates = []
        for template in potential_templates:
            if template.match_substitutions(substitutions):
                matching_templates.append(template)

        if exact_match and len(matching_templates) > 1:
            raise TemplateEIDConflictError("%d templates matched query for "
                                           "EID %d and substitutions" % eid)
        if len(matching_templates) == 0:
            sig = str(eid) + "-" + "-".join(["[%d|%d| ]" % (i, j) for i, j in \
                                                 enumerate(map(lambda p: p[0], substitutions))])
            raise TemplateNotFoundError(
                "No loaded templates with given substitution signature: %s" % sig)

        return matching_templates[0]

    def serialize(self):
        ret = []
        for id_ in sorted(self._templates.keys()):
            for template in self._templates[id_]:
                ret.append(template.serialize())
                ret.append("\n\n")
        return "\n".join(ret)

    def deserialize(self, txt, warn_on_conflict=True):
        """
        Load a serialized TemplateDatabase into this one.

        Merges with whatever is currently in this database.

        @type txt: str
        @rtype: None
        @raises: TemplateEIDConflictError
        """
        self._templates = {}
        for template_txt in txt.split("TEMPLATE\n"):
            template = Template.deserialize("TEMPLATE\n" + template_txt.rstrip("\n"))
            if template is None:
                continue
            if template.get_id() in self._templates and warn_on_conflict:
                raise TemplateEIDConflictError("More than one template with ID %s" % template.get_id())
            elif template.get_id() in self._templates and not warn_on_conflict:
                self._templates[template.get_id()].append(template)
            else:
                self._templates[template.get_id()] = [template]
                if template.get_eid() in self._eid_map:
                    self._eid_map[template.get_eid()].append(template.get_id())
                else:
                    self._eid_map[template.get_eid()] = [template.get_id()]
