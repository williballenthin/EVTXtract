import re
import sys
import logging

import six
import Evtx.Evtx
import Evtx.Nodes
import Evtx.Views

import evtxtract.utils
import evtxtract.templates


logger = logging.getLogger(__name__)


class Template(object):
    substitition_re = re.compile("\[(Conditional|Normal) Substitution\(index=(\d+), type=(\d+)\)\]")

    def __init__(self, eid, xml):
        self.eid = eid
        self.xml = xml

        self._cached_placeholders = None
        self._cached_id = None

    def get_id(self):
        """
        @rtype: str
        @return: A string that can be parsed into constraints describing what
          types of subsitutions this template can accept.
          Short example: 1100-[0|4|c]-[1|4|c]-[2|6|c]-[3|6|c]
        """
        if self._cached_id is not None:
            return self._cached_id

        ret = [str(self.eid)]
        for index, type_, mode in self._get_placeholders():
            if mode:
                mode_str = "c"
            else:
                mode_str = "n"
            ret.append("[%s|%s|%s]" % (index, type_, mode_str))

        self._cached_id = "-".join(ret)
        return self._cached_id

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
        for mode, index, type_ in Template.substitition_re.findall(self.xml):
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

        @type substitutions: list of (int, str)
        @param substitutions: Tuple schema (type, value)
        @rtype: boolean
        """
        logger = logging.getLogger("match_substitutions")
        placeholders = self._get_placeholders()
        logger.debug("Substitutions: %s", str(substitutions))
        logger.debug("Constraints: %s", str(placeholders))
        if len(placeholders) > len(substitutions):
            logger.debug("Failing on lens: %d vs %d",
                         len(placeholders), len(substitutions))
            return False
        if max(placeholders, key=lambda k: k[0])[0] > len(substitutions):
            logger.debug("Failing on max index: %d vs %d",
                         max(placeholders, key=lambda k: k[0])[0],
                         len(substitutions))
            return False

        # it seems that some templates request different values than what are subsequently put in them
        #   specifically, a Hex64 might be put into a SizeType field (EID 4624)
        # this maps from the type described in a template, to possible additional types that a
        #   record can provide for a particular substitution
        overrides = {
            16: set([21])
        }

        for index, type_, is_conditional in placeholders:
            sub_type, sub_value = substitutions[index]
            if is_conditional and sub_type == 0:
                continue
            if sub_type != type_:
                if type_ not in overrides or sub_type not in overrides[type_]:
                    logger.debug("Failing on type comparison, index %d: %d vs %d (mode: %s)",
                                 index, sub_type, type_, is_conditional)
                    return False
                else:
                    logger.debug("Overriding template type %d with substitution type %d", type_, sub_type)
                    continue
        return True

    escape_re = re.compile(r"\\\\(\d)")

    @staticmethod
    def _escape(value):
        """
        Escape the static value to be used in a regular expression
          subsititution. This processes any backreferences and
          makes them plain, escaped sequences.

        @type value: str
        @rtype: str
        """
        return Template.escape_re.sub(r"\\\\\\\\\1", re.escape(value))

    def insert_substitutions(self, substitutions):
        """
        Return a copy of the template with the given substitutions inserted.

        @type substitutions: list of (int, str)
        @param substitutions: an ordered list of (type:int, value:str)
        @rtype: str
        """
        ret = self.xml
        for index, pair in enumerate(substitutions):
            type_, value = pair
            from_pattern = "\[(Normal|Conditional) Substitution\(index=%d, type=\d+\)\]" % index
            if isinstance(value, six.string_types):
                value = Template._escape(value)
            else:
                value = str(value)
            ret = re.sub(from_pattern, value, ret)
        return ret


REPLACEMENT_PATTERNS = {
    i: re.compile(
        "\[(Normal|Conditional) Substitution\(index=%d, type=\d+\)\]" % i)
    for i in range(35)}


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
    if index not in REPLACEMENT_PATTERNS:
        from_pattern = re.compile("\[(Normal|Conditional) Substitution\(index=%d, type=\d+\)\]" % index)
        REPLACEMENT_PATTERNS[index] = from_pattern
    return REPLACEMENT_PATTERNS[index].sub(substitution, template)


def get_complete_template(root, current_index=0):
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
    template = Evtx.Views.evtx_template_readable_view(root)  # TODO(wb): make sure this is working

    # walk through each substitution.
    # if its a normal node, continue
    # else its a subtemplate, and we count the number of substitutions _it_ has
    #   so that we can later fixup all the indices
    replacements = []
    for index, substitution in enumerate(root.substitutions()):
        # find all sub-templates
        if not isinstance(substitution, Evtx.Nodes.BXmlTypeNode):
            replacements.append(current_index + index)
            continue
        # TODO(wb): hack here accessing ._root
        subtemplate = get_complete_template(substitution._root,
                                             current_index=current_index + index)
        replacements.append(subtemplate)
        current_index += subtemplate.count("Substitution(index=")
    replacements.reverse()

    # now walk through all the indices and fix them up depth-first
    for i, replacement in enumerate(replacements):
        index = len(replacements) - i - 1
        if isinstance(replacement, int):
            # fixup index
            from_pattern = "index=%d," % index
            to_pattern = "index=%d," % replacement
            template = template.replace(from_pattern, to_pattern)
        if isinstance(replacement, six.string_types):
            # insert sub-template
            template = make_replacement(template, index, replacement)
    return template


def get_template(record):
    """
    Given a complete Record, parse out the nodes that make up the Template
      and return it as a Template.

    @type record: Record
    @rtype: Template
    """
    record_xml = Evtx.Views.evtx_record_xml_view(record)
    eid = evtxtract.utils.get_eid(record_xml)
    return Template(eid, get_complete_template(record.root()))
