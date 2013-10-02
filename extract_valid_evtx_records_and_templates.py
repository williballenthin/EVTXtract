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
from Evtx.BinaryParser import hex_dump

from Evtx.Evtx import ChunkHeader
from Evtx.Nodes import BXmlTypeNode, EndOfStreamNode, OpenStartElementNode, AttributeNode, CloseStartElementNode, CloseEmptyElementNode, CloseElementNode, ValueNode, CDataSectionNode, EntityReferenceNode, ProcessingInstructionTargetNode, ProcessingInstructionDataNode, TemplateInstanceNode, NormalSubstitutionNode, ConditionalSubstitutionNode, StreamStartNode, TemplateNode
from Evtx.Evtx import InvalidRecordException
from Evtx.Views import evtx_record_xml_view, UnexpectedElementException
from Progress import NullProgress
from State import State
from TemplateDatabase import TemplateDatabase
from TemplateDatabase import Template

from recovery_utils import get_eid, Mmap, do_common_argparse_config

logger = logging.getLogger("extract_records")

_replacement_patterns = {i: re.compile("\[(Normal|Conditional) Substitution\(index=%d, type=\d+\)\]" % i) for i in
                         xrange(35)}
def _make_replacement(template, index, substitution):
    """
    Makes a substitution given a template as a string.

    Implementation is a huge hack that depends on the
    brittle template_format() output.

    @type template: str
    @type index: int
    @type substitution: str
    @rtype: str
    """
    if index not in _replacement_patterns:
        from_pattern = re.compile("\[(Normal|Conditional) Substitution\(index=%d, type=\d+\)\]" % index)
        _replacement_patterns[index] = from_pattern
    return _replacement_patterns[index].sub(substitution, template)


def evtx_template_readable_view(root_node, cache=0):
    def rec(node, acc):
        if isinstance(node, EndOfStreamNode):
            pass  # intended
        elif isinstance(node, OpenStartElementNode):
            acc.append("<")
            acc.append(node.tag_name())
            for child in node.children():
                if isinstance(child, AttributeNode):
                    acc.append(" ")
                    acc.append(child.attribute_name().string())
                    acc.append("=\"")
                    rec(child.attribute_value(), acc)
                    acc.append("\"")
            acc.append(">")
            for child in node.children():
                rec(child, acc)
            acc.append("</")
            acc.append(node.tag_name())
            acc.append(">\n")
        elif isinstance(node, CloseStartElementNode):
            pass  # intended
        elif isinstance(node, CloseEmptyElementNode):
            pass  # intended
        elif isinstance(node, CloseElementNode):
            pass  # intended
        elif isinstance(node, ValueNode):
            acc.append(node.children()[0].string())
        elif isinstance(node, AttributeNode):
            pass  # intended
        elif isinstance(node, CDataSectionNode):
            acc.append("<![CDATA[")
            acc.append(node.cdata())
            acc.append("]]>")
        elif isinstance(node, EntityReferenceNode):
            acc.append(node.entity_reference())
        elif isinstance(node, ProcessingInstructionTargetNode):
            acc.append(node.processing_instruction_target())
        elif isinstance(node, ProcessingInstructionDataNode):
            acc.append(node.string())
        elif isinstance(node, TemplateInstanceNode):
            raise UnexpectedElementException("TemplateInstanceNode")
        elif isinstance(node, NormalSubstitutionNode):
            acc.append("[Normal Substitution(index=%d, type=%d)]" % \
                           (node.index(), node.type()))
        elif isinstance(node, ConditionalSubstitutionNode):
            acc.append("[Conditional Substitution(index=%d, type=%d)]" % \
                           (node.index(), node.type()))
        elif isinstance(node, StreamStartNode):
            pass  # intended

    # TODO(wb): reeval this
    acc = []
    template_instance = root_node.fast_template_instance()
    templ_off = template_instance.template_offset() + template_instance._chunk.offset()
    node = TemplateNode(template_instance._buf, templ_off, template_instance._chunk, template_instance)
    sub_acc = []
    for c in node.children():
        rec(c, sub_acc)
    sub_templ = "".join(sub_acc)
    acc.append(sub_templ)
    return "".join(acc)

def _get_complete_template(root, current_index=0):
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
    template = evtx_template_readable_view(root)  # TODO(wb): make sure this is working

    # walk through each substitution.
    # if its a normal node, continue
    # else its a subtemplate, and we count the number of substitutions _it_ has
    #   so that we can later fixup all the indices
    replacements = []
    for index, substitution in enumerate(root.substitutions()):
        # find all sub-templates
        if not isinstance(substitution, BXmlTypeNode):
            replacements.append(current_index + index)
            continue
        # TODO(wb): hack here accessing ._root
        subtemplate = _get_complete_template(substitution._root,
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
        if isinstance(replacement, basestring):
            # insert sub-template
            template = _make_replacement(template, index, replacement)
    return template


def get_template(record, record_xml):
    """
    Given a complete Record, parse out the nodes that make up the Template
      and return it as a Template.

    @type record: Record
    @type record_xml: str
    @rtype: Template
    """
    template = _get_complete_template(record.root())
    return Template(int(get_eid(record_xml)), template)


def extract_chunk(buf, offset, state, templates):
    """
    Parse an EVTX chunk
      updating the State with new valid records, and
      extracting the templates into a TemplateDatabase.

    @sideeffect: parameter `templates`
    @sideeffect: parameter `state`

    @type buf: bytestring
    @type offset: int
    @type state: State
    @type templates: TemplateDatabase
    """
    logger.debug("Considering chunk at offset %d", offset)

    chunk = ChunkHeader(buf, offset)

    xml = []
    cache = {}
    for record in chunk.records():
        try:
            offset = record.offset()
            logger.debug("Considering record at offset %d",  offset)
            record_xml = evtx_record_xml_view(record, cache=cache)
            eid = get_eid(record_xml)

            state.add_valid_record(offset, eid, record_xml)

            template = get_template(record, record_xml)
            templates.add_template(template)
        except UnicodeEncodeError:
            logger.info("Unicode encoding issue processing record at %s" % \
                        hex(record.offset()))
            continue
        except UnicodeDecodeError:
            logger.info("Unicode decoding issue processing record at %s" % \
                        hex(record.offset()))
            continue
        except InvalidRecordException:
            logger.info("EVTX parsing issue processing record at %s" % \
                        hex(record.offset()))
            continue
        except Exception as e:
            logger.info("Unknown exception processing record at %s: %s" % \
                        (hex(record.offset()), str(e)))
            raise e
            continue


def extract_valid_evtx_records_and_templates(state, templates, buf, progress_class=NullProgress):
    progress = progress_class(len(state.get_valid_chunk_offsets()) - 1)
    for i, chunk_offset in enumerate(state.get_valid_chunk_offsets()):
        extract_chunk(buf, chunk_offset, state, templates)
        progress.set_current(i)
    progress.set_complete()


def main():
    args = do_common_argparse_config("Extract valid EVTX records and templates.")

    with State(args.project_json) as state:
        if len(state.get_valid_chunk_offsets()) == 0:
            logger.warn("No valid chunk offsets recorded. Perhaps you haven't yet run find_evtx_chunks?")
            return
        with TemplateDatabase(args.templates_json) as templates:
            with Mmap(args.image) as buf:
                extract_valid_evtx_records_and_templates(state, templates, buf, progress_class=args.progress_class)


if __name__ == "__main__":
    main()
