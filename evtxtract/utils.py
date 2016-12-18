import mmap
import logging
from lxml import etree


logger = logging.getLogger(__name__)


def to_lxml(record_xml):
    """
    Convert an XML string to an Etree element.

    @type record_xml: str
    @rtype: etree.Element
    """
    if "<?xml" not in record_xml:
        return etree.fromstring(
            "<?xml version=\"1.0\" standalone=\"yes\" ?>%s" % record_xml)
    else:
        return etree.fromstring(record_xml)


def get_child(node, tag,
              ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    """
    Given an Etree element, get the first child node with the given tag.

    @type node: etree.Element
    @type tag: str
    @type ns: str
    @rtype: etree.Element or None
    """
    return node.find("%s%s" % (ns, tag))


def get_eid(record_xml):
    """
    Given EVTX record XML, return the EID of the record.

    Args:
      record_xml (str)

    Returns:
      int: the event ID of the record
    """
    return int(
        get_child(
            get_child(to_lxml(record_xml),
                      "System"),
            "EventID").text)


class Mmap(object):
    """
    Convenience class for opening a read-only memory map for a file path.
    """

    def __init__(self, filename):
        super(Mmap, self).__init__()
        self._filename = filename
        self._f = None
        self._mmap = None

    def __enter__(self):
        self._f = open(self._filename, "rb")
        self._mmap = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        return self._mmap

    def __exit__(self, type, value, traceback):
        self._mmap.close()
        self._f.close()
