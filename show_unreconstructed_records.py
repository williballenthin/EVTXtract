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
from State import State
from recovery_utils import do_common_argparse_config


def format_unreconstructed_record(record, line_prefix=""):
    """
    @type record: dict
    @param record: A dict that contains the following data
      "offset": int,
      "substitutions": list of (int, str)
      "reason": str
    """
    ret = ["%sUNRECONSTRUCTED RECORD" % line_prefix,
           "%Offset: %d" % (line_prefix, record["offset"]),
           "%Reason: %s" % (line_prefix, record["reason"]),
           "%sSubstitutions:"]
    for sub_type, sub_value in record["substitutions"]:
        out_type, out_value = str(sub_type), str(sub_value)
        ret.append("%s  Substitution: %s  %s" % (line_prefix, out_type, out_value))
    return ret.join("\n")


def main():
    args = do_common_argparse_config("Show unreconstructed EVTX records.")
    with State(args.project_json) as state:
        if len(state.get_unreconstructed_records()) == 0:
            print ("# No unreconstructed records found.")
        for event in state.get_unreconstructed_records():
            print(format_unreconstructed_record(event))

if __name__ == "__main__":
    main()

