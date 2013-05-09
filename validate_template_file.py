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
import sys

from reconstruct_lost_records import load_templates
from reconstruct_lost_records import TemplateEIDConflictError


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Verify a template file's syntax and contents.")
    parser.add_argument("templates", type=str,
                        help="Path to the file containing recovered templates")
    args = parser.parse_args()

    with open(args.templates, "rb") as f:
        templates_txt = f.read()
    try:
        load_templates(templates_txt)
    except TemplateEIDConflictError as e:
        print(str(e))
        sys.exit(-1)
    except Exception as e:
        print "Failed to parse templates file"
        raise e

    print("File verified")
    sys.exit(0)



if __name__ == "__main__":
    main()
