#!/bin/bash

EVTX="$1";

rm -rf chunk_list.txt record_list.txt recovered_records.txt;

python ../find_evtx_chunks.py "$EVTX" > chunk_list.txt;
python ../extract_valid_evtx_records_and_templates.py "$EVTX" chunk_list.txt;
python ../find_evtx_records.py "$EVTX" chunk_list.txt > record_list.txt;
python ../extract_lost_evtx_records.py "$EVTX" record_list.txt > recovered_records.txt;
