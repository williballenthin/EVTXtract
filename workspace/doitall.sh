#!/bin/bash

EVTX="$1";

rm -rf chunk_list.txt record_list.txt recovered_records.txt;

python ../find_evtx_chunks.py "$EVTX" > chunk_list.txt;
python ../extract_valid_evtx_records_and_templates.py "$EVTX" chunk_list.txt;
python ../find_evtx_records.py "$EVTX" chunk_list.txt > record_list.txt;
python ../extract_lost_evtx_records.py "$EVTX" record_list.txt > recovered_records.txt;
NOT_VALIDATED=0
while [[ $NOT_VALIDATED -ne 1 ]]; do
    python ../validate_template_file.py templates.txt;
    if [[ $? -eq 0 ]]; then 
        NOT_VALIDATED=1;
    else
        echo "Please update 'templates.txt'";
        read -p "Press enter when done>";
    fi
done
python ../reconstruct_lost_records.py templates.txt recovered_records.txt reconstructed_records.xml unreconstructed_records.txt;
