FIND_EVTX = "../../find_evtx_chunks.py"
TESTFILE = "few_records.evtx"

test_find_chunks:
	@if [ $$(python $(FIND_EVTX) $(TESTFILE) | grep "CHUNK_VALID" | wc -l) -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi
	@if [ $$(python $(FIND_EVTX) $(TESTFILE) | grep "CHUNK_BAD_HEADER" | wc -l) -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi
	@if [ $$(python $(FIND_EVTX) $(TESTFILE) | grep "CHUNK_BAD_DATA" | wc -l) -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi
	@if [ $$(python $(FIND_EVTX) $(TESTFILE) | grep "CHUNK_BAD_SIZE" | wc -l) -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi

test: test_find_chunks



