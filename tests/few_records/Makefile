FIND_EVTX = "../../find_evtx_chunks.py"
FIND_RECORDS = "../../find_evtx_records.py"
CHUNK_LIST = "./chunk_list.txt"
TESTFILE = "few_records.evtx"

test_find_chunks:
	@echo "-- Testing find_chunks --"
	@if [ $$(python $(FIND_EVTX) $(TESTFILE) | grep "CHUNK_VALID" | wc -l) -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi
	@if [ $$(python $(FIND_EVTX) $(TESTFILE) | grep "CHUNK_BAD_HEADER" | wc -l) -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi
	@if [ $$(python $(FIND_EVTX) $(TESTFILE) | grep "CHUNK_BAD_DATA" | wc -l) -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi
	@if [ $$(python $(FIND_EVTX) $(TESTFILE) | grep "CHUNK_BAD_SIZE" | wc -l) -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi

test_find_records:
	@echo "-- Testing find_records --"
	@python $(FIND_EVTX) $(TESTFILE) > $(CHUNK_LIST)
	@if [ $$(python $(FIND_RECORDS) $(TESTFILE) $(CHUNK_LIST) | wc -l) -eq 3 ]; then echo "PASS"; else echo "FAIL"; fi

clean_tests:
	@rm -rf $(CHUNK_LIST) *.pyc *~

test: test_find_chunks test_find_records clean_tests



