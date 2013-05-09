FIND_EVTX = "../../find_evtx_chunks.py"
FIND_RECORDS = "../../find_evtx_records.py"
EXTRACT_LOST_RECORDS = "../../extract_lost_evtx_records.py"
CHUNK_LIST = "./chunk_list.txt"
LOST_LIST = "./lost_list.txt"
TESTFILE = "one_record.evtx"

test_find_chunks:
	@echo "-- Testing find_chunks --"
	@if [ $$(python $(FIND_EVTX) $(TESTFILE) | grep "CHUNK_VALID" | wc -l) -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi
	@if [ $$(python $(FIND_EVTX) $(TESTFILE) | grep "CHUNK_BAD_HEADER" | wc -l) -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi
	@if [ $$(python $(FIND_EVTX) $(TESTFILE) | grep "CHUNK_BAD_DATA" | wc -l) -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi
	@if [ $$(python $(FIND_EVTX) $(TESTFILE) | grep "CHUNK_BAD_SIZE" | wc -l) -eq 0 ]; then echo "PASS"; else echo "FAIL"; fi

test_find_records:
	@echo "-- Testing find_records --"
	@python $(FIND_EVTX) $(TESTFILE) > $(CHUNK_LIST)
	@if [ $$(python $(FIND_RECORDS) $(TESTFILE) $(CHUNK_LIST) | wc -l) -eq 1 ]; then echo "PASS"; else echo "FAIL"; fi

test_extract_lost_records:
	@echo "-- Testing extract_lost_records --"
	@python $(FIND_EVTX) $(TESTFILE) > $(CHUNK_LIST)
	@python $(FIND_RECORDS) $(TESTFILE) $(CHUNK_LIST) > $(LOST_LIST)
	@if [ $$(python $(EXTRACT_LOST_RECORDS) $(TESTFILE) $(LOST_LIST) | grep "RECORD" | wc -l) -eq 1 ]; then echo "PASS"; else echo "FAIL"; fi

clean_tests:
	@rm -rf $(CHUNK_LIST) $(LOST_LIST) *.pyc *~

test: test_find_chunks test_find_records test_extract_lost_records clean_tests




