FIND_EVTX = "../../../find_evtx_chunks.py"
EXTRACT_TEMPLATES = "../../../extract_valid_evtx_records_and_templates.py"
FIND_RECORDS = "../../../find_evtx_records.py"
EXTRACT_LOST_RECORDS = "../../../extract_lost_evtx_records.py"
RECONSTRUCT_RECORDS = "../../../reconstruct_lost_records.py"
TESTING_TEMPLATES = "./testing_templates.txt"
CHUNK_LIST = "./chunk_list.txt"
RECORDS_XML = "./records.xml"
TEMPLATES_TXT = "./templates.txt"
LOST_LIST = "./lost_list.txt"
RECOVERED_RECORDS = "./recovered_records.txt"
RECONSTRUCTED_RECORDS = "./reconstructed_records.xml"
UNRECONSTRUCTED_RECORDS = "./unreconstructed_records.txt"
TESTFILE = "FIXME.evtx"

.PHONY: test_find_chunks
test_find_chunks:
	@echo "-- Testing find_chunks --"
	@python $(FIND_EVTX) $(TESTFILE) > $(CHUNK_LIST)
	@echo "!! Test not implemented !!"

.PHONY: test_extract_templates
test_extract_templates: test_find_chunks
	@echo "-- Testing extract_valid_templates_and_records --"
	@python $(EXTRACT_TEMPLATES) $(TESTFILE) $(CHUNK_LIST) --records_outfile=$(RECORDS_XML) --templates_outfile=$(TEMPLATES_TXT)
	@echo "!! Test not implemented !!"

.PHONY: test_find_records
test_find_records: test_find_chunks
	@echo "-- Testing find_records --"
	@python $(FIND_RECORDS) $(TESTFILE) $(CHUNK_LIST) > $(LOST_LIST)
	@echo "!! Test not implemented !!"

.PHONY: test_extract_lost_records
test_extract_lost_records: test_find_records
	@echo "-- Testing extract_lost_records --"
	@python $(EXTRACT_LOST_RECORDS) $(TESTFILE) $(LOST_LIST) > $(RECOVERED_RECORDS)
	@echo "!! Test not implemented !!"

.PHONY: test_reconstruct_records
test_reconstruct_records: test_extract_lost_records
	@echo "-- Testing reconstruct_records --"
	@python $(RECONSTRUCT_RECORDS) $(TESTING_TEMPLATES) $(RECOVERED_RECORDS) $(RECONSTRUCTED_RECORDS) $(UNRECONSTRUCTED_RECORDS) > /dev/null
	@echo "!! Test not implemented !!"

.PHONY: clean_tests
clean_tests:
	@rm -rf $(CHUNK_LIST) $(RECORDS_XML) $(TEMPLATES_TXT) $(LOST_LIST) $(RECOVERED_RECORDS) $(RECONSTRUCTED_RECORDS) $(UNRECONSTRUCTED_RECORDS) *.pyc *~

.PHONY: test
test: test_find_chunks test_extract_templates test_find_records test_extract_lost_records test_reconstruct_records clean_tests




