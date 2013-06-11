SUBDIRS = chunk_fragment  complete_evtx  few_records  one_record  valid_chunk
.PHONY: $(SUBDIRS)

$(SUBDIRS):
	@$(MAKE) -C $@ test

.PHONY: subdirs
subdirs: $(SUBDIRS)

.PHONY: test
test: subdirs

