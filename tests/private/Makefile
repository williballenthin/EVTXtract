SUBDIRS = chunk_fragment  complete_evtx  few_records  one_record  valid_chunk  badfilesdir  win2008r2test  memoryevtx
.PHONY: $(SUBDIRS)

$(SUBDIRS):
	@$(MAKE) -C $@ test

.PHONY: subdirs
subdirs: $(SUBDIRS)

.PHONY: test
test: subdirs

