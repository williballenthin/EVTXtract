SUBDIRS = 
.PHONY: $(SUBDIRS)

$(SUBDIRS):
	@$(MAKE) -C $@ test

.PHONY: subdirs
subdirs: $(SUBDIRS)

.PHONY: test
test: subdirs

