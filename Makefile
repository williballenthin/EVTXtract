.PHONY: test
test:
	@$(MAKE) -C tests test

.PHONY: clean
clean: 
	find . -name "*~" -exec rm {} \;
	find . -name "*pyc" -exec rm {} \;
