SUBDIRS = shmqueue DynTrace IGC SASG

$(SUBDIRS):init
	for subdir in $(SUBDIRS);\
	do $(MAKE) -C $$subdir;\
	done

init:
	@echo begin compile $(PWD)

.PHONY : clean
clean:
	for subdir in $(SUBDIRS);\
	do $(MAKE) -C $$subdir clean;\
	done
	@rm -rf lib