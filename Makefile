#
# Makefile for running unit tests
#
# List of subdirectories to build
TEST_FOLDER := ./test/
# List of unit test directories for libraries
UNITTESTS := $(sort $(dir $(wildcard $(TEST_FOLDER)*/unittest/*)))
TESTDIRS := $(UNITTESTS:%=build-%)
CLEANTESTDIRS := $(UNITTESTS:%=clean-%)
COVERAGEFILE := ./lcov/coverage.info

#
# Define compiler toolchain
#
include toolchain_rules.mk

$(eval $(call generate_rules,$(LIB),$(SRCS)))

# Extend default clean rule
clean: clean-extra

$(TESTDIRS):
	@yotta target x86-linux-native
	@yotta install mbed-client
	@make -C $(@:build-%=%)

$(CLEANDIRS):
	@make -C $(@:clean-%=%) clean

$(CLEANTESTDIRS):
	@make -C $(@:clean-%=%) clean

.PHONY: test
test: $(TESTDIRS)
	@rm -rf ./lcov
	@rm -rf ./coverage
	@mkdir -p lcov
	@mkdir -p lcov/results
	@mkdir coverage
	@find ./test -name '*.xml' | xargs cp -t ./lcov/results/
	@rm -f lcov/index.xml
	@./xsl_script.sh
	@cp junit_xsl.xslt lcov/.
	@xsltproc -o lcov/testresults.html lcov/junit_xsl.xslt lcov/index.xml
	@rm -f lcov/junit_xsl.xslt
	@rm -f lcov/index.xml
	@find ./ -name '*.gcno' | xargs cp --backup=numbered -t ./coverage/
	@find ./ -name '*.gcda' | xargs cp --backup=numbered -t ./coverage/
	gcovr --object-directory ./coverage --exclude '/usr' --exclude '${PWD}/test/mbed-client-linux/unittest/' --exclude '${PWD}/stub/' --exclude '/yotta_modules/' --exclude '${PWD}/common/' --exclude '${PWD}/coverage/' -x -o ./lcov/gcovr.xml
	@lcov -d test/. -c -o $(COVERAGEFILE)
	@lcov -q -r $(COVERAGEFILE) "/usr*" -o $(COVERAGEFILE)
	@lcov -q -r $(COVERAGEFILE) "/test*" -o $(COVERAGEFILE)
	@lcov -q -r $(COVERAGEFILE) "/mbed-client/*" -o $(COVERAGEFILE)
	@genhtml -q $(COVERAGEFILE) --show-details --output-directory lcov/html
	@yotta uninstall mbed-client
	@echo mbed-clientlinux module unit tests built

clean-extra: $(CLEANDIRS) \
	$(CLEANTESTDIRS)
