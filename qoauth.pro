TEMPLATE = subdirs

SUBDIRS += src tests

CONFIG += ordered

check.target = check
# Note that functional test requires active network connection
# and depends also on an external server. When using in an automatic
# build environment, it's recommended not to run the functional test.

isEmpty(FUNC_TEST): check.commands = cd tests/ut_interface && ./ut_interface
else: check.commands = ( cd tests/ut_interface && ./ut_interface ) && ( cd tests/ft_interface && ./ft_interface )
check.depends = sub-tests
QMAKE_EXTRA_TARGETS += check
