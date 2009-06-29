TEMPLATE = subdirs

SUBDIRS += src tests

CONFIG += ordered

check.target = check
# Note that functional test requires active network connection
# and depends also on the external server. When using in an automatic
# build environment, it's recommended not to run functional test.
isEmpty(FUNC_TEST): check.commands = tests/ut_qoauth/ut_qoauth
else: check.commands = tests/ut_qoauth/ut_qoauth && tests/ft_qoauth/ft_qoauth
check.depends = sub-tests
QMAKE_EXTRA_TARGETS += check
