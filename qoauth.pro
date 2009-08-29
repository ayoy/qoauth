TEMPLATE = subdirs

SUBDIRS += src tests

CONFIG += ordered

check.target = check
check.commands = ( cd tests/ut_interface && ./ut_interface ) && ( cd tests/ft_interface && ./ft_interface )
check.depends = sub-tests
QMAKE_EXTRA_TARGETS += check
