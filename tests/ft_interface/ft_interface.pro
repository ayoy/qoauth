TARGET = ft_interface
TEMPLATE = app

DEFINES += UNIT_TEST
include(../../oauth.prf)

QT += testlib network
QT -= gui
CONFIG += crypto

macx {
    CONFIG -= app_bundle
    QMAKE_POST_LINK += install_name_tool -change qoauth.framework/Versions/1/qoauth \
                       ../../lib/qoauth.framework/Versions/1/qoauth $${TARGET}
}
else:unix {
  # the second argument (after colon) is for
  # being able to run make check from the root source directory
  LIBS += -Wl,-rpath,../../lib:lib
}

INCLUDEPATH += . ../../src
HEADERS += ft_interface.h
SOURCES += ft_interface.cpp
