TARGET = ut_interface
TEMPLATE = app

DEFINES += UNIT_TEST
include(../../oauth.prf)

QT += testlib network
QT -= gui
CONFIG += crypto

macx {
    CONFIG -= app_bundle
    # keep this in sync with oauth.prf
    LIBDIR = $$[QT_INSTALL_LIBS]
    LIBDIR ~= s!/qt4*!!
    QMAKE_POST_LINK += install_name_tool -change $$LIBDIR/qoauth.framework/Versions/1/qoauth \
                       ../../lib/qoauth.framework/Versions/1/qoauth $${TARGET}
}
else:unix {
  # the second argument (after colon) is for
  # being able to run make check from the root source directory
  LIBS += -Wl,-rpath,../../lib:lib
}

INCLUDEPATH += . ../../src
HEADERS += ut_interface.h
SOURCES += ut_interface.cpp
