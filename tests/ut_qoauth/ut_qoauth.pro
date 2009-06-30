TARGET = ut_qoauth
TEMPLATE = app

DEFINES += UNIT_TEST
include(../../oauth.prf)

QT += testlib
QT -= gui

macx {
    CONFIG -= app_bundle
    QMAKE_POST_LINK += install_name_tool -change qoauth.framework/Versions/0/qoauth \
                       ../../lib/qoauth.framework/Versions/0/qoauth $${TARGET}
}
else:unix {
  # the second argument (after colon) is for
  # being able to run make check from the root source directory
  LIBS += -Wl,-rpath,../../lib:lib
}

INCLUDEPATH += .
HEADERS += ut_qoauth.h
SOURCES += ut_qoauth.cpp
