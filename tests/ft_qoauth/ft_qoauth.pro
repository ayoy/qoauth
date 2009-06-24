TARGET = ft_qoauth
TEMPLATE = app

DEFINES += UNIT_TEST
include(../../oauth.prf)

QT += testlib network
QT -= gui

macx {
    CONFIG -= app_bundle
    QMAKE_POST_LINK += install_name_tool -change qoauth.framework/Versions/0/qoauth \
                       ../../lib/qoauth.framework/Versions/0/qoauth $${TARGET}
}
else:unix {
  LIBS += -Wl,-rpath,../../lib
}

INCLUDEPATH += .
HEADERS += ft_qoauth.h
SOURCES += ft_qoauth.cpp
