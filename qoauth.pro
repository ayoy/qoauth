TARGET = qoauth

include(qoauth.pri)
TEMPLATE = lib
QT += network
QT -= gui
CONFIG += dll \
    crypto \
    create_prl \
    link_prl

DEFINES += QOAUTH

headers.files = include/QOAuth include/qoauth.h include/qoauth_global.h
features.path = $$[QMAKE_MKSPECS]/features
features.files = oauth.prf

macx {
    CONFIG += lib_bundle
    FRAMEWORK_HEADERS.version = Versions
    FRAMEWORK_HEADERS.files = include/QOAuth include/qoauth.h include/qoauth_global.h
    FRAMEWORK_HEADERS.path = Headers
    QMAKE_BUNDLE_DATA += FRAMEWORK_HEADERS
    target.path = $$[QT_INSTALL_LIBS]
    INSTALLS += target \
        features
}
else:unix { 
    DESTDIR = lib
    isEmpty( PREFIX ):INSTALL_PREFIX = /usr
    else:INSTALL_PREFIX = $${PREFIX}
    target.path = $${INSTALL_PREFIX}/lib
    headers.path = $${INSTALL_PREFIX}/include/QOAuth
    INSTALLS += target \
        lib_headers \
        features
}
else:win32 { 
    DESTDIR = lib
    DLLDESTDIR = $${DESTDIR}
}

OBJECTS_DIR = tmp
MOC_DIR = tmp

SOURCES += qoauth.cpp
HEADERS += include/qoauth_global.h \
    include/qoauth.h \
    include/qoauth_p.h
INCLUDEPATH += include tmp
