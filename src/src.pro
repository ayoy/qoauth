TARGET = qoauth
DESTDIR = ../lib
win32:DLLDESTDIR = $${DESTDIR}

VERSION = 1.0.0

TEMPLATE = lib
QT += network
QT -= gui
CONFIG += \
    build_all \
    crypto \
    create_prl

#!macx: CONFIG += static_and_shared

OBJECTS_DIR = tmp
MOC_DIR = tmp
INC_DIR = ../include

INCLUDEPATH += $${INC_DIR}

PUBLIC_HEADERS += \
    $${INC_DIR}/qoauth_global.h \
    $${INC_DIR}/qoauth_namespace.h \
    $${INC_DIR}/qoauth.h
PRIVATE_HEADERS += \
    $${INC_DIR}/qoauth_p.h

HEADERS = \
    $$PUBLIC_HEADERS \
    $$PRIVATE_HEADERS
SOURCES += qoauth.cpp

DEFINES += QOAUTH

headers.files = \
    $${PUBLIC_HEADERS} \
    $${INC_DIR}/QtOAuth
features.path = $$[QMAKE_MKSPECS]/features
features.files = ../oauth.prf
docs.files = ../doc/html

macx {
    CONFIG += lib_bundle
    QMAKE_FRAMEWORK_BUNDLE_NAME = $$TARGET
    CONFIG(debug, debug|release): CONFIG += build_all
    FRAMEWORK_HEADERS.version = Versions
    FRAMEWORK_HEADERS.files = $$headers.files
    FRAMEWORK_HEADERS.path = Headers
    QMAKE_BUNDLE_DATA += FRAMEWORK_HEADERS
    target.path = $$[QT_INSTALL_LIBS]
    INSTALLS += \
        target \
        features
}
else:unix {
    isEmpty( PREFIX ):INSTALL_PREFIX = /usr
    else:INSTALL_PREFIX = $${PREFIX}

    # this creates a pkgconfig file
    system( ./pcfile.sh $${INSTALL_PREFIX} $${VERSION} )
    pkgconfig.files = qoauth.pc

    target.path = $${INSTALL_PREFIX}/lib
    headers.path = $${INSTALL_PREFIX}/include/QtOAuth
    docs.path = $${INSTALL_PREFIX}/share/doc/$${TARGET}-$${VERSION}
    pkgconfig.path = $${target.path}/pkgconfig
    INSTALLS += \
        target \
        headers \
        docs \
        pkgconfig \
        features
}

build_pass:CONFIG(debug, debug|release) {
    unix: TARGET = $$join(TARGET,,,_debug)
    else: TARGET = $$join(TARGET,,,d)
}
