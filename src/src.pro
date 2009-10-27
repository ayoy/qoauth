TARGET = qoauth
DESTDIR = ../lib
win32:DLLDESTDIR = $${DESTDIR}

VERSION = 1.0.1

TEMPLATE = lib
QT += network
QT -= gui
CONFIG += \
    crypto \
    create_prl

!macx: CONFIG += static_and_shared

OBJECTS_DIR = tmp
MOC_DIR = tmp
INC_DIR = ../include

INCLUDEPATH += .

PUBLIC_HEADERS += \
    qoauth_global.h \
    qoauth_namespace.h \
    interface.h
PRIVATE_HEADERS += \
    interface_p.h

HEADERS = \
    $$PUBLIC_HEADERS \
    $$PRIVATE_HEADERS
SOURCES += interface.cpp

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
    
    contains(QMAKE_HOST.arch, x86_64) {
      target.path = $${INSTALL_PREFIX}/lib64
    } else {
      target.path = $${INSTALL_PREFIX}/lib
    }

    headers.path = $${INSTALL_PREFIX}/include/QtOAuth
    docs.path = $${INSTALL_PREFIX}/share/doc/$${TARGET}-$${VERSION}/html
    pkgconfig.path = $${target.path}/pkgconfig
    INSTALLS += \
        target \
        headers \
        docs \
        pkgconfig \
        features
}

CONFIG(debug_and_release) {
    build_pass:CONFIG(debug, debug|release) {
        unix: TARGET = $$join(TARGET,,,_debug)
        else: TARGET = $$join(TARGET,,,d)
    }
}
