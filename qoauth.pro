TARGET = qoauth
DESTDIR = lib
win32:DLLDESTDIR = $${DESTDIR}

VERSION = 0.1.0

include(qoauth.pri)

TEMPLATE = lib
QT += network
QT -= gui
CONFIG += \
    crypto \
    create_prl

OBJECTS_DIR = tmp
MOC_DIR = tmp

SOURCES += qoauth.cpp

PUBLIC_HEADERS += \
    include/qoauth_global.h \
    include/qoauth.h
PRIVATE_HEADERS += \
    include/qoauth_p.h

HEADERS = \
    $$PUBLIC_HEADERS \
    $$PRIVATE_HEADERS

INCLUDEPATH += include


DEFINES += QOAUTH

headers.files = \
    include/QtOAuth \
    include/qoauth.h \
    include/qoauth_global.h
features.path = $$[QMAKE_MKSPECS]/features
features.files = oauth.prf
docs.files = doc/html

macx {
    CONFIG += lib_bundle
    QMAKE_FRAMEWORK_BUNDLE_NAME = $$TARGET
    CONFIG(debug, debug|release) {
      CONFIG += build_all
    }
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
