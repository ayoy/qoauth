TARGET = qoauth
DESTDIR = ../lib
win32:DLLDESTDIR = $${DESTDIR}

equals(QT_MAJOR_VERSION, 5){
   VERSION = 2.0.0
}
equals(QT_MAJOR_VERSION, 4) {
   VERSION = 1.0.1
}

TEMPLATE = lib
QT += network
QT -= gui
CONFIG += \
    crypto \
    create_prl


INC_DIR = ../include

INCLUDEPATH += .
win32 {
	CONFIG(debug, debug|release) {
		BUILDDIR = build/debug
		windows: TARGET = $$join(TARGET,,,d)
        mac: TARGET = $$join(TARGET,,,_debug)
	} else {
		BUILDDIR = build/release
	}
}

INCLUDEPATH += ./$${BUILDDIR}
MOC_DIR += ./$${BUILDDIR}
OBJECTS_DIR += ./$${BUILDDIR}
UI_DIR += ./$${BUILDDIR}
RCC_DIR += ./$${BUILDDIR}


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
