#!/bin/sh
# This "script" creates a pkg-config file basing on values set
# in project file

echo "prefix=$1
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include/QtOAuth

Name: QOAuth
Description: Qt OAuth support library
Version: $2
Requires: QtCore QtNetwork qca2
Libs: -L\${libdir} -lqoauth
Cflags: -I\${includedir}" > qoauth.pc
