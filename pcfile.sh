#!/bin/sh
echo "prefix=$1
exec_prefix=\${prefix}
libdir=$1/lib
includedir=$1/include/QtOAuth

Name: QOAuth
Description: Qt OAuth support library
Version: $2
Requires: QtCore QtNetwork qca2
Libs: -L\${libdir} -lqoauth
Cflags: -I\${includedir}" > qoauth.pc
