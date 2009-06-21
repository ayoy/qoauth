win32: QOAUTH_LIB = -lqoauth$${VER_MAJ}
else:  QOAUTH_LIB = -lqoauth

INCLUDEPATH += $$PWD/include
DEPENDPATH  += $$PWD/include
