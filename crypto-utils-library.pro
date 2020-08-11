TEMPLATE = lib

QT -= core gui
CONFIG += staticlib

TARGET = crypto-utils

SOURCES += \
        source/crypto-utils.cxx

HEADERS += \
        source/crypto-utils.hxx

win32 {
    # OpenSSL Include directory.
    INCLUDEPATH += C:/OpenSSL-Win64/include/
    DEPENDPATH += C:/OpenSSL-Win64/include/

    # Separate Windows libraries that OpenSSL requires to link properly.
    LIBS += -lUser32 -lAdvapi32 -lCrypt32 -lWs2_32

    # OpenSSL Library directory.
    LIBS += -LC:/OpenSSL-Win64/lib/VC/static/

    # OpenSSL Static library linkage (debug/release).
    CONFIG(release, debug|release): LIBS += -llibcrypto64MD
    CONFIG(debug, debug|release): LIBS += -llibcrypto64MDd
}

unix {
    INCLUDEPATH += /usr/local/include/
    DEPENDPATH += /usr/local/include/
    LIBS += -L/usr/local/lib/

    # libcrypto.a Should be in /usr/local/lib
    LIBS += -lcrypto

    target.path = /usr/lib
    INSTALLS += target
}

macx {
    INCLUDEPATH += /usr/local/include/
    DEPENDPATH += /usr/local/include/
    LIBS += -L/usr/local/lib/

    # libcrypto.a Should be in /usr/local/lib
    LIBS += -lcrypto

    target.path = /usr/lib
    INSTALLS += target
}
