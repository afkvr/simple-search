#-------------------------------------------------
#
# Project created by QtCreator 2018-03-26T10:46:57
#
#-------------------------------------------------

QT       += core gui
QT       += sql
greaterThan(QT_MAJOR_VERSION, 4): QT += quick

TARGET = enterprise
TEMPLATE = app
CONFIG+=c++11
CONFIG+=no_keywords

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        mainwindow.cpp \
        keymanager.cpp \
    ../../message/message.cpp \
    ../../database/db_interface.cpp \
    ../../vendors/cpp-elasticsearch/src/elasticsearch/elasticsearch.cpp \
    ../../vendors/cpp-elasticsearch/src/http/http.cpp \
    ../../vendors/cpp-elasticsearch/src/json/json.cpp \
    zmq_manager.cpp \
    ../../utils/utils.cpp \
    ../../blockchain/blockchain_interface.cpp \
    internaldb.cpp \
    dealmanager.cpp \
    accountmanager.cpp \
    blockchainWorkerThread.cpp \
    config.cpp


HEADERS += \
        mainwindow.h \
        keymanager.h \
        ../../vendors/nlohmann_json/nlohmann/json.hpp \
    ../../message/message.h \
    ../../database/db_interface.h \
    ../../vendors/cpp-elasticsearch/src/elasticsearch/elasticsearch.h \
    ../../vendors/cpp-elasticsearch/src/http/http.h \
    ../../vendors/cpp-elasticsearch/src/json/json.h \
    zmq_manager.h \
    ../../utils/utils.h \
    ../../blockchain/blockchain_interface.h \
    internaldb.h \
    dealmanager.h \
    accountmanager.h \
    blockchainWorkerThread.h \
    config.h


RESOURCES += \
    qml.qrc

INCLUDEPATH += ../../vendors/nlohmann_json/ ../../ ../../vendors/cpp-elasticsearch/src/

unix|win32: LIBS += -lzmq
unix|win32: LIBS += -lsodium

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../../vendors/curlcpp/release/ -lcurlcpp
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../vendors/curlcpp/debug/ -lcurlcpp
else:unix: LIBS += -L$$PWD/../../vendors/curlcpp/ -lcurlcpp

INCLUDEPATH += $$PWD/../../vendors/curlcpp/include/
DEPENDPATH += $$PWD/../../vendors/curlcpp

win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/curlcpp/release/libcurlcpp.a
else:win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/curlcpp/debug/libcurlcpp.a
else:win32:!win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/curlcpp/release/curlcpp.lib
else:win32:!win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/curlcpp/debug/curlcpp.lib
else:unix: PRE_TARGETDEPS += $$PWD/../../vendors/curlcpp/libcurlcpp.a

unix:!macx: PRE_TARGETDEPS += $$PWD/../../vendors/socket.io/lib/libsioclient_tls.a

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../../vendors/curl-7.59.0/lib/release/ -lcurl
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../vendors/curl-7.59.0/lib/debug/ -lcurl
else:unix: LIBS += -L$$PWD/../../vendors/curl-7.59.0/lib/ -lcurl

INCLUDEPATH += $$PWD/../../vendors/curl-7.59.0/include
DEPENDPATH += $$PWD/../../vendors/curl-7.59.0/include

CONFIG(release, debug|release): LIBS += -L$$PWD/../../../build/lib/Release/ -lboost_random
else:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../../build/lib/Debug/ -lboost_random

CONFIG(release, debug|release): LIBS += -L$$PWD/../../../build/lib/Release/ -lboost_system
else:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../../build/lib/Debug/ -lboost_system

CONFIG(release, debug|release): LIBS += -L$$PWD/../../../build/lib/Release/ -lboost_date_time
else:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../../build/lib/Debug/ -lboost_date_time




DISTFILES +=

unix|win32: LIBS += -lboost_filesystem

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../../vendors/cryptopp700/release/ -lcryptopp
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../vendors/cryptopp700/debug/ -lcryptopp
else:unix: LIBS += -L$$PWD/../../vendors/cryptopp700/ -lcryptopp

INCLUDEPATH += $$PWD/../../vendors/cryptopp700/include
DEPENDPATH += $$PWD/../../vendors/cryptopp700/include

win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/cryptopp700/release/libcryptopp.a
else:win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/cryptopp700/debug/libcryptopp.a
else:win32:!win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/cryptopp700/release/cryptopp.lib
else:win32:!win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/cryptopp700/debug/cryptopp.lib
else:unix: PRE_TARGETDEPS += $$PWD/../../vendors/cryptopp700/libcryptopp.a


unix:!macx: LIBS += -L$$PWD/../../vendors/socket.io/lib/ -lsioclient_tls

INCLUDEPATH += $$PWD/../../vendors/socket.io/include
DEPENDPATH += $$PWD/../../vendors/socket.io/include

unix:!macx: PRE_TARGETDEPS += $$PWD/../../vendors/socket.io/lib/libsioclient_tls.a

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../../vendors/openssl_1.0.2n/lib/release/ -lssl
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../vendors/openssl_1.0.2n/lib/debug/ -lssl
else:unix: LIBS += -L$$PWD/../../vendors/openssl_1.0.2n/lib/ -lssl

INCLUDEPATH += $$PWD/../../vendors/openssl_1.0.2n/include
DEPENDPATH += $$PWD/../../vendors/openssl_1.0.2n/include

win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/openssl_1.0.2n/lib/release/libssl.a
else:win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/openssl_1.0.2n/lib/debug/libssl.a
else:win32:!win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/openssl_1.0.2n/lib/release/ssl.lib
else:win32:!win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/openssl_1.0.2n/lib/debug/ssl.lib
else:unix: PRE_TARGETDEPS += $$PWD/../../vendors/openssl_1.0.2n/lib/libssl.a



win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../../vendors/openssl_1.0.2n/lib/release/ -lcrypto
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../vendors/openssl_1.0.2n/lib/debug/ -lcrypto
else:unix: LIBS += -L$$PWD/../../vendors/openssl_1.0.2n/lib/ -lcrypto

INCLUDEPATH += $$PWD/../../vendors/openssl_1.0.2n/include
DEPENDPATH += $$PWD/../../vendors/openssl_1.0.2n/include

win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/openssl_1.0.2n/lib/release/libcrypto.a
else:win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/openssl_1.0.2n/lib/debug/libcrypto.a
else:win32:!win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/openssl_1.0.2n/lib/release/crypto.lib
else:win32:!win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../vendors/openssl_1.0.2n/lib/debug/crypto.lib
else:unix: PRE_TARGETDEPS += $$PWD/../../vendors/openssl_1.0.2n/lib/libcrypto.a

unix:!macx: LIBS += -ldl
