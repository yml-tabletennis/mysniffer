QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    capturepackagethread.cpp \
    main.cpp \
    mainwindow.cpp \
    tabledata.cpp

HEADERS += \
    capturepackagethread.h \
    mainwindow.h \
    tabledata.h

FORMS += \
    mainwindow.ui

# 导入头文件
INCLUDEPATH += G:/QtProject/WpdPack_4_1_2/WpdPack/Include
# 添加在内部配置的库 进行初始化

LIBS += G:/QtProject/WpdPack_4_1_2/WpdPack/Lib/x64/wpcap.lib G:/QtProject/WpdPack_4_1_2/WpdPack/Lib/x64/Packet.lib
LIBS += G:\QtProject\WpdPack_4_1_2\WpdPack\Lib\libwpcap.a G:\QtProject\WpdPack_4_1_2\WpdPack\Lib\libpacket.a
# windows库
LIBS += -lws2_32

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
