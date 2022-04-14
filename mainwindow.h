#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>// 主界面
#include <pcap.h>// winpcap开发者包
#include <QTableWidgetItem>// 表格项
#include <QList>// 使用链表进行存储设备名
#include "capturepackagethread.h"// 线程对象
#include <QAbstractItemView> // 抽象项视图
#include <QScreen>// 屏幕类
#include <math.h>// 数学
#include <QFile>// 文件
#include <QDataStream>// 二进制
#include <QTextStream>// 文本
#include <QJsonArray>// json数组
#include <QJsonObject>// json对象
#include <QJsonDocument>// json解析
#include <QJsonValue>// json值

// 文件存储名
static QString fileName="datagramInfo.txt";

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    // 将列表信息存储到文件
    // 将数据以二进制存储到文件中的操作
    bool binaryStorage(QString fileName="takeNotes.txt");
    // 将数据以JSON格式存储到文件中
    bool jsonStorage(QString fileName="takeNotes.txt");

private slots:
    // 选择设备的槽函数
    void on_selectDevice_Box_activated(int index);
    // 选择协议的槽函数
    void on_selectProtocol_Box_activated(const QString &text);
    // 开始抓包的槽函数
    void on_capturePackage_clicked();
    // 开始存储数据的槽函数
    //void on_storedRecord_clicked();
    // 双击列表行的函数
    //void on_messageInfo_tabel_itemDoubleClicked(QTableWidgetItem *item);
    // 添加列表行的函数
    void add_tableLine(int index);

private:
    // ui指针
    Ui::MainWindow *ui;
    // 使用链表存储设备名
    QList<QString> device_Name;
    // 使用变量存储选择的下标
    int index;
    // 线程对象
    capturePackageThread* thread;
};

#endif // MAINWINDOW_H
