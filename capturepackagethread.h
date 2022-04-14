#ifndef CAPTUREPACKAGETHREAD_H
#define CAPTUREPACKAGETHREAD_H

#include <QObject>
#include <QThread>// 线程
#include <QTableWidget>// 表格
#include <QList>// 链表
#include <QDebug>// 测试
#include "tabledata.h"// 列表信息
#include <QDate>// 日期
#include <QTimer>// 定时器
#include <QTime>// 计时器

// 设置回调函数
void packet_handler(u_char* param,const struct pcap_pkthdr* header,const u_char* pkt_data);

// 存储已获取的数据包
//static QList<u_char*> data;

class capturePackageThread : public QThread
{
    Q_OBJECT
public:
    capturePackageThread();
    ~capturePackageThread();
    // 初始化设备
    void init_deviceInfo();
    // 提供设备列表的接口
    QList<QString> get_deviceName();
    void set_deviceName(QList<QString> device_Name);
    // 提供选择设备的接口
    int get_index();
    void set_index(int index);
    // 提供过滤器的接口
    QString get_filter();
    void set_filter(QString filter);
    void add_filter(QString addFilter);
    // 控制线程退出
    bool get_Flag();
    void set_Flag(bool f);
    // 存储数据包的获取
    //QList<u_char*> get_data();
    //void set_data(QList<u_char*> data_list);
    int getPacketNumber() const;
    void setPacketNumber(int value);
    // 列表信息指针的获取
    TableData *getTable_data() const;
    void setTable_data(TableData *value);
    pcap_t *getAdhandle() const;
    void setAdhandle(pcap_t *value);
    // 线程函数
    void run();
signals:
    void show_data(int index);
    void exit_run();
private slots:
    void close_pcap();
private:
    // 定义变量记录已使用包编号
    int id;
    // 设备列表
    QList<QString> device_Name;
    // 选择的设备对象
    pcap_if_t *alldevs;
    // 定义变量存储开启的设备
    pcap_t * adhandle;
    // 选择的设备编号
    int index;
    // 过滤器
    QString filter;
    // 线程是否执行
    bool flag;
    // 定义变量存储包的个数
    int packetNumber=0;
    // 存储列表信息的类型对象链表
    TableData* table_data;
    // 定义变量存储包的个数
    //int packetNumber;
public:
    // 计时器对象
    QTime* fTimeCounter;
};

#endif // CAPTUREPACKAGETHREAD_H
