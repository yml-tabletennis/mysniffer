#ifndef TABLEDATA_H
#define TABLEDATA_H

#include <QString>// qt形式的字符串
#define HAVE_REMOTE
#include "pcap.h"// winpcap
#include "remote-ext.h"// winpcap支持包
#include <windows.h>// windows库
#include <QDebug>// 测试


// 报文信息
// 以太网头
typedef struct __DIC_HEADER{
    u_char dstmac[6];// 目的MAC地址
    u_char srcmac[6];// 源MAC地址
    u_short ethertype;// 帧类型
}DIC_HEADER,*PDIC_HEADER;
// IP头
typedef struct __IP_HEADER{
    u_char h_len_ver;// IP版本号(高4位)以及32比特为单位的IP包头部的长度(低4位)
    u_char tos;// 服务类型TOS
    u_short total_len;// IP包总长度
    u_short ident;// 标识
    u_short frag_and_flags;// 标志位
    u_char ttl;// 生存时间
    u_char proto;// 协议类型
    u_short checksum;// IP首部校验和
    u_char sourceip[4];// 源IP地址(32位)
    // 或者 u_int sourceip;
    u_char destip[4];// 目的IP地址(32位)
    // 或者 u_int destip;
}IP_HEADER,*PIP_HEADER;
// UDP头
typedef struct __UDP_HEADER{
    u_short srcport;// 源端口
    u_short dstport;// 目的端口
    u_short total_len;// 包括UDP的报头以及UDP数据的长度(单位：字节)
    u_short chksum;// 校验和
}UDP_HEADER,*PUDP_HEADER;
// UDP伪首部 仅用于计算效验和
typedef struct __TSD_HEADER{
    u_char sourceip[4];// 源地址
    u_char destip[4];// 目的地址
    u_char mbz;// 置空(0)
    u_char ptcl;// 协议类型(IPPROTO_UDP)
    u_short udpl;// UDP包总长度
}TSD_HEADER,PTSD_HEADER;

// TCP头
typedef struct __TCP_HEADER{
    u_short srcport;// 源端口
    u_short dstport;// 目的端口
    u_int seqnum;// 顺序号
    u_int acknum;// 期待获得对方的TCP包编号
    u_char h_len;// 以32比特为单位的TCP报头长度
    u_char flags;// 标志
    u_short indow;// 窗口大小
    u_short chksum;// 效验和
    u_short urgptr;// 紧急指针
}TCP_HEADER,*PTCP_HEADER;
// TCP伪首部 用于进行TCP效验和的计算，保证TCP效验的有效性
typedef struct __PSD_HEADER{
    u_long sourceip;// 源ip地址
    u_long destip;// 目的ip地址
    u_char mbz;// 置空(0)
    u_char ptcl;// 协议类型(IPPROTO_TCP)
    u_short tcpl;// TCP头的长度(单位:字节)
}PSD_HEADER,*PPSD_HEADER;

class TableData
{
public:
    TableData();
    TableData(const TableData& tableData);
    ~TableData();

    QString getSource() const;
    void setSource(const QString value);

    QString getDestination() const;
    void setDestination(const QString value);

    QString getProtocol() const;
    void setProtocol(const QString value);

    QString getCurrentTime() const;
    void setCurrentTime(const QString value);

    long getCurrent_sec() const;
    void setCurrent_sec(const long value);

    long getCurrent_usec() const;
    void setCurrent_usec(const long value);

    QString getCurrentDate() const;
    void setCurrentDate(const QString value);

    QString getRelativeTime() const;
    void setRelativeTime(const QString value);

    QString getPacket() const;
    void setPacket(const QString value);

    QString getSize() const;
    void setSize(const QString value);
    // 将毫秒转换为相对时间的形式
    QString formatRelativeTime(int ms);
    // 将u_char转换为QString类型数据
    QString etheraddr_string(const u_char* data,int data_len,QString buf);

    QString getMessage() const;
    void setMessage(const QString value);
private:
    // 包编号
    QString Packet;
    // 源地址
    QString Source;
    // 目标地址
    QString Destination;
    // 大小
    QString Size;
    // 包相对时间
    QString RelativeTime;
    // 协议类型
    QString Protocol;
    // 报文
    QString message;
    // 当前时间
    QString currentTime;
    // 时间戳
    long current_sec;// 当前秒数
    long current_usec;// 余下不足一秒的时间
    // 日期
    QString currentDate;
};

#endif // TABULATIONDATA_H
