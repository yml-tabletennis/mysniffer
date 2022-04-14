#include "tabledata.h"

TableData::TableData()
{

}

TableData::TableData(const TableData &tableData)
{
    this->Packet=tableData.Packet;
    this->Source=tableData.Source;
    this->Destination=tableData.Destination;
    this->Size=tableData.Size;
    this->RelativeTime=tableData.RelativeTime;
    this->Protocol=tableData.Protocol;
}

TableData::~TableData()
{

}

QString TableData::getSource() const
{
    return Source;
}

void TableData::setSource(const QString value)
{
    Source = value;
}

QString TableData::getDestination() const
{
    return Destination;
}

void TableData::setDestination(const QString value)
{
    Destination = value;
}

QString TableData::getProtocol() const
{
    return Protocol;
}

void TableData::setProtocol(const QString value)
{
    Protocol = value;
}

QString TableData::getCurrentTime() const
{
    return currentTime;
}

void TableData::setCurrentTime(const QString value)
{
    currentTime = value;
}

long TableData::getCurrent_sec() const
{
    return current_sec;
}

void TableData::setCurrent_sec(const long value)
{
    current_sec = value;
}

long TableData::getCurrent_usec() const
{
    return current_usec;
}

void TableData::setCurrent_usec(const long value)
{
    current_usec = value;
}

QString TableData::getCurrentDate() const
{
    return currentDate;
}

void TableData::setCurrentDate(const QString value)
{
    currentDate = value;
}

QString TableData::getRelativeTime() const
{
    return RelativeTime;
}

void TableData::setRelativeTime(const QString value)
{
    RelativeTime = value;
}

QString TableData::getPacket() const
{
    return Packet;
}

void TableData::setPacket(const QString value)
{
    Packet = value;
}

QString TableData::getSize() const
{
    return Size;
}

void TableData::setSize(const QString value)
{
    Size = value;
}

QString TableData::formatRelativeTime(int ms)
{
    // 设置秒
    int ss=1000;
    // 设置分
    int mi=ss*60;
    // 设置时
    int hh=mi*60;
    // 设置天
    int dd=hh*24;
    // 获取天
    long day=ms/dd;
    // 获取时
    long hour=(ms-day*dd)/hh;
    // 获取分
    long minute=(ms-day*dd-hour*hh)/mi;
    // 获取秒
    long second=(ms-day*dd-hour*hh-minute*mi)/ss;
    // 获取毫秒
    long milliSecond=ms-day*dd-hour*hh-minute*mi-second*ss;
    // 获取字符串形式的时分秒以及毫秒
    QString hou=QString::number(hour,10);
    if(hou.size()==1){
        hou="0"+hou;
    }
    QString min=QString::number(minute,10);
    if(min.size()==1){
        min="0"+min;
    }
    QString sec=QString::number(second,10);
    if(sec.size()==1){
        sec="0"+sec;
    }
    QString msec=QString::number(milliSecond,10);// msec不可能大于4位-进位过
    while(msec.size()!=6){
        if(msec.size()<3){// 前补零
            msec="0"+msec;
        }else{// 后补零
            msec+="0";
        }
    }
    // 拼接返回
    return hou+":"+min+":"+sec+"."+msec;
}

QString TableData::etheraddr_string(const u_char *data, int data_len, QString buf)
{
    // 存储字符的数组
    char hex[16]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    // 定义变量控制移动以及赋值
    u_int j;
    // 做移动
    for(int i=0;i<data_len;i++){
        if((j=(*data>>4))!=0){// 转换前4位
            buf+=hex[j];
        }else{
            buf+='0';
        }
        // 转换后4位
#ifdef __DEBUG__
        qDebug()<<" "<<*data<<" "<<j<<" "<<(*data>>4)<<" "<<(*data & 0xf);
#endif
        buf+=hex[*data++ & 0xf];
        // 做分隔
        buf+=" ";
    }
    // 做结尾
    buf+='\0';
    // 做返回
    return buf;
}


QString TableData::getMessage() const
{
    return message;
}

void TableData::setMessage(const QString value)
{
    message = value;
}


