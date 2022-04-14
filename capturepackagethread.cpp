#include "capturepackagethread.h"

capturePackageThread::capturePackageThread()
{
    // 初始化过滤器
    this->filter="ip and udp";
    // 初始化包数量
    this->packetNumber=0;
    this->init_deviceInfo();
    // 初始化线程是否开启的标志
    this->flag=false;
    // 创建数据对象
    this->table_data=new TableData();
    // 创建计时器
    this->fTimeCounter=new QTime();
    // 初始化定时器
    //this->fTimer=new QTimer();
    // 停止定时器
    //this->fTimer->stop();
    // 设置定时器的间隔
    //this->fTimer->setInterval(1);
    // 绑定信号与槽
    this->connect(this,&capturePackageThread::exit_run,this,&capturePackageThread::close_pcap);
}

capturePackageThread::~capturePackageThread()
{
    // 请求终止
    requestInterruption();
    // 关闭线程
    quit();
    // 等待回收
    wait();
}

void capturePackageThread::init_deviceInfo()
{
    // 定义变量遍历数据
    pcap_if_t * d;
    // 定义变量进行验证
    int i=0;
    // 定义数组存储错误信息
    char errbuf[PCAP_ERRBUF_SIZE];
    // 获取本机设备列表
    if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&this->alldevs,errbuf)==-1){
        qDebug()<<"Error in pcap_findallevs:"<<errbuf<< endl;
        exit(0);
    }
    // 获取设备列表信息
    for(d=this->alldevs;d;d=d->next){
        // 计算设备列表的长度
        i++;
        // 将设备列表存储得到链表
        this->device_Name.append(d->name);
    }
    // 判断主机是否存在设备列表
    if(i==0){
        qDebug()<<"No interfaces found! Make sure WinPcap is installed."<< endl;
        return ;
    }
}

QList<QString> capturePackageThread::get_deviceName()
{
    return this->device_Name;
}

void capturePackageThread::set_deviceName(QList<QString> device_Name)
{
    // 清空
    this->device_Name.clear();
    // 遍历传入链表
    foreach (QString str, device_Name) {
        this->device_Name.append(str);
    }
}

int capturePackageThread::get_index()
{
    return this->index;
}

void capturePackageThread::set_index(int index)
{
    this->index=index;
}

QString capturePackageThread::get_filter()
{
    return this->filter;
}

void capturePackageThread::set_filter(QString filter)
{
    this->filter="ip and"+filter;
}

void capturePackageThread::add_filter(QString addFilter)
{
    this->filter+=addFilter;
}

bool capturePackageThread::get_Flag()
{
    return this->flag;
}

void capturePackageThread::set_Flag(bool f)
{
    this->flag=f;
}

void capturePackageThread::run()
{
    // 定义变量存储数据
    pcap_if_t *d;
    // 定义变量进行控制
    int i=0;
    // 定义数组存储错误信息
    char errbuf[PCAP_ERRBUF_SIZE];
    // 创建存储掩码的变量
    u_int netmask;
    // 创建设置过滤的对象
    struct bpf_program fcode;
    // 判断选择下标是否正确
    if(this->index<1 || this->index>this->device_Name.size()){
        qDebug()<<"Interface number out of range."<< endl;
        qDebug()<<"index:"<<this->index;
        qDebug()<<"size:"<<this->device_Name.size();
        // 释放设备列表
        pcap_freealldevs(this->alldevs);
        return ;
    }
    // 跳转到选中的适配器
    for(d=this->alldevs,i=0;i<this->index;d=d->next,i++);
    // 打开设备
    if((this->adhandle=pcap_open(d->name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errbuf))==NULL){
        qDebug()<<"Unable to open the adapter. "<<d->name<<" is not supported by WinPcap."<< endl;
        // 释放设备列表
        pcap_freealldevs(this->alldevs);
        return ;
    }
    // 检查数据链路层，为了简单，只考虑以太网
    if(pcap_datalink(this->adhandle)!=DLT_EN10MB){
        qDebug()<<"This program vorks only on Ethernet networks."<< endl;
        // 释放设备列表
        pcap_freealldevs(this->alldevs);
        return ;
    }
    // 获取掩码
    if(d->addresses!=NULL){
        // 获取接口第一个地址的掩码
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    }else{
        // 如果接口没有地址，那么我们假设一个C类的掩码
        netmask=0xffffff;
    }
    // 编译过滤器
    if(pcap_compile(this->adhandle,&fcode,this->filter.toStdString().c_str(),1,netmask)<0){
        qDebug()<<"Unable to compile the packet filter.Check the syntax."<< endl;
        // 释放设备列表
        pcap_freealldevs(this->alldevs);
        return ;
    }
    // 设置过滤器
    if(pcap_setfilter(this->adhandle,&fcode)<0){
        qDebug()<<"Error setting the filter."<< endl;
        // 释放设备列表
        pcap_freealldevs(this->alldevs);
        return ;
    }

    qDebug()<<"listening on "<<d->description<<"..."<<endl;
    // 释放设备列表
    pcap_freealldevs(this->alldevs);
    // 使用回调函数
    pcap_loop(this->adhandle,0,packet_handler,(u_char*)this);
    return ;
}

void capturePackageThread::close_pcap()
{
    // 关闭设备
    pcap_close(this->adhandle);
    // 停止计时器
    delete this->fTimeCounter;
    // 重新创建
    this->fTimeCounter=new QTime();
}

pcap_t *capturePackageThread::getAdhandle() const
{
    return adhandle;
}

void capturePackageThread::setAdhandle(pcap_t *value)
{
    adhandle = value;
}

TableData *capturePackageThread::getTable_data() const
{
    return table_data;
}

void capturePackageThread::setTable_data(TableData *value)
{
    table_data = value;
}

int capturePackageThread::getPacketNumber() const
{
    return packetNumber;
}

void capturePackageThread::setPacketNumber(int value)
{
    packetNumber = value;
}

void packet_handler(u_char *param, const pcap_pkthdr *header, const u_char *pkt_data)
{
    // 获取this指针
    capturePackageThread* capturePackageThread_this=(capturePackageThread*)param;
    // 包计数
    capturePackageThread_this->setPacketNumber(capturePackageThread_this->getPacketNumber()+1);
    // 获取包体计数
#define __DEBUG__
#ifdef __DEBUG__
    qDebug()<<capturePackageThread_this->getPacketNumber();
#endif
    capturePackageThread_this->getTable_data()->setPacket(QString("%1").arg(capturePackageThread_this->getPacketNumber()));
    // 时间结构体对象
    struct tm * ltime;
    // 字符串
    char timestr[16];
    // 便于后续转换
    time_t local_tv_sec;
    // 以太网报头
    PDIC_HEADER dic_header;
    // ip报头
    PIP_HEADER ip_header;
    // udp报头
    PUDP_HEADER udp_header;
    // 将时间戳转换成可识别的格式
    local_tv_sec=header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime(timestr,sizeof timestr,"%H:%M:%S",ltime);
    // 获取当前时间
    capturePackageThread_this->getTable_data()->setCurrentTime(QString("%1.%2").arg(timestr).arg(header->ts.tv_usec));
    // 获取当前日期
    capturePackageThread_this->getTable_data()->setCurrentDate(QString(QDate::currentDate().toString()));
    // 判断是否为抓取的第一个包
    if(capturePackageThread_this->getTable_data()->getPacket()=="1"){// 在时间戳更换前进行获取
        // 初始化包相对时间
        capturePackageThread_this->getTable_data()->setRelativeTime("00:00:00.000000");
        // 启动计时器
        capturePackageThread_this->fTimeCounter->start();
    }else{
        // 获取相对时间
        // 获取相差毫秒
        int tmMesc=capturePackageThread_this->fTimeCounter->elapsed();
        // 修改相对时间
        capturePackageThread_this->getTable_data()->setRelativeTime(capturePackageThread_this->getTable_data()->formatRelativeTime(tmMesc));
    }
    // 获取数据包的长度
    capturePackageThread_this->getTable_data()->setSize(QString("%1").arg(header->len+4));
    // 获取时间戳
    capturePackageThread_this->getTable_data()->setCurrent_sec(header->ts.tv_sec);
    capturePackageThread_this->getTable_data()->setCurrent_usec(header->ts.tv_usec);
    // 打印时间
#ifdef __DEBUG__
    qDebug()<<timestr<<","<<header->ts.tv_usec<<header->len<< endl;
#endif
    // 获取报头
    // 以太网报头
    dic_header=(PDIC_HEADER)(pkt_data);
    // ip报头
    ip_header=(PIP_HEADER)(pkt_data+14);
    // 计算ip报头的长度
    int ip_len=(ip_header->h_len_ver & 0xf)* 4;
    // udp报头
    udp_header=(PUDP_HEADER)((u_char*)ip_header+ip_len);
    // 数据解析
    // 解析IP包
#ifdef __DEBUG__
    qDebug()<<ip_header->sourceip[0]<<"."<<ip_header->sourceip[1]<<"."<<ip_header->sourceip[2]<<"."<<ip_header->sourceip[3]<<"->";
    qDebug()<<ip_header->destip[0]<<"."<<ip_header->destip[1]<<"."<<ip_header->destip[2]<<"."<<ip_header->destip[3];
    qDebug()<<"len :"<<ntohs(ip_header->total_len)+18;
#endif
    // 获取源IP
    capturePackageThread_this->getTable_data()->setSource(QString("%1.%2.%3.%4").arg(ip_header->sourceip[0]).arg(ip_header->sourceip[1]).arg(ip_header->sourceip[2]).arg(ip_header->sourceip[3]));
    // 获取目的IP
    capturePackageThread_this->getTable_data()->setDestination(QString("%1.%2.%3.%4").arg(ip_header->destip[0]).arg(ip_header->destip[1]).arg(ip_header->destip[2]).arg(ip_header->destip[3]));
    // 获取协议类型
    if(ip_header->proto==IPPROTO_UDP){
        capturePackageThread_this->getTable_data()->setProtocol("udp");
    }else if(ip_header->proto==IPPROTO_TCP){
        capturePackageThread_this->getTable_data()->setProtocol("tcp");
    }
#ifdef __DEBUG__
    qDebug()<<capturePackageThread_this->getTable_data()->getProtocol();
#endif
    // 获取摘要
#ifdef __DEBUG__
    qDebug()<<ntohs(udp_header->srcport)<<"->"<<ntohs(udp_header->dstport)<<" len:"<<ntohs(udp_header->total_len);
#endif
    // 获取报文本体
    u_char * data=((u_char*)udp_header+sizeof(udp_header));
    // 获取报文长度
    int data_len=ntohs(udp_header->total_len)-sizeof(udp_header);
#ifdef __DEBUG__
    qDebug()<<data_len;
#endif
    // 获取数据
    // 初始化字符串
    capturePackageThread_this->getTable_data()->setMessage("");
    // 获取此次的集合
    capturePackageThread_this->getTable_data()->setMessage(capturePackageThread_this->getTable_data()->etheraddr_string(data,data_len,capturePackageThread_this->getTable_data()->getMessage()));
#ifdef __DEBUG__
    qDebug()<<capturePackageThread_this->getTable_data()->getMessage();
#endif
    // 发送信号
    emit capturePackageThread_this->show_data(capturePackageThread_this->getPacketNumber());
#ifdef __DEBUG__
    qDebug()<<__TIME__;
#endif
    QThread::sleep(1);
    // 线程结束的函数-需要将数据插入再退出-否则数据会出现新插入的数据无法在文件中显示的情况
    if(!capturePackageThread_this->get_Flag()){
        // 使线程休眠-等待进程回收
        // 请求终止
        //capturePackageThread_this->requestInterruption();
        // 等待回收
        //capturePackageThread_this->wait();
        // 关闭线程
        //capturePackageThread_this->quit();
#ifdef __DEBUG__
    qDebug()<<"__exit__";
#endif
        emit capturePackageThread_this->exit_run();
        pcap_breakloop(capturePackageThread_this->getAdhandle());
        //return ;
    }
    // 数据存储
}
