
#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    // 初始化界面
    ui->setupUi(this);
    // 创建链表
    //this->device_Name=new QList<QString>;
    // 创建线程对象
    this->thread=new capturePackageThread();
    // 绑定线程对象的信号与主页面的槽
    this->connect(this->thread,&capturePackageThread::show_data,this,&MainWindow::add_tableLine);
    // 获取设备列表
    this->device_Name=this->thread->get_deviceName();
    // 将设备名放入选择设备框中
    foreach (QString str, this->device_Name) {
        ui->selectDevice_Box->addItem(str);
    }
    // 将选择协议放入到选择协议框中
    ui->selectProtocol_Box->addItem("udp");
    ui->selectProtocol_Box->addItem("tcp");
    ui->selectProtocol_Box->addItem("http");
    ui->selectProtocol_Box->addItem("arp");
    ui->selectProtocol_Box->addItem("ip");

    // 获取屏幕分辨率
    QScreen *screen=QGuiApplication::primaryScreen();
    // 获取屏幕的像素大小
    QRect mm=screen->availableGeometry();
    // 设置界面的大小
    this->resize(mm.width(),mm.height());

    // 设置表格信息
    // 设置表格的列数
    ui->packetlistTable->setColumnCount(7);
    // 设置初始行数
    ui->packetlistTable->setRowCount(0);
    // 设置单元格的高度
    for(int i=0;i<ui->packetlistTable->rowCount();i++){
        ui->packetlistTable->setRowHeight(i,50);
    }
    // 设置单元格的大小
    ui->packetlistTable->setColumnWidth(0,static_cast<int>(floor(static_cast<double>(this->geometry().width())/20)));
    ui->packetlistTable->setColumnWidth(1,static_cast<int>(floor(static_cast<double>(this->geometry().width())*3/20)));
    ui->packetlistTable->setColumnWidth(2,static_cast<int>(floor(static_cast<double>(this->geometry().width())*3/20)));
    ui->packetlistTable->setColumnWidth(3,static_cast<int>(floor(static_cast<double>(this->geometry().width())/20)));
    ui->packetlistTable->setColumnWidth(4,static_cast<int>(floor(static_cast<double>(this->geometry().width())*3/20)));
    ui->packetlistTable->setColumnWidth(5,static_cast<int>(floor(static_cast<double>(this->geometry().width())*2/20)));
    ui->packetlistTable->setColumnWidth(6,static_cast<int>(floor(static_cast<double>(this->geometry().width())*6/20)));
    // 设置表格为只读，防止误修改
    ui->packetlistTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // 设置没有默认行号
    ui->packetlistTable->verticalHeader()->setVisible(false);
    // 设置选择方式为整行选中
    ui->packetlistTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    // 设置标题行信息
    QStringList tableAttributes;
    tableAttributes<<"Packet"<<"Source"<<"Destination"<<"Size"<<"Relative Time"<<"Protocol"<<"message";
    // 设置标题行
    ui->packetlistTable->setHorizontalHeaderLabels(tableAttributes);
    // 设置标题名为
    this->setWindowTitle("嗅探器-狗冕，嗅！");
}

MainWindow::~MainWindow()
{
    // 销毁列表
    ui->packetlistTable->close();
    ui->packetlistTable->clear();
    delete ui;
}

bool MainWindow::binaryStorage(QString fileName)
{
    // 创建文件对象
    QFile file(fileName);
    // 创建索引
    int maxIndex=0;
    // 读文件
    if(file.exists()){
        // 打开文件
        if(!file.open(QIODevice::ReadOnly)){
            // 错误信息
            qDebug()<<"读取文件失败";
            return false;
        }
        // 读取之前的条数
        QString allData=file.readAll();
        // 获取特定字符的个数
        maxIndex=allData.count("|");
        // 关闭文件
        file.close();
    }
    // 写文件
    // 判断文件是否存在-存在以追加形式打开否则以创建文件并打开
    if(file.exists()){
        // 打开文件-追加
        if(!file.open(QIODevice::Append)){
            // 错误信息
            qDebug()<<"文件(追加)打开失败";
            return false;
        }
    }else{
        // 打开文件
        if(!file.open(QIODevice::ReadWrite)){
            // 错误信息
            qDebug()<<"文件(创建)打开失败";
            return false;
        }
    }
    // 等待所有数据写入
    QThread::sleep(2);
    // 创建二进制文本对象
    QDataStream out(&file);
    // 使用双层for循环将列表项逐个遍历
    // 行遍历
    for(int i=0;i<ui->packetlistTable->rowCount();i++){
        // 列遍历
        for(int j=0;j<ui->packetlistTable->columnCount();j++){
            // 将数据逐个遍历
            // 将条数相加
            if(j==0){// 设置索引
                int currentIndex=ui->packetlistTable->item(i,j)->text().toInt();
                out<<QString("%1").arg(maxIndex+currentIndex)<<" -";
            }else{
               // 每个数据之间以" -"分隔
               out<<ui->packetlistTable->item(i,j)->text()<<" -";
            }
        }
        // 每行数据之间以"|"分隔
        out<<"|";
    }
    // 数据存储完毕-关闭文件
    file.close();
    return true;
}

bool MainWindow::jsonStorage(QString fileName)
{

}

// 修改选择设备时
void MainWindow::on_selectDevice_Box_activated(int index)
{
    this->thread->set_index(index);
}
// 修改选择协议时
void MainWindow::on_selectProtocol_Box_activated(const QString &text)
{
    this->thread->set_filter(text);
}
// 进行抓包
void MainWindow::on_capturePackage_clicked()
{
    if(this->thread->get_Flag()){//实际上还需要使用锁-防止数据写入不完全
        // 开启就关闭，并保存数据
        // 设置标志关闭
        this->thread->set_Flag(false);
        // 修改文本
        ui->capturePackage->setText("开始捕获");
        // 设置设备和协议可使用
        ui->selectDevice_Box->setEnabled(true);
        ui->selectProtocol_Box->setEnabled(true);
        // json
        //this->jsonStorage();
        // 关闭线程
        // 请求终止
        this->thread->requestInterruption();
        // 结束线程
        this->thread->quit();
        // 等待回收
        this->thread->wait();
        // 设置记录存储
        // 二进制
        this->binaryStorage();
    }else{
        // 关闭就开启，并保存数据
        // 设置标志开启
        this->thread->set_Flag(true);
        // 修改按钮文本
        ui->capturePackage->setText("结束捕获");
        // 对设备以及协议选择禁用
        ui->selectDevice_Box->setEnabled(false);
        ui->selectProtocol_Box->setEnabled(false);
        // 开启线程
        this->thread->start();
    }
}
// 进行选择存储记录时
/*void MainWindow::on_storedRecord_clicked()
{

}*/
// 进行点击对数据包进行具体分析
/*void MainWindow::on_messageInfo_tabel_itemDoubleClicked(QTableWidgetItem *item)
{

}*/
// 添加抓包的数据
void MainWindow::add_tableLine(int index)
{
    // 添加抓包的数据项
    // 添加新行 index表示插入的行数以及数据存储的编号
    ui->packetlistTable->insertRow(index-1);
    // 创建行中数据项
    QTableWidgetItem *Packet=new QTableWidgetItem(this->thread->getTable_data()->getPacket());
    QTableWidgetItem *Source=new QTableWidgetItem(this->thread->getTable_data()->getSource());
    QTableWidgetItem *Destination=new QTableWidgetItem(this->thread->getTable_data()->getDestination());
    QTableWidgetItem *Size=new QTableWidgetItem(QString(this->thread->getTable_data()->getSize()));
    QTableWidgetItem *RelativeTime=new QTableWidgetItem(this->thread->getTable_data()->getRelativeTime());
    QTableWidgetItem *Protocol=new QTableWidgetItem(this->thread->getTable_data()->getProtocol());
    QTableWidgetItem *Message=new QTableWidgetItem(this->thread->getTable_data()->getMessage());

    // 添加行
    ui->packetlistTable->setItem(index-1,0,Packet);
    ui->packetlistTable->setItem(index-1,1,Source);
    ui->packetlistTable->setItem(index-1,2,Destination);
    ui->packetlistTable->setItem(index-1,3,Size);
    ui->packetlistTable->setItem(index-1,4,RelativeTime);
    ui->packetlistTable->setItem(index-1,5,Protocol);
    ui->packetlistTable->setItem(index-1,6,Message);

    // 设置单元格的对其格式
    ui->packetlistTable->item(index-1,0)->setTextAlignment(Qt::AlignRight|Qt::AlignVCenter);
    ui->packetlistTable->item(index-1,1)->setTextAlignment(Qt::AlignCenter);
    ui->packetlistTable->item(index-1,2)->setTextAlignment(Qt::AlignCenter);
    ui->packetlistTable->item(index-1,3)->setTextAlignment(Qt::AlignRight|Qt::AlignVCenter);
    ui->packetlistTable->item(index-1,4)->setTextAlignment(Qt::AlignRight|Qt::AlignVCenter);
    ui->packetlistTable->item(index-1,5)->setTextAlignment(Qt::AlignLeft|Qt::AlignVCenter);
    ui->packetlistTable->item(index-1,6)->setTextAlignment(Qt::AlignLeft|Qt::AlignVCenter);

}

