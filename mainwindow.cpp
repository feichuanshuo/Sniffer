// 主窗口文件
#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "ncdialog.h"
#include "filterdialog.h"
#include <QMessageBox>

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    /*处理链路层*/
//    ethernet_header *eh;
//    eh = (ethernet_header *)pkt_data;
//    printf("源MAC地址：%x:%x:%x:%x:%x:%x",eh->saddr.byte1,eh->saddr.byte2,eh->saddr.byte3,eh->saddr.byte4,eh->saddr.byte5,eh->saddr.byte6);
    qDebug() << header->caplen;
}


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{

    ui->setupUi(this);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(7, QHeaderView::Stretch);

}

MainWindow::~MainWindow()
{
    delete ui;
}
// 设置网卡设备
void MainWindow::setSDev(QString data){
    sdev = data;
}

// 添加过滤规则
void MainWindow::addFilter(QString data){
    filterList.insert(data);
}

// 打开网卡设备选择窗口
void MainWindow::on_menu1_action1_triggered()
{
    NcDialog* ncdialog = new NcDialog(this);
    connect(ncdialog,SIGNAL(sendSDev(QString)),this,SLOT(setSDev(QString)));
    ncdialog->open();
}
// 打开过滤规则选择窗口
void MainWindow::on_menu1_action2_triggered()
{
    FilterDialog* filterdialog = new FilterDialog(this);
    connect(filterdialog,SIGNAL(sendFilter(QString)),this,SLOT(addFilter(QString)));
    filterdialog->open();
}


// 开始捕获

void MainWindow::on_menu2_action1_triggered()
{
    if(sdev==""){
        QMessageBox::warning(this,"警告","请先绑定网卡设备！");
        return;
    }
    else{
        const char* dname = sdev.toUtf8();
        char errbuf[PCAP_ERRBUF_SIZE];	// 出错信息
        // 打开一个网络接口
        pcap_t* descr = pcap_open_live(dname, BUFSIZ, 0, -1, errbuf);
        if (descr == NULL) {
            QMessageBox::critical(this,"错误","系统找不到指定的设备");
            return;
        }
        // 判断数据链路层类型是否为以太网
        if (pcap_datalink(descr) != DLT_EN10MB) {
            QMessageBox::critical(this,"错误","设备不是以太网设备！");
            pcap_close(descr);
            return;
        }
//        delete[] dname;
        // 创建过滤规则
        QString filter_exp = "";
        for (auto it = filterList.begin(); it != filterList.end(); ++it) {
            filter_exp = filter_exp + *it;
            if (*it!=*(filterList.rbegin())){
                filter_exp = filter_exp + " or ";
            }
        }
        struct bpf_program fp;
        bpf_u_int32 net;
        if (pcap_compile(descr, &fp, NULL , 0, net) == -1) {
            cerr << "pcap_compile failed: " << pcap_geterr(descr) << endl;
            pcap_close(descr);
            exit(1);
        }
        if (pcap_setfilter(descr, &fp) == -1)
        {
            cerr << "pcap_setfilter failed: " << pcap_geterr(descr) << endl;
            exit(1);
        }
        pcap_loop(descr, -1 , packet_handler, NULL);
        pcap_close(descr);

    }

}



