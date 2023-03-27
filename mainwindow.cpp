// 主窗口文件
#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "ncdialog.h"
#include "filterdialog.h"
#include <QMessageBox>



MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{

    char sdev[1024] = {0};
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
    delete[] sdev;
}
// 设置网卡设备
void MainWindow::setSDev(QString data){
    sdev = data.toUtf8();
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
    if(sdev==nullptr || strlen(sdev) == 0){
        QMessageBox::warning(this,"警告","请先绑定网卡设备！");
        return;
    }
    else{
        char errbuf[PCAP_ERRBUF_SIZE];	// 出错信息
        // 打开一个网络接口
        pcap_t* descr = pcap_open_live(sdev, BUFSIZ, 0, -1, errbuf);
        if (descr == NULL) {
            QMessageBox::critical(this,"错误","系统找不到指定的设备");
        }
        // 判断数据链路层类型是否为以太网
        if (pcap_datalink(descr) != DLT_EN10MB) {
            QMessageBox::critical(this,"错误","设备不是以太网设备！");
            pcap_close(descr);
        }
    }

}



