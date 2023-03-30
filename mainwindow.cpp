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
    ui->setupUi(this);
    m_sniffer = new Sniffer(nullptr,this);
    connect(m_sniffer, SIGNAL(warning(QString)), this, SLOT(showWarningDialog(QString)));
    connect(m_sniffer, SIGNAL(error(QString)), this, SLOT(showErrorDialog(QString)));
    connect(m_sniffer, SIGNAL(setTableData(QString,QString,QString,QString,QString,QString,QString)), this, SLOT(setPacketTable(QString,QString,QString,QString,QString,QString,QString)));


    ui->tableWidget->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    // 设置整行选中
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    // 设置不可编辑
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);

}

MainWindow::~MainWindow()
{
    delete ui;
    delete m_sniffer;
    // 在主线程中销毁QThread对象
    m_thread->quit();
    m_thread->wait();
    delete m_thread;
}

// 打开网卡设备选择窗口
void MainWindow::on_menu1_action1_triggered()
{
    NcDialog* ncdialog = new NcDialog(this);
    connect(ncdialog,SIGNAL(sendSDev(QString)),m_sniffer,SLOT(setSDev(QString)));
    ncdialog->open();
}
// 打开过滤规则选择窗口
void MainWindow::on_menu1_action2_triggered()
{
    FilterDialog* filterdialog = new FilterDialog(this);
    connect(filterdialog,SIGNAL(addFilter(QString)),m_sniffer,SLOT(addFilter(QString)));
    connect(filterdialog,SIGNAL(clearFilter()),m_sniffer,SLOT(clearFilter()));
    connect(filterdialog,SIGNAL(getFilter()),m_sniffer,SLOT(getFilter()));
    filterdialog->open();
}

// 展示警告弹窗
void MainWindow::showWarningDialog(QString text){
    QMessageBox::warning(this,"警告",text);
}
// 展示错误弹窗
void MainWindow::showErrorDialog(QString text){
    QMessageBox::critical(this,"错误",text);
}

// 展示包
void MainWindow::setPacketTable(QString p_protocol,QString p_time,QString p_dmac,QString p_smac,QString p_dip,QString p_sip,QString p_len){
    // 新增一行
    int row = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(row);
    /*** 添加数据 ***/
    // 添加上层协议类型
    QTableWidgetItem *packet_protocol = new QTableWidgetItem(p_protocol);
    ui->tableWidget->setItem(row, 0, packet_protocol);
    // 添加包捕获时间
    QTableWidgetItem *packet_time = new QTableWidgetItem(p_time);
    ui->tableWidget->setItem(row, 1, packet_time);
    // 添加包的目的MAC地址
    QTableWidgetItem *packet_dmac = new QTableWidgetItem(p_dmac);
    ui->tableWidget->setItem(row, 2, packet_dmac);
    // 添加包的源MAC地址
    QTableWidgetItem *packet_smac = new QTableWidgetItem(p_smac);
    ui->tableWidget->setItem(row, 3, packet_smac);
    // 添加包的目的IP地址
    QTableWidgetItem *packet_dip = new QTableWidgetItem(p_dip);
    ui->tableWidget->setItem(row, 4, packet_dip);
    // 添加包的源MAC地址
    QTableWidgetItem *packet_sip = new QTableWidgetItem(p_sip);
    ui->tableWidget->setItem(row, 5, packet_sip);
    // 添加包长度
    QTableWidgetItem *packet_len = new QTableWidgetItem(p_len);
    ui->tableWidget->setItem(row, 6, packet_len);
}

// 开始捕获
void MainWindow::on_menu2_action1_triggered(){
    m_thread = new QThread(this);
    m_sniffer->moveToThread(m_thread);
    connect(m_thread, &QThread::started, m_sniffer, &Sniffer::startCapture);
    m_thread->start();

}




// 停止捕获
void MainWindow::on_menu2_action2_triggered()
{
    m_sniffer->stopCapture();
}

