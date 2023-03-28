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
    delete m_sniffer;
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
    connect(filterdialog,SIGNAL(sendFilter(QString)),m_sniffer,SLOT(addFilter(QString)));
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
    m_thread->quit();
    m_thread->wait();  // 等待线程退出
}

