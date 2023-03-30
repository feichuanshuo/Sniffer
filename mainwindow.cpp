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
    connect(m_sniffer, SIGNAL(setTableData(ethernet_data,ip_data,QString,QString)), this, SLOT(setPacketTable(ethernet_data,ip_data,QString,QString)));

    ui->tableWidget->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    // 处理 itemSelectionChanged() 信号
    connect(ui->tableWidget, &QTableWidget::itemSelectionChanged, this, [this]() {
        // 获取当前选中的行数
        QList<QTableWidgetItem *> selectedItems = ui->tableWidget->selectedItems();
        QList<int> selectedRows;
        for (auto item : selectedItems) {
            if (!selectedRows.contains(item->row())) {
                selectedRows.append(item->row());
            }
        }

        // 处理选中行的内容
        for (int row : selectedRows) {
            QTableWidgetItem *item3 = ui->tableWidget->item(row, 3);
            QTableWidgetItem *item5 = ui->tableWidget->item(row, 5);
            ethernet_data p_ethernet = item3->data(Qt::UserRole).value<ethernet_data>();
            ip_data p_ip = item5->data(Qt::UserRole).value<ip_data>();
            ui->treeWidget->setHeaderLabel("数据包"+QString::number(row));
            // 删除所有节点
            ui->treeWidget->clear();

            // 添加数据链路层
            QTreeWidgetItem *ethernetLayer = new QTreeWidgetItem(ui->treeWidget);
            ethernetLayer->setText(0, "数据链路层");
            ui->treeWidget->addTopLevelItem(ethernetLayer);

            QTreeWidgetItem *echild1 = new QTreeWidgetItem(ethernetLayer);
            echild1->setText(0, "源MAC地址:"+p_ethernet.dmac);
            ethernetLayer->addChild(echild1);

            QTreeWidgetItem *echild2 = new QTreeWidgetItem(ethernetLayer);
            echild2->setText(0, "目的MAC地址:"+p_ethernet.smac);
            ethernetLayer->addChild(echild2);

            QTreeWidgetItem *echild3 = new QTreeWidgetItem(ethernetLayer);
            echild3->setText(0, "上层协议:"+p_ethernet.protocol);
            ethernetLayer->addChild(echild3);

            // 添加网路层
            QTreeWidgetItem *networkLayer = new QTreeWidgetItem(ui->treeWidget);
            networkLayer->setText(0, "网络层");
            ui->treeWidget->addTopLevelItem(networkLayer);

            QTreeWidgetItem *nchild1 = new QTreeWidgetItem(networkLayer);
            nchild1->setText(0, "版本:"+p_ip.ver);
            networkLayer->addChild(nchild1);

            QTreeWidgetItem *nchild2 = new QTreeWidgetItem(networkLayer);
            nchild2->setText(0, "首部长度:"+p_ip.ihl);
            networkLayer->addChild(nchild2);

            QTreeWidgetItem *nchild3 = new QTreeWidgetItem(networkLayer);
            nchild3->setText(0, "服务类型:0x"+p_ip.tos);
            networkLayer->addChild(nchild3);

            QTreeWidgetItem *nchild4 = new QTreeWidgetItem(networkLayer);
            nchild4->setText(0, "总长度:"+p_ip.tlen);
            networkLayer->addChild(nchild4);

            QTreeWidgetItem *nchild5 = new QTreeWidgetItem(networkLayer);
            nchild5->setText(0, "标识:0x"+p_ip.identification);
            networkLayer->addChild(nchild5);

            QTreeWidgetItem *nchild6 = new QTreeWidgetItem(networkLayer);
            nchild6->setText(0, "标志位:"+p_ip.flags_fo);
            networkLayer->addChild(nchild6);

            QTreeWidgetItem *nchild7 = new QTreeWidgetItem(networkLayer);
            nchild7->setText(0, "生存时间:"+p_ip.ttl);
            networkLayer->addChild(nchild7);

            QTreeWidgetItem *nchild8 = new QTreeWidgetItem(networkLayer);
            nchild8->setText(0, "上层协议:"+p_ip.type);
            networkLayer->addChild(nchild8);

            QTreeWidgetItem *nchild9 = new QTreeWidgetItem(networkLayer);
            nchild9->setText(0, "首部校验和:0x"+p_ip.crc);
            networkLayer->addChild(nchild9);

            QTreeWidgetItem *nchild10 = new QTreeWidgetItem(networkLayer);
            nchild10->setText(0, "源地址:"+p_ip.saddr);
            networkLayer->addChild(nchild10);

            QTreeWidgetItem *nchild11 = new QTreeWidgetItem(networkLayer);
            nchild11->setText(0, "目的地址:"+p_ip.daddr);
            networkLayer->addChild(nchild11);

            QTreeWidgetItem *nchild12 = new QTreeWidgetItem(networkLayer);
            nchild12->setText(0, "选项与填充:"+p_ip.op_pad);
            networkLayer->addChild(nchild12);



            // 添加传输层
            QTreeWidgetItem *transportLayer = new QTreeWidgetItem(ui->treeWidget);
            transportLayer->setText(0, "传输层");
            ui->treeWidget->addTopLevelItem(transportLayer);
        }
    });

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
void MainWindow::setPacketTable(ethernet_data p_ethernet,ip_data p_ip,QString p_len,QString p_time){
    // 新增一行
    int row = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(row);
    /*** 添加数据 ***/
    // 添加上层协议类型
    QTableWidgetItem *packet_protocol = new QTableWidgetItem(p_ip.type);
    ui->tableWidget->setItem(row, 0, packet_protocol);

    // 添加包捕获时间
    QTableWidgetItem *packet_time = new QTableWidgetItem(p_time);
    ui->tableWidget->setItem(row, 1, packet_time);

    // 添加包的目的MAC地址
    QTableWidgetItem *packet_dmac = new QTableWidgetItem(p_ethernet.dmac);
    ui->tableWidget->setItem(row, 2, packet_dmac);

    // 添加包的源MAC地址
    QTableWidgetItem *packet_smac = new QTableWidgetItem(p_ethernet.smac);
    // 将以太网帧数据存到该表格项
    packet_smac->setData(Qt::UserRole, QVariant::fromValue(p_ethernet));
    ui->tableWidget->setItem(row, 3, packet_smac);

    // 添加包的目的IP地址
    QTableWidgetItem *packet_dip = new QTableWidgetItem(p_ip.daddr);
    ui->tableWidget->setItem(row, 4, packet_dip);

    // 添加包的源IP地址
    QTableWidgetItem *packet_sip = new QTableWidgetItem(p_ip.saddr);
    // 将网络层数据存储到该表格项
    packet_sip->setData(Qt::UserRole, QVariant::fromValue(p_ip));
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

