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
    m_sniffer = new Sniffer();
    connect(m_sniffer, SIGNAL(warning(QString)), this, SLOT(showWarningDialog(QString)));
    connect(m_sniffer, SIGNAL(error(QString)), this, SLOT(showErrorDialog(QString)));
    connect(m_sniffer, SIGNAL(setTableData(DataPackage)), this, SLOT(setPacketTable(DataPackage)));

    ui->tableWidget->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    ui->treeWidget->setHeaderLabel("");
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

            /****** 展示包详情 ******/
            ui->treeWidget->clear();
            ui->treeWidget->setHeaderLabel("数据包"+QString::number(row+1));
            DataPackage data = m_sniffer->packageList.at(row);

            // 添加数据链路层
            QTreeWidgetItem *ethernetLayer = new QTreeWidgetItem(ui->treeWidget);
            ethernetLayer->setText(0, "数据链路层");
            ui->treeWidget->addTopLevelItem(ethernetLayer);

            QTreeWidgetItem *echild1 = new QTreeWidgetItem(ethernetLayer);
            echild1->setText(0, "源MAC地址: " + data.getSrcMacAddr());
            ethernetLayer->addChild(echild1);

            QTreeWidgetItem *echild2 = new QTreeWidgetItem(ethernetLayer);
            echild2->setText(0, "目的MAC地址: " + data.getDesMacAddr());
            ethernetLayer->addChild(echild2);

            QTreeWidgetItem *echild3 = new QTreeWidgetItem(ethernetLayer);
            echild3->setText(0, "上层协议: " + data.getMacType());
            ethernetLayer->addChild(echild3);

            // 添加网络层
            QTreeWidgetItem *networkLayer = new QTreeWidgetItem(ui->treeWidget);

            networkLayer->setText(0, "网络层");
            ui->treeWidget->addTopLevelItem(networkLayer);

            if (data.getPackageNLType() == IP){
                QTreeWidgetItem *nchild1 = new QTreeWidgetItem(networkLayer);
                nchild1->setText(0, "版本: " + data.getIpVersion());
                networkLayer->addChild(nchild1);

                QTreeWidgetItem *nchild2 = new QTreeWidgetItem(networkLayer);
                nchild2->setText(0, "首部长度: " + data.getIpHeaderLength());
                networkLayer->addChild(nchild2);

                QTreeWidgetItem *nchild3 = new QTreeWidgetItem(networkLayer);
                nchild3->setText(0, "服务类型: " + data.getIpTos());
                networkLayer->addChild(nchild3);

                QTreeWidgetItem *nchild4 = new QTreeWidgetItem(networkLayer);
                nchild4->setText(0, "总长度: " + data.getIpTotalLength());
                networkLayer->addChild(nchild4);

                QTreeWidgetItem *nchild5 = new QTreeWidgetItem(networkLayer);
                nchild5->setText(0, "标识: " + data.getIpIdentification());
                networkLayer->addChild(nchild5);

                QTreeWidgetItem *nchild6 = new QTreeWidgetItem(networkLayer);
                nchild6->setText(0, "标志位: " + data.getIpFlag());
                networkLayer->addChild(nchild6);

                QTreeWidgetItem *nchild7 = new QTreeWidgetItem(networkLayer);
                nchild7->setText(0, "保留位: " + data.getIpReservedBit());
                networkLayer->addChild(nchild7);

                QTreeWidgetItem *nchild8 = new QTreeWidgetItem(networkLayer);
                nchild8->setText(0, "DF: " + data.getIpDF());
                networkLayer->addChild(nchild8);

                QTreeWidgetItem *nchild9 = new QTreeWidgetItem(networkLayer);
                nchild9->setText(0, "MF: " + data.getIpMF());
                networkLayer->addChild(nchild9);

                QTreeWidgetItem *nchild10 = new QTreeWidgetItem(networkLayer);
                nchild10->setText(0, "片偏移: " + data.getIpFragmentOffset());
                networkLayer->addChild(nchild10);

                QTreeWidgetItem *nchild11 = new QTreeWidgetItem(networkLayer);
                nchild11->setText(0, "生存时间: " + data.getIpTTL());
                networkLayer->addChild(nchild11);

                QTreeWidgetItem *nchild12 = new QTreeWidgetItem(networkLayer);
                nchild12->setText(0, "上层协议: " + data.getIpProtocol());
                networkLayer->addChild(nchild12);

                QTreeWidgetItem *nchild13 = new QTreeWidgetItem(networkLayer);
                nchild13->setText(0, "首部校验和: " + data.getIpCheckSum());
                networkLayer->addChild(nchild13);

                QTreeWidgetItem *nchild14 = new QTreeWidgetItem(networkLayer);
                nchild14->setText(0, "源地址: " + data.getSrcIpAddr());
                networkLayer->addChild(nchild14);

                QTreeWidgetItem *nchild15 = new QTreeWidgetItem(networkLayer);
                nchild15->setText(0, "目的地址: " + data.getDesIpAddr());
                networkLayer->addChild(nchild15);

                // 添加传输层
                QTreeWidgetItem *transportLayer = new QTreeWidgetItem(ui->treeWidget);
                transportLayer->setText(0, "传输层");
                ui->treeWidget->addTopLevelItem(transportLayer);
                if (data.getIpProtocol() == "TCP"){
                    QTreeWidgetItem *tchild1 = new QTreeWidgetItem(transportLayer);
                    tchild1->setText(0, "源端口: " + data.getTcpSourcePort());
                    transportLayer->addChild(tchild1);

                    QTreeWidgetItem *tchild2 = new QTreeWidgetItem(transportLayer);
                    tchild2->setText(0, "目的端口: " + data.getTcpDestinationPort());
                    transportLayer->addChild(tchild2);

                    QTreeWidgetItem *tchild5 = new QTreeWidgetItem(transportLayer);
                    tchild5->setText(0, "头部长度: " + data.getTcpHeaderLength());
                    transportLayer->addChild(tchild5);

                    QTreeWidgetItem *tchild3 = new QTreeWidgetItem(transportLayer);
                    tchild3->setText(0, "序列号: " + data.getTcpSequence());
                    transportLayer->addChild(tchild3);

                    QTreeWidgetItem *tchild12 = new QTreeWidgetItem(transportLayer);
                    tchild12->setText(0, "确认号: " + data.getTcpAcknowledgment());
                    transportLayer->addChild(tchild12);

                    QTreeWidgetItem *tchild7 = new QTreeWidgetItem(transportLayer);
                    tchild7->setText(0, "Flags: " + data.getTcpFlags());
                    transportLayer->addChild(tchild7);

                    QTreeWidgetItem *tchild8 = new QTreeWidgetItem(transportLayer);
                    tchild8->setText(0, "PSH: " + data.getTcpPSH());
                    transportLayer->addChild(tchild8);

                    QTreeWidgetItem *tchild4 = new QTreeWidgetItem(transportLayer);
                    tchild4->setText(0, "ACK: " + data.getTcpACK());
                    transportLayer->addChild(tchild4);

                    QTreeWidgetItem *tchild10 = new QTreeWidgetItem(transportLayer);
                    tchild10->setText(0, "SYN: " + data.getTcpSYN());
                    transportLayer->addChild(tchild10);

                    QTreeWidgetItem *tchild6 = new QTreeWidgetItem(transportLayer);
                    tchild6->setText(0, "URG: " + data.getTcpURG());
                    transportLayer->addChild(tchild6);

                    QTreeWidgetItem *tchild11 = new QTreeWidgetItem(transportLayer);
                    tchild11->setText(0, "FIN: " + data.getTcpFIN());
                    transportLayer->addChild(tchild11);

                    QTreeWidgetItem *tchild9 = new QTreeWidgetItem(transportLayer);
                    tchild9->setText(0, "RST: " + data.getTcpRST());
                    transportLayer->addChild(tchild9);

                    QTreeWidgetItem *tchild13 = new QTreeWidgetItem(transportLayer);
                    tchild13->setText(0, "窗口大小: " + data.getTcpWindowSize());
                    transportLayer->addChild(tchild13);

                    QTreeWidgetItem *tchild14 = new QTreeWidgetItem(transportLayer);
                    tchild14->setText(0, "校验和: " + data.getTcpCheckSum());
                    transportLayer->addChild(tchild14);

                    QTreeWidgetItem *tchild15 = new QTreeWidgetItem(transportLayer);
                    tchild15->setText(0, "紧急指针: " + data.getTcpUrgentPointer());
                    transportLayer->addChild(tchild15);
                }
                else if (data.getIpProtocol() == "UDP"){
                    QTreeWidgetItem *tchild1 = new QTreeWidgetItem(transportLayer);
                    tchild1->setText(0, "源端口: " + data.getUdpSourcePort());
                    transportLayer->addChild(tchild1);

                    QTreeWidgetItem *tchild2 = new QTreeWidgetItem(transportLayer);
                    tchild2->setText(0, "目的端口: " + data.getUdpDestinationPort());
                    transportLayer->addChild(tchild2);

                    QTreeWidgetItem *tchild3 = new QTreeWidgetItem(transportLayer);
                    tchild3->setText(0, "数据长度: " + data.getUdpDataLength());
                    transportLayer->addChild(tchild3);

                    QTreeWidgetItem *tchild4 = new QTreeWidgetItem(transportLayer);
                    tchild4->setText(0, "校验和: " + data.getUdpCheckSum());
                    transportLayer->addChild(tchild4);
                }
                else if (data.getIpProtocol() == "ICMP") {
                    QTreeWidgetItem *tchild1 = new QTreeWidgetItem(transportLayer);
                    tchild1->setText(0, "类型: " + data.getIcmpType());
                    transportLayer->addChild(tchild1);

                    QTreeWidgetItem *tchild2 = new QTreeWidgetItem(transportLayer);
                    tchild2->setText(0, "Code: " + data.getIcmpCode());
                    transportLayer->addChild(tchild2);

                    QTreeWidgetItem *tchild3 = new QTreeWidgetItem(transportLayer);
                    tchild3->setText(0, "校验和: " + data.getIcmpCheckSum());
                    transportLayer->addChild(tchild3);

                    QTreeWidgetItem *tchild4 = new QTreeWidgetItem(transportLayer);
                    tchild4->setText(0, "标识: " + data.getIcmpIdentification());
                    transportLayer->addChild(tchild4);

                    QTreeWidgetItem *tchild5 = new QTreeWidgetItem(transportLayer);
                    tchild5->setText(0, "序列号: " + data.getIcmpSequeue());
                    transportLayer->addChild(tchild5);

                }
            }
            else if (data.getPackageNLType() == ARP){
                QTreeWidgetItem *nchild1 = new QTreeWidgetItem(networkLayer);
                nchild1->setText(0, "硬件类型: " + data.getArpHardwareType());
                networkLayer->addChild(nchild1);

                QTreeWidgetItem *nchild2 = new QTreeWidgetItem(networkLayer);
                nchild2->setText(0, "协议类型: " + data.getArpProtocolType());
                networkLayer->addChild(nchild2);

                QTreeWidgetItem *nchild3 = new QTreeWidgetItem(networkLayer);
                nchild3->setText(0, "硬件长度: " + data.getArpHardwareLength());
                networkLayer->addChild(nchild3);

                QTreeWidgetItem *nchild4 = new QTreeWidgetItem(networkLayer);
                nchild4->setText(0, "协议长度: " + data.getArpProtocolLength());
                networkLayer->addChild(nchild4);

                QTreeWidgetItem *nchild5 = new QTreeWidgetItem(networkLayer);
                nchild5->setText(0, "操作类型: " + data.getArpOperationCode());
                networkLayer->addChild(nchild5);

                QTreeWidgetItem *nchild6 = new QTreeWidgetItem(networkLayer);
                nchild6->setText(0, "发送端硬件地址: " + data.getArpSourceEtherAddr());
                networkLayer->addChild(nchild6);

                QTreeWidgetItem *nchild7 = new QTreeWidgetItem(networkLayer);
                nchild7->setText(0, "发送端协议地址: " + data.getArpSourceIpAddr());
                networkLayer->addChild(nchild7);

                 QTreeWidgetItem *nchild8 = new QTreeWidgetItem(networkLayer);
                 nchild8->setText(0, "接受端硬件地址: " + data.getArpDestinationEtherAddr());
                 networkLayer->addChild(nchild8);

                 QTreeWidgetItem *nchild9 = new QTreeWidgetItem(networkLayer);
                 nchild9->setText(0, "接受端协议地址: " + data.getArpDestinationIpAddr());
                 networkLayer->addChild(nchild9);

            }

            /****** 展示包二进制数据流 ******/

            QByteArray hexData;
            for (int i = 0; i < data.getDataLength(); i++) {
                 hexData.append(QString("%1").arg(data.pkt_content[i], 2, 16, QChar('0')).toUtf8());
                 hexData.append(" ");
            }
            QString hexString(hexData);
            ui->textBrowser1->setText(hexString);

            QString utf8Data = QString::fromLocal8Bit(reinterpret_cast<const char*>(data.pkt_content), data.getDataLength());
            ui->textBrowser2->setText(utf8Data);
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
    m_sniffer->quit();
    m_sniffer->wait();
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
void MainWindow::setPacketTable(DataPackage package){
    // 新增一行
    int row = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(row);

    // 添加包捕获时间
    QTableWidgetItem *packet_time = new QTableWidgetItem(package.getTime());
    ui->tableWidget->setItem(row, 0, packet_time);

    // 添加包的目的MAC地址
    QTableWidgetItem *packet_dmac = new QTableWidgetItem(package.getDesMacAddr());
    ui->tableWidget->setItem(row, 1, packet_dmac);

    // 添加包的源MAC地址
    QTableWidgetItem *packet_smac = new QTableWidgetItem(package.getSrcMacAddr());
    ui->tableWidget->setItem(row, 2, packet_smac);

    // 添加包的目的IP地址
    QTableWidgetItem *packet_dip = new QTableWidgetItem(package.getDesIpAddr());
    ui->tableWidget->setItem(row, 3, packet_dip);

    // 添加包的源IP地址
    QTableWidgetItem *packet_sip = new QTableWidgetItem(package.getSrcIpAddr());
    ui->tableWidget->setItem(row, 4, packet_sip);

    // 添加上层协议类型
    QTableWidgetItem *packet_protocol = new QTableWidgetItem(package.getIpProtocol());
    ui->tableWidget->setItem(row, 5, packet_protocol);

    // 添加包长度
    QTableWidgetItem *packet_len = new QTableWidgetItem(QString::number(package.getDataLength()));
    ui->tableWidget->setItem(row, 6, packet_len);

}


// 开始捕获
void MainWindow::on_menu2_action1_triggered(){
    m_sniffer->start();
}




// 停止捕获
void MainWindow::on_menu2_action2_triggered()
{
    m_sniffer->stopCapture();
}

void MainWindow::on_actiondsadas_triggered()
{
    m_sniffer->packageList.clear();
    ui->tableWidget->clearContents();
    ui->tableWidget->setRowCount(0);
    ui->treeWidget->clear();
    ui->treeWidget->setHeaderLabel("");
}

