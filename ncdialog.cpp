// 网卡设备选择窗口文件
#include "ncdialog.h"
#include "ui_ncdialog.h"
#include <QPushButton>
#include <QMessageBox>


NcDialog::NcDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::NcDialog)
{
    setFixedSize(660,350);
    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText("绑定");
    ui->buttonBox->button(QDialogButtonBox::Cancel)->setText("取消");
    // 设置各列的宽度
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    // 设置整行选中
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    // 设置不可编辑
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
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
            QTableWidgetItem *item0 = ui->tableWidget->item(row, 0);
            ui->textBrowser->setText(item0->text());
        }
    });

}

NcDialog::~NcDialog()
{
    delete ui;
}

void NcDialog::showEvent(QShowEvent * event){
   QWidget::showEvent(event);
    // 网络接口设备列表
   char errbuf[PCAP_ERRBUF_SIZE];	// 出错信息
   // 网卡设备列表
   pcap_if_t* alldevs;

   // 获取网络接口设备名称
   if (pcap_findalldevs(&alldevs, errbuf) == -1)
   {
       cerr << "Error in pcap_findalldevs:" << errbuf << endl;
       exit(1);
   }
   // 清空表格中的内容
   ui->tableWidget->clearContents();

   // 设置表格的行数
   int devNum = 0;
   for(pcap_if_t* dev = alldevs; dev; dev = dev->next){
       devNum++;
   }
   ui->tableWidget->setRowCount(devNum);

   int row = 0;
   for(pcap_if_t* dev = alldevs; dev; dev = dev->next,row++){
       ui->tableWidget->setItem(row,0,new QTableWidgetItem(dev->name));
       ui->tableWidget->setItem(row,1,new QTableWidgetItem(dev->description));
   }
   // 释放网络接口设备列表占用的内存空间
   pcap_freealldevs(alldevs);

}

// 自定义窗口按钮功能
void NcDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    QDialogButtonBox::StandardButton btn = ui->buttonBox->standardButton(button);
    if (btn == QDialogButtonBox::Ok) {
        // 绑定网卡设备
        if(ui->textBrowser->toPlainText()==""){
             // 用户未选择网卡设备的回调
            QMessageBox::warning(this,"警告","请选择网卡设备后再进行绑定！");
        }
        else {
            // 用户选择网卡设备的回调
            emit sendSDev(ui->textBrowser->toPlainText());
            QDialog::accept();

        }

    } else if (btn == QDialogButtonBox::Cancel) {
        // 取消操作
        QDialog::reject();

    }
}

