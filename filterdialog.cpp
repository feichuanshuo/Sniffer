// 过滤规则弹窗文件
#include "filterdialog.h"
#include "ui_filterdialog.h"
#include <QPushButton>

FilterDialog::FilterDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::FilterDialog)
{
    setFixedSize(400,200);
    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText("确定");
    ui->buttonBox->button(QDialogButtonBox::Cancel)->setText("取消");
}

FilterDialog::~FilterDialog()
{
    delete ui;
}

void FilterDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    emit sendFilter("");
    QDialogButtonBox::StandardButton btn = ui->buttonBox->standardButton(button);
    if (btn == QDialogButtonBox::Ok) {
        QList<QCheckBox*> checkBoxes = findChildren<QCheckBox*>();
        for (auto checkBox : checkBoxes) {
            if(checkBox->isChecked()){
                emit sendFilter(checkBox->text());
            }
        }
        QDialog::accept();
    } else if (btn == QDialogButtonBox::Cancel) {
        // 取消操作
        QDialog::reject();

    }
}

