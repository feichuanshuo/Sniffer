// 过滤规则弹窗文件
#ifndef FILTERDIALOG_H
#define FILTERDIALOG_H

#include <QDialog>
#include <QPushButton>

namespace Ui {
class FilterDialog;
}

class FilterDialog : public QDialog
{
    Q_OBJECT

public:
    explicit FilterDialog(QWidget *parent = nullptr);
    ~FilterDialog();

private slots:
    void on_buttonBox_clicked(QAbstractButton *button);

signals:
    void sendFilter(QString);
private:
    Ui::FilterDialog *ui;
};

#endif // FILTERDIALOG_H
