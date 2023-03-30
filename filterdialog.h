// 过滤规则弹窗文件
#ifndef FILTERDIALOG_H
#define FILTERDIALOG_H

#include <QDialog>
#include <QPushButton>
#include <set>

namespace Ui {
class FilterDialog;
}

class FilterDialog : public QDialog
{
    Q_OBJECT

public:
    explicit FilterDialog(QWidget *parent = nullptr);
    ~FilterDialog();

protected:
    void showEvent(QShowEvent *event) override;

private slots:
    void on_buttonBox_clicked(QAbstractButton *button);

signals:
    // 添加过滤规则
    void addFilter(QString);
    // 获取过滤规则
    std::set<QString> getFilter();
    // 清空过滤规则
    void clearFilter();

private:
    Ui::FilterDialog *ui;
};

#endif // FILTERDIALOG_H
