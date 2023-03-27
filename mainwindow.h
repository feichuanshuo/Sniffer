// 主窗口文件
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "pcap.h"
#include <QMainWindow>
#include <set>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_menu1_action1_triggered();
    // 设置网卡设备
    void setSDev(QString data);
    // 添加过滤规则
    void addFilter(QString data);

    void on_menu2_action1_triggered();

    void on_menu1_action2_triggered();

private:
    Ui::MainWindow *ui;
    // 当前用于捕获的网卡设备
    const char* sdev = nullptr;
    std::set<QString> filterList;
};
#endif // MAINWINDOW_H
