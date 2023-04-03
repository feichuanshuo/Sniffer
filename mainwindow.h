// 主窗口文件
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "pcap.h"
#include <QMainWindow>
#include "sniffer.h"
#include "head.h"

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
    void on_menu1_action2_triggered();
    void on_menu2_action1_triggered();
    void on_menu2_action2_triggered();
    // 展示警告弹窗
    void showWarningDialog(QString text);
    // 展示错误弹窗
    void showErrorDialog(QString text);
    // 展示包
    void setPacketTable(DataPackage package);
    void on_actiondsadas_triggered();

signals:
    void warning(QString);
    void error(QString);
private:
    Ui::MainWindow *ui;
    // 嗅探器程序
    Sniffer* m_sniffer;
};
#endif // MAINWINDOW_H
