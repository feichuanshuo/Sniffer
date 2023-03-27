#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

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
    void setSDev(QString data);

private:
    Ui::MainWindow *ui;
    // 当前用于捕获的网卡设备
    QString sdev;
};
#endif // MAINWINDOW_H
