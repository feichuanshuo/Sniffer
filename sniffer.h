#ifndef SNIFFER_H
#define SNIFFER_H

#include <QObject>
#include <QThread>
#include <QMainWindow>
#include <set>
#include "pcap.h"

class Sniffer : public QObject
{
    Q_OBJECT
public:
    explicit Sniffer(QObject *parent = nullptr,QMainWindow* win = nullptr);
public slots:
    // 设置网卡设备
    void setSDev(QString data);
    // 添加过滤规则
    void addFilter(QString data);
    // 开始捕获
    void startCapture();
    // 结束捕获
    void stopCapture();
signals:
    void warning(QString);
    void error(QString);

private:
    QString sdev = "";
    std::set<QString> filterList;
    pcap_t* descr;
    QMainWindow* m_win;
};

class MyThread : public QThread
{
    Q_OBJECT

public:
    MyThread(QObject* parent = nullptr);
    void quit();

protected:
    void run() override;

private:
    Sniffer* m_sniffer;
};

#endif // SNIFFER_H
