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
    // 获取过滤规则
    std::set<QString> getFilter();
    // 清空过滤规则
    void clearFilter();
    // 开始捕获
    void startCapture();
    // 结束捕获
    void stopCapture();

signals:
    // 警告弹窗
    void warning(QString);
    // 错误弹窗
    void error(QString);
    // 向表格填充数据
    void setTableData(QString p_protocol,QString p_time,QString p_dmac,QString p_smac,QString p_dip,QString p_sip,QString p_len);

private:
    QString sdev = "";
    std::set<QString> filterList;
    pcap_t* descr;
    QMainWindow* m_win;

};

// sniffer线程
class MyThread : public QThread
{
    Q_OBJECT

public:
    MyThread(QObject* parent = nullptr);

protected:
    void run() override;

private:
    Sniffer* m_sniffer;
};

#endif // SNIFFER_H
