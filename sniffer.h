#ifndef SNIFFER_H
#define SNIFFER_H

#include <QObject>
#include <QThread>
#include <QMainWindow>
#include <set>
#include "pcap.h"
#include "datapackage.h"

/****** sniffer ******/
class Sniffer : public QThread
{
    Q_OBJECT
private:
    QString sdev = "";
    std::set<QString> filterList;
    pcap_t* descr;
    QMainWindow* m_win;
public:
    QVector<DataPackage> packageList;
public:
    explicit Sniffer();
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
    void setTableData(DataPackage package);
protected:
    void run() override;

};

#endif
