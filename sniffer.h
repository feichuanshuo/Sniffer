#ifndef SNIFFER_H
#define SNIFFER_H

#include <QObject>
#include <QThread>
#include <QMainWindow>
#include <set>
#include "pcap.h"

// 以太网数据帧
typedef struct ethernet_data{
    // 目的mac地址
    QString dmac;
    // 源mac地址
    QString smac;
    // 上层协议
    QString protocol;
} ethernet_data;

// IP数据包
typedef struct ip_data
{
    QString ver;                // 版本
    QString ihl;                // 首部长度
    QString  tos;               // 服务类型(Type of service)
    QString tlen;               // 总长度(Total length)
    QString identification;     // 标识(Identification)
    QString flags_fo;           // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    QString  ttl;               // 生存时间(Time to live)
    QString  type;              // 协议(Protocol)
    QString crc;                // 首部校验和(Header checksum)
    QString  saddr;             // 源地址(Source address)
    QString  daddr;             // 目的地址(Destination address)
    QString   op_pad;           // 选项与填充(Option + Padding)
}ip_data;



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
    void setTableData(ethernet_data p_ethernet,ip_data p_ip,QString p_len,QString p_time);

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

