
#include "sniffer.h"
#include "head.h"
#include <winsock2.h>
#include <iostream>


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    // 将用户参数转换为Sniffer对象
    Sniffer* sniffer = reinterpret_cast<Sniffer*>(param);

    /****** 定义传递的数据包详情 ******/
    QString p_time;
    QString p_len;
    // 以太网帧
    ethernet_data p_ethernet;
    // ip数据包
    ip_data p_ip;


    /****** 解析包头信息 ******/
    // 获取数据包的长度
    p_len = QString::number(header->len);
    // 获取数据包的时间戳
    time_t t = header->ts.tv_sec;
    struct tm* local_time = localtime(&t);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", local_time);
    int ms = header->ts.tv_usec;
    p_time = QString(time_str) + "." + QString::number(ms).leftJustified(6, '0');
    /****** 解析数据包 ******/
    /*处理链路层*/
    ethernet_header *eh;
    eh = (ethernet_header *)pkt_data;
    // 解析目标MAC地址
    p_ethernet.dmac = QString("%1:%2:%3:%4:%5:%6")
           .arg(eh->daddr.byte1, 2, 16, QChar('0'))
           .arg(eh->daddr.byte2, 2, 16, QChar('0'))
           .arg(eh->daddr.byte3, 2, 16, QChar('0'))
           .arg(eh->daddr.byte4, 2, 16, QChar('0'))
           .arg(eh->daddr.byte5, 2, 16, QChar('0'))
           .arg(eh->daddr.byte6, 2, 16, QChar('0'));

   // 解析源MAC地址
   p_ethernet.smac = QString("%1:%2:%3:%4:%5:%6")
           .arg(eh->saddr.byte1, 2, 16, QChar('0'))
           .arg(eh->saddr.byte1, 2, 16, QChar('0'))
           .arg(eh->saddr.byte1, 2, 16, QChar('0'))
           .arg(eh->saddr.byte1, 2, 16, QChar('0'))
           .arg(eh->saddr.byte1, 2, 16, QChar('0'))
           .arg(eh->saddr.byte1, 2, 16, QChar('0'));
    //  将网络字节序转换成主机字节序，获取网络层协议类型
    u_short eh_type = ntohs(eh->type);
    /*处理网络层*/
    if(eh_type == IP){
        p_ethernet.protocol = "IP";
       // 获取IP头部信息
       ip_header *iph;
       iph = (ip_header *)(pkt_data + sizeof(ethernet_header));
       // IP版本
       p_ip.ver = QString::number(iph->ver);
       // 首部长度
       p_ip.ihl = QString::number(iph->ihl);
       // 服务类型(Type of service)
       p_ip.tos = QString("%1").arg(iph->tos,2,16,QChar('0')).toUpper();
       // 总长(Total length)
       p_ip.tlen = QString::number(ntohs(iph->tlen));
       // 标识(Identification)
       p_ip.identification = QString("%1").arg(ntohs(iph->identification),4,16,QChar('0')).toUpper();
       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
       //u_short p_ip_flags_fo = iph->flags_fo;
       p_ip.flags_fo = QString::number(iph->flags_fo);
       // 生存时间(Time to live)
       p_ip.ttl = QString::number(iph->ttl);
       // 协议(Protocol)
       switch (iph->type){
        case 1 : p_ip.type = "ICMP" ; break;
        case 2 : p_ip.type = "IGMP" ; break;
        case 6 : p_ip.type = "TCP" ; break;
        case 17 : p_ip.type = "UDP" ; break;
        case 46 : p_ip.type = "RSVP" ; break;
        case 47 : p_ip.type = "GRE" ; break;
        case 50: p_ip.type = "ESP" ; break;
        case 51 : p_ip.type = "AH " ; break;
        case 58 : p_ip.type = "ICMPv6" ; break;
        case 89 : p_ip.type = "OSPF" ; break;
        case 132: p_ip.type = "SCTP" ; break;
        default: p_ip.type = "不常用协议";
       }

       // 首部校验和(Header checksum)
       p_ip.crc = QString("%1").arg(ntohs(iph->crc),4,16,QChar('0')).toUpper();;
       // 源地址(Source address)
       p_ip.saddr = QString("%1.%2.%3.%4")
               .arg(iph->saddr.byte1)
               .arg(iph->saddr.byte2)
               .arg(iph->saddr.byte3)
               .arg(iph->saddr.byte4);
       // 目的地址(Destination address)
       p_ip.daddr = QString("%1.%2.%3.%4")
               .arg(iph->daddr.byte1)
               .arg(iph->daddr.byte2)
               .arg(iph->daddr.byte3)
               .arg(iph->daddr.byte4);
       // 选项与填充(Option + Padding)
       //u_int   p_ip_op_pad = iph->op_pad;
       p_ip.op_pad = QString::number(iph->op_pad);
    }
    emit sniffer->setTableData(p_ethernet,p_ip,p_len,p_time);

}

Sniffer::Sniffer(QObject *parent,QMainWindow* win)
    : QObject{parent} , m_win(nullptr)
{

}
// 设置网卡设备
void Sniffer::setSDev(QString data){
    sdev = data;
}

// 添加过滤规则
void Sniffer::addFilter(QString data){
    filterList.insert(data);
}
// 获取过滤规则
std::set<QString> Sniffer::getFilter(){
    return filterList;
};
// 清空过滤规则
void Sniffer::clearFilter(){
    filterList.clear();
};

// 开始捕获
void Sniffer::startCapture()
{
    if(sdev==""){
        emit warning("请先绑定网卡设备！");
        return;
    }
    else{
        const char* dname = sdev.toUtf8();
        char errbuf[PCAP_ERRBUF_SIZE];	// 出错信息
        // 打开一个网络接口
        descr = pcap_open_live(dname, BUFSIZ, 0, -1, errbuf);
        if (descr == NULL) {
            emit error("系统找不到指定的设备!");
            return;
        }
        // 判断数据链路层类型是否为以太网
        if (pcap_datalink(descr) != DLT_EN10MB) {
            emit error("设备不是以太网设备！");
            pcap_close(descr);
            return;
        }
//        delete[] dname;
        // 创建过滤规则
        QString filters = "";
        for (auto it = filterList.begin(); it != filterList.end(); ++it) {
            filters = filters + *it;
            if (*it!=*(filterList.rbegin())){
                filters = filters + " or ";
            }
        }
        const char* filter_exp = filters.toStdString().c_str();
        struct bpf_program fp;
        bpf_u_int32 net;
        if (pcap_compile(descr, &fp, filter_exp , 0, net) == -1) {

            emit error(pcap_geterr(descr));
            pcap_close(descr);
            return;
        }
        if (pcap_setfilter(descr, &fp) == -1)
        {
            emit error(pcap_geterr(descr));
            return;
        }
        pcap_loop(descr, -1 ,packet_handler, reinterpret_cast<u_char*>(this));

        // 捕获循环结束，关闭适配器
        pcap_close(descr);
    }

}

// 结束捕获
void Sniffer::stopCapture(){
    qDebug()<< descr;
    pcap_breakloop(descr);
}



/*********sniffer线程***************/
MyThread::MyThread(QObject* parent)
    : QThread(parent)
{
    m_sniffer = new Sniffer();

}

void MyThread::run()
{
    m_sniffer->startCapture();
}
