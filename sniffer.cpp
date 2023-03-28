
#include "sniffer.h"
#include "head.h"

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    /*处理链路层*/
    ethernet_header *eh;
    eh = (ethernet_header *)pkt_data;
    printf("源MAC地址：%x:%x:%x:%x:%x:%x",eh->saddr.byte1,eh->saddr.byte2,eh->saddr.byte3,eh->saddr.byte4,eh->saddr.byte5,eh->saddr.byte6);
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
// 开始捕获
void Sniffer::startCapture()
{
    qDebug()<<m_win;
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
        QString filter_exp = "";
        for (auto it = filterList.begin(); it != filterList.end(); ++it) {
            filter_exp = filter_exp + *it;
            if (*it!=*(filterList.rbegin())){
                filter_exp = filter_exp + " or ";
            }
        }
        struct bpf_program fp;
        bpf_u_int32 net;
        if (pcap_compile(descr, &fp, NULL , 0, net) == -1) {

            emit error(pcap_geterr(descr));
            pcap_close(descr);
            return;
        }
        if (pcap_setfilter(descr, &fp) == -1)
        {
            emit error(pcap_geterr(descr));
            return;
        }
        pcap_loop(descr, -1 , packet_handler, NULL);

        // 捕获循环结束，关闭适配器
        pcap_close(descr);
    }

}

// 结束捕获
void Sniffer::stopCapture(){
    qDebug()<< descr;
    pcap_breakloop(descr);
}

MyThread::MyThread(QObject* parent)
    : QThread(parent)
{
    m_sniffer = new Sniffer();

}

void MyThread::quit(){
    qDebug() << "MyThread is quitting...";
    m_sniffer->stopCapture();
    QThread::quit();
}

void MyThread::run()
{
    m_sniffer->startCapture();
}
