#include "sniffer.h"
#include <winsock2.h>
#include <iostream>


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    // 将用户参数转换为Sniffer对象
    Sniffer* sniffer = reinterpret_cast<Sniffer*>(param);

    DataPackage package;
    // 获取数据包的长度
    package.setDataLength(header->len);

    // 获取数据包的时间
    time_t t = header->ts.tv_sec;
    struct tm* local_time = localtime(&t);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y/%m/%d %H:%M:%S", local_time);
    int ms = header->ts.tv_usec;
    package.setTime(QString(time_str) + "." + QString::number(ms).leftJustified(6, '0'));

    // 解析包
    package.setPackagePointer(pkt_data,header->len);

    sniffer->packageList.append(package);

    emit sniffer->setTableData(package);

}

Sniffer::Sniffer()
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

void Sniffer::run()
{
    startCapture();
}
