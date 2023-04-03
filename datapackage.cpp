
#include "dataPackage.h"
#include <QMetaType>
#include <winsock2.h>
#include <QVector>
#include "head.h"

DataPackage::DataPackage()
{
    qRegisterMetaType<DataPackage>("DataPackage");
    this->time = "";
    this->data_length = 0;
    this->packageNLType = 0;
    this->pkt_content = nullptr;
}
/****** 设置基本信息 ******/
void DataPackage::setDataLength(unsigned int length){
    this->data_length = length;
}

void DataPackage::setTime(QString time){
    this->time = time;
}

void DataPackage::setPackageNLType(u_short type){
    this->packageNLType = type;
}

void DataPackage::setPackagePointer(const u_char *pkt_content,int size){
    this->pkt_content = (u_char*)malloc(size);
    if(this->pkt_content != nullptr)
        memcpy((char*)(this->pkt_content),pkt_content,size);
    else this->pkt_content = nullptr;
    ethernet_header* eh;
    eh = (ethernet_header*)pkt_content;
    setPackageNLType( ntohs(eh->type));
}
void DataPackage::setPackageInfo(QString info){
    this->info = info;
}
/****** 获取基本信息 ******/
QString DataPackage::getTime(){
    return this->time;
}

int DataPackage::getDataLength(){
    return this->data_length;
}

u_short DataPackage::getPackageNLType(){
    return packageNLType;
}

QString DataPackage::getInfo(){
    return info;
}

QString DataPackage::getSource(){
    if(this->packageNLType == ARP)
        return getArpSourceIpAddr();
    else return getSrcIpAddr();
}
QString DataPackage::getDestination(){
    if(this->packageNLType == ARP)
        return getArpDestinationIpAddr();
    else return getDesIpAddr();
}

/* Ether */
/********************** get destination ethenet address **********************/
QString DataPackage::getDesMacAddr(){
    ethernet_header* eh;
    eh = (ethernet_header*)pkt_content;
    if(eh){
        QString dmac = QString("%1:%2:%3:%4:%5:%6")
                                 .arg(eh->daddr.byte1, 2, 16, QChar('0'))
                                 .arg(eh->daddr.byte2, 2, 16, QChar('0'))
                                 .arg(eh->daddr.byte3, 2, 16, QChar('0'))
                                 .arg(eh->daddr.byte4, 2, 16, QChar('0'))
                                 .arg(eh->daddr.byte5, 2, 16, QChar('0'))
                                 .arg(eh->daddr.byte6, 2, 16, QChar('0'));
        if(dmac == "FF:FF:FF:FF:FF:FF") return "FF:FF:FF:FF:FF:FF(Broadcast)";
        else
            return dmac;
    }
    return "";
}
/********************** get source ethenet address **********************/
QString DataPackage::getSrcMacAddr(){
    ethernet_header* eh;
    eh = (ethernet_header*)pkt_content;
    if(eh){
        QString smac = QString("%1:%2:%3:%4:%5:%6")
                                 .arg(eh->saddr.byte1, 2, 16, QChar('0'))
                                 .arg(eh->saddr.byte1, 2, 16, QChar('0'))
                                 .arg(eh->saddr.byte1, 2, 16, QChar('0'))
                                 .arg(eh->saddr.byte1, 2, 16, QChar('0'))
                                 .arg(eh->saddr.byte1, 2, 16, QChar('0'))
                                 .arg(eh->saddr.byte1, 2, 16, QChar('0'));
        if(smac == "FF:FF:FF:FF:FF:FF") return "FF:FF:FF:FF:FF:FF(Broadcast)";
        else return smac;
    }
    return "";
}
/********************** get ethenet type **********************/
QString DataPackage::getMacType(){
    ethernet_header* eh;
    eh = (ethernet_header*)pkt_content;
    u_short ethernet_type = ntohs(eh->type);
    switch (ethernet_type) {
    case IP: return "IPv4(0x800)";
    case ARP:return "ARP(0x0806)";
    default:{
        return "";
    }
    }
}

/* ip */
/********************** get destination ip address **********************/
QString DataPackage::getDesIpAddr(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    QString daddr = QString("%1.%2.%3.%4")
                        .arg(iph->daddr.byte1)
                        .arg(iph->daddr.byte2)
                        .arg(iph->daddr.byte3)
                        .arg(iph->daddr.byte4);
    return daddr;
}
/********************** get source ip address **********************/
QString DataPackage::getSrcIpAddr(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    QString saddr = QString("%1.%2.%3.%4")
                        .arg(iph->saddr.byte1)
                        .arg(iph->saddr.byte2)
                        .arg(iph->saddr.byte3)
                        .arg(iph->saddr.byte4);
    return saddr;
}
/********************** get ip version **********************/
QString DataPackage::getIpVersion(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    return QString::number(iph->ver);;
}
/********************** get ip header length **********************/
QString DataPackage::getIpHeaderLength(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    QString res = "";
    int length = iph->ihl;
    if(length == 5) res = "20 bytes (5)";
    else res = QString::number(length*5) + "bytes (" + QString::number(length) + ")";
    return res;
}

/********************** get ip TOS **********************/
QString DataPackage::getIpTos(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    return "0x" + QString("%1").arg(iph->tos,2,16,QChar('0')).toUpper();
}
/********************** get ip total length **********************/
QString DataPackage::getIpTotalLength(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    return QString::number(ntohs(iph->tlen));
}
/********************** get ip indentification **********************/
QString DataPackage::getIpIdentification(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    return "0x" +QString("%1").arg(ntohs(iph->identification),4,16,QChar('0')).toUpper();
}
/********************** get ip flag **********************/
QString DataPackage::getIpFlag(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    return "0x" +QString("%1").arg(ntohs( iph->flags_fo ) & 0xe000 / 0x2000,2,16,QChar('0')).toUpper();
}
/********************** get ip reverse bit **********************/
QString DataPackage::getIpReservedBit(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    int bit = (ntohs(iph->flags_fo) & 0x8000) >> 15;
    return QString::number(bit);
}
/********************** get ip DF flag[Don't Fragment] **********************/
QString DataPackage::getIpDF(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    return QString::number((ntohs(iph->flags_fo) & 0x4000) >> 14);
}
/********************** get ip MF flag[More Fragment] **********************/
QString DataPackage::getIpMF(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    return QString::number((ntohs(iph->flags_fo) & 0x2000) >> 13);
}
/********************** get ip Fragment Offset **********************/
QString DataPackage::getIpFragmentOffset(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    return QString::number(ntohs(iph->flags_fo) & 0x1FFF);
}
/********************** get ip TTL **********************/
QString DataPackage::getIpTTL(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    return QString::number(iph->ttl);
}
/********************** get ip protocol **********************/
QString DataPackage::getIpProtocol(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    switch (iph->type){
    case 1 : return "ICMP";
    case 2 : return "IGMP" ;
    case 6 : return "TCP" ;
    case 17 : return "UDP" ;
    case 46 : return "RSVP" ;
    case 47 : return "GRE" ;
    case 50: return "ESP" ;
    case 51 : return "AH " ;
    case 58 : return "ICMPv6" ;
    case 89 : return "OSPF" ;
    case 132: return "SCTP" ;
    default: return "不常用协议";
    }
}
/********************** get ip checksum **********************/
QString DataPackage::getIpCheckSum(){
    ip_header *iph;
    iph = (ip_header *)(pkt_content + sizeof(ethernet_header));
    return "0x" +QString("%1").arg(ntohs(iph->crc),4,16,QChar('0')).toUpper();
}

/* arp */
QString DataPackage::getArpHardwareType(){
    arp_header *arph;
    arph = (arp_header *)(pkt_content + sizeof(ethernet_header));
    int type = ntohs(arph->arp_hdr);
    QString res = "";
    if(type == 0x0001) res = "Ethernet(1)";
    else res = QString::number(type);
    return res;
}
/********************** get arp protocol type **********************/
QString DataPackage::getArpProtocolType(){
    arp_header *arph;
    arph = (arp_header *)(pkt_content + sizeof(ethernet_header));
    int type = ntohs(arph->arp_pro);
    QString res = "";
    if(type == IP) res = "IPv4(0x0800)";
    else res = QString::number(type);
    return res;
}
/********************** get hardware length **********************/
QString DataPackage::getArpHardwareLength(){
    arp_header *arph;
    arph = (arp_header *)(pkt_content + sizeof(ethernet_header));
    return QString::number(arph->arp_hln);
}
/********************** get arp protocol length **********************/
QString DataPackage::getArpProtocolLength(){
    arp_header *arph;
    arph = (arp_header *)(pkt_content + sizeof(ethernet_header));
    return QString::number(arph->apr_pln);
}
/********************** get arp operator code **********************/
QString DataPackage::getArpOperationCode(){
    arp_header *arph;
    arph = (arp_header *)(pkt_content + sizeof(ethernet_header));
    int code = ntohs(arph->arp_opt);
    QString res = "";
    if(code == 1) res  = "request(1)";
    else if(code == 2) res = "reply(2)";
    return res;
}
/********************** get arp source ethernet address **********************/
QString DataPackage::getArpSourceEtherAddr(){
    arp_header *arph;
    arph = (arp_header *)(pkt_content + sizeof(ethernet_header));
    if(arph){
        return QString("%1:%2:%3:%4:%5:%6")
                    .arg(arph->arp_smac.byte1, 2, 16, QChar('0'))
                    .arg(arph->arp_smac.byte2, 2, 16, QChar('0'))
                    .arg(arph->arp_smac.byte3, 2, 16, QChar('0'))
                    .arg(arph->arp_smac.byte4, 2, 16, QChar('0'))
                    .arg(arph->arp_smac.byte5, 2, 16, QChar('0'))
                    .arg(arph->arp_smac.byte6, 2, 16, QChar('0'));
    }
    return "";
}
/********************** get arp destination ethernet address **********************/
QString DataPackage::getArpDestinationEtherAddr(){
    arp_header *arph;
    arph = (arp_header *)(pkt_content + sizeof(ethernet_header));
    u_char*addr;
    if(arph){
        return QString("%1:%2:%3:%4:%5:%6")
            .arg(arph->arp_dmac.byte1, 2, 16, QChar('0'))
            .arg(arph->arp_dmac.byte2, 2, 16, QChar('0'))
            .arg(arph->arp_dmac.byte3, 2, 16, QChar('0'))
            .arg(arph->arp_dmac.byte4, 2, 16, QChar('0'))
            .arg(arph->arp_dmac.byte5, 2, 16, QChar('0'))
            .arg(arph->arp_dmac.byte6, 2, 16, QChar('0'));
    }
    return "";
}
/********************** get arp source ip address **********************/
QString DataPackage::getArpSourceIpAddr(){
    arp_header *arph;
    arph = (arp_header *)(pkt_content + sizeof(ethernet_header));
    if(arph){
        return QString("%1.%2.%3.%4")
            .arg(arph->arp_sip.byte1)
            .arg(arph->arp_sip.byte2)
            .arg(arph->arp_sip.byte3)
            .arg(arph->arp_sip.byte4);
    }
    return "";
}
/********************** get arp destination ip address **********************/
QString DataPackage::getArpDestinationIpAddr(){
    arp_header *arph;
    arph = (arp_header *)(pkt_content + sizeof(ethernet_header));
    if(arph){
        return QString("%1.%2.%3.%4")
            .arg(arph->arp_dip.byte1)
            .arg(arph->arp_dip.byte2)
            .arg(arph->arp_dip.byte3)
            .arg(arph->arp_dip.byte4);
    }
    return "";
}

/* icmp */
/********************** get icmp type **********************/
QString DataPackage::getIcmpType(){
    icmp_header*icmp;
    icmp = (icmp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(ntohs(icmp->type));
}
/********************** get icmp code **********************/
QString DataPackage::getIcmpCode(){
    icmp_header*icmp;
    icmp = (icmp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(ntohs(icmp->code));

}
/********************** get icmp checksum **********************/
QString DataPackage::getIcmpCheckSum(){
    icmp_header*icmp;
    icmp = (icmp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(ntohs(icmp->checksum),16);
}
/********************** get icmp identification **********************/
QString DataPackage::getIcmpIdentification(){
    icmp_header*icmp;
    icmp = (icmp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(ntohs(icmp->identification));
}
/********************** get icmp sequence **********************/
QString DataPackage::getIcmpSequeue(){
    icmp_header*icmp;
    icmp = (icmp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(ntohs(icmp->sequence));
}
/********************** get icmp data **********************/
QString DataPackage::getIcmpData(int size){
    char*icmp;
    icmp = (char*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header) + 8);
    QString res= "";
    for(int i = 0;i < size;i++){
        res += (*icmp);
        icmp++;
    }
    return res;
}

/* tcp */
/********************** get tcp source port **********************/
QString DataPackage::getTcpSourcePort(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    int port = ntohs(tcp->sport);
    if(port == 443) return "https(443)";
    return QString::number(port);
}
/********************** get tcp destination port **********************/
QString DataPackage::getTcpDestinationPort(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    int port = ntohs(tcp->dport);
    if(port == 443) return "https(443)";
    return QString::number(port);
}
/********************** get tcp sequence **********************/
QString DataPackage::getTcpSequence(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(ntohl(tcp->seq));
}
/********************** get tcp acknowledgment **********************/
QString DataPackage::getTcpAcknowledgment(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(ntohl(tcp->ack));
}
/********************** get tcp header length **********************/
QString DataPackage::getTcpHeaderLength(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    int length = (tcp->header_length >> 4);
    if(length == 5) return "20 bytes (5)";
    else return QString::number(length*4) + " bytes (" + QString::number(length) + ")";
}
QString DataPackage::getTcpRawHeaderLength(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(tcp->header_length >> 4);
}

/********************** get tcp flags **********************/
QString DataPackage::getTcpFlags(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(tcp->flags,16);
}

/********************** get tcp PSH **********************/
QString DataPackage::getTcpPSH(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(((tcp->flags) & 0x08) >> 3);
}
/********************** get tcp ACK **********************/
QString DataPackage::getTcpACK(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(((tcp->flags) & 0x10) >> 4);
}
/********************** get tcp SYN **********************/
QString DataPackage::getTcpSYN(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(((tcp->flags) & 0x02) >> 1);
}
/********************** get tcp UGR **********************/
QString DataPackage::getTcpURG(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(((tcp->flags) & 0x20) >> 5);
}
/********************** get tcp FIN **********************/
QString DataPackage::getTcpFIN(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number((tcp->flags) & 0x01);
}
/********************** get tcp RST **********************/
QString DataPackage::getTcpRST(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(((tcp->flags) & 0x04) >> 2);
}
/********************** get tcp window size **********************/
QString DataPackage::getTcpWindowSize(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(ntohs(tcp->window_size));
}
/********************** get tcp checksum **********************/
QString DataPackage::getTcpCheckSum(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(ntohs(tcp->crc),16);
}
/********************** get tcp urgent pointer **********************/
QString DataPackage::getTcpUrgentPointer(){
    tcp_header* tcp;
    tcp = (tcp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(ntohs(tcp->urp));
}

QString DataPackage::getTcpOperationKind(int kind){
    switch(kind){
    case 0:return "EOL";              // end of list
    case 1:return "NOP";              // no operation
    case 2:return "MSS";              // max segment
    case 3:return "WSOPT";            // window scaling factor
    case 4:return "SACK-Premitted";   // support SACK
    case 5:return "SACK";             // SACK Block
    case 8:return "TSPOT";            // Timestamps
    case 19:return "TCP-MD5";         // MD5
    case 28:return "UTP";             // User Timeout
    case 29:return "TCP-AO";          // authenticated
    }
}

int DataPackage::getTcpOperationRawKind(int offset){
    u_char*tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    return *tcp;
}
bool DataPackage::getTcpOperationSACK(int offset,u_char&length,QVector<u_int>&edge){
    u_char*tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 5){
        tcp++;
        length = *tcp;
        tcp++;
        u_int* pointer = (u_int*)tcp;
        for(int i = 0;i < (length - 2)/4;i++){
            u_int temp = htonl(*pointer);
            edge.push_back(temp);
            pointer++;
        }
        return true;
    }else return false;
}
bool DataPackage::getTcpOperationMSS(int offset, u_short &mss){
    u_char *tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 2){
        tcp++;
        if(*tcp == 4){
            tcp++;
            u_short* Mss = (u_short*)tcp;
            mss = ntohs(*Mss);
            return true;
        }
        else return false;
    }
    return false;
}
bool DataPackage::getTcpOperationSACKP(int offset){
    u_char *tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 4)
        return true;
    else return false;
}
bool DataPackage::getTcpOperationWSOPT(int offset, u_char &shit){
    u_char *tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 3){
        tcp++;
        if(*tcp == 3){
            tcp++;
            shit = *tcp;
        }else return false;
    }else return false;
}

bool DataPackage::getTcpOperationTSPOT(int offset, u_int &value, u_int &reply){
    u_char *tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 8){
        tcp++;
        if(*tcp == 10){
            tcp++;
            u_int *pointer = (u_int*)(tcp);
            value = ntohl(*pointer);
            pointer++;
            reply = ntohl(*pointer);
            return true;
        }else return false;
    }else return false;
}
/* udp */
/********************** get udp source port **********************/
QString DataPackage::getUdpSourcePort(){
    udp_header* udp;
    udp = (udp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    int port = ntohs(udp->sport);
    if(port == 53) return "domain(53)";
    else return QString::number(port);
}
/********************** get udp destination port **********************/
QString DataPackage::getUdpDestinationPort(){
    udp_header* udp;
    udp = (udp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    int port = ntohs(udp->dport);
    if(port == 53) return "domain(53)";
    else return QString::number(port);
}
/********************** get udp data length **********************/
QString DataPackage::getUdpDataLength(){
    udp_header* udp;
    udp = (udp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return QString::number(ntohs(udp->len));

}
/********************** get udp checksum **********************/
QString DataPackage::getUdpCheckSum(){
    udp_header* udp;
    udp = (udp_header*)(pkt_content + sizeof(ethernet_header) + sizeof(ip_header));
    return "0x" + QString::number(ntohs(udp->crc),16);
}
