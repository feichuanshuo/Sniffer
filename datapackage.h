
#ifndef DATAPACKET_H
#define DATAPACKET_H

#include <QString>
#include "pcap.h"


class DataPackage
{
private:
    u_int data_length; // 数据包长度
    QString time; // 数据包时间
    QString info;      // 数据包简介信息
    u_short packageNLType;   // 数据包类型

public:
    const u_char *pkt_content; // 数据包数据指针
public:
    DataPackage();
    ~DataPackage()=default;

    /****** 设置包数据 ******/
    void setDataLength(unsigned int length);                    // 设置包长度
    void setTime(QString timeStamp);                            // 设置时间
    void setPackageNLType(u_short type);                        // 设置包类型
    void setPackagePointer(const u_char *pkt_content,int size); // 设置包数据
    void setPackageInfo(QString info);                          // 设置包简介信息

    /****** 获取包数据 ******/
    int getDataLength();                  // 获取包长度
    QString getTime();                        // 获取包时间
    u_short getPackageNLType();                 // 获取包类型
    QString getInfo();                        // 获取包简介信息
    QString getSource();                      // 获取包的源地址
    QString getDestination();                 // 获取包的目的地址


    /****** 获取MAC数据帧信息 ******/
    QString getDesMacAddr();                  // 获取目的MAC地址
    QString getSrcMacAddr();                  // 获取源MAC地址
    QString getMacType();                     // 获取上层协议类型

    /****** 获取IP数据包信息 ******/
    QString getDesIpAddr();                   // 获取目的IP
    QString getSrcIpAddr();                   // 获取源IP
    QString getIpVersion();                   // 获取IP版本
    QString getIpHeaderLength();              // 获取首部长度
    QString getIpTos();                       // 获取服务类型
    QString getIpTotalLength();               // 获取总长
    QString getIpIdentification();            // 获取标识信息
    QString getIpFlag();                      // 获取标志位
    QString getIpReservedBit();               // 获取保留位
    QString getIpDF();                        // 是否分片
    QString getIpMF();                        // 是否有后续分片
    QString getIpFragmentOffset();            // 获取片偏移
    QString getIpTTL();                       // 获取生存时间
    QString getIpProtocol();                  // 获取上层协议类型
    QString getIpCheckSum();                  // 获取首部校验和

    /****** 获取ARP数据包信息 ******/
    QString getArpHardwareType();             // 硬件类型：指明了发送方想知道的硬件接口类型，以太网的值为1
    QString getArpProtocolType();             // 协议类型：指明了发送方提供的高层协议类型，IP为0800（16进制）
    QString getArpHardwareLength();           // 硬件长度，8位字段，定义对应物理地址长度，以太网中这个值为6
    QString getArpProtocolLength();           // 协议长度，8位字段，定义以字节为单位的逻辑地址长度，对IPV4协议这个值为4
    QString getArpOperationCode();            // 操作类型：用来表示这个报文的类型，ARP请求为1，ARP响应为2，RARP请求为3，RARP响应为4
    QString getArpSourceEtherAddr();          // 发送端硬件地址，可变长度字段，对以太网这个字段是6字节长
    QString getArpSourceIpAddr();             // 发送端协议地址，可变长度字段，对IP协议，这个字段是4字节长
    QString getArpDestinationEtherAddr();     // 接受端硬件地址
    QString getArpDestinationIpAddr();        // 接受协议地址

    /****** 获取ICMP数据包信息 ******/
    QString getIcmpType();                    // 获取ICMP类型
    QString getIcmpCode();                    // 获取ICMP CODE
    QString getIcmpCheckSum();                // 获取ICMP校验和
    QString getIcmpIdentification();          // 获取ICMP标识
    QString getIcmpSequeue();                 // 获取ICMP序列号
    QString getIcmpData(int size);            // 获取ICMP数据

    /****** 获取TCP数据包信息 ******/
    QString getTcpSourcePort();               // get tcp source port
    QString getTcpDestinationPort();          // get tcp destination port
    QString getTcpSequence();                 // get tcp sequence
    QString getTcpAcknowledgment();           // get acknowlegment
    QString getTcpHeaderLength();             // get tcp head length
    QString getTcpRawHeaderLength();          // get tcp raw head length [default is 0x05]
    QString getTcpFlags();                    // get tcp flags
    QString getTcpPSH();                      // PSH flag
    QString getTcpACK();                      // ACK flag
    QString getTcpSYN();                      // SYN flag
    QString getTcpURG();                      // URG flag
    QString getTcpFIN();                      // FIN flag
    QString getTcpRST();                      // RST flag
    QString getTcpWindowSize();               // get tcp window size
    QString getTcpCheckSum();                 // get tcp checksum
    QString getTcpUrgentPointer();            // get tcp urgent pointer
    QString getTcpOperationKind(int kind);    // get tcp option kind
    int getTcpOperationRawKind(int offset);   // get tcp raw option kind

    /*
     * tcp optional parts
    */
    bool getTcpOperationMSS(int offset,u_short& mss);                          // kind = 2
    bool getTcpOperationWSOPT(int offset,u_char&shit);                         // kind = 3
    bool getTcpOperationSACKP(int offset);                                     // kind = 4
    bool getTcpOperationSACK(int offset,u_char&length,QVector<u_int>&edge);    // kind = 5
    bool getTcpOperationTSPOT(int offset,u_int& value,u_int&reply);            // kind = 8

    /****** 获取UDP数据包信息 ******/
    QString getUdpSourcePort();               // get udp source port
    QString getUdpDestinationPort();          // get udp destination port
    QString getUdpDataLength();               // get udp data length
    QString getUdpCheckSum();                 // get udp checksum

};

#endif // DATAPACKET_H
