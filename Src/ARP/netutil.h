/*
 * netutil.h
 *
 *  Created on: 2017/12/26
 *      Author: user1
 */

#ifndef NETUTIL_H_
#define NETUTIL_H_

#include    <signal.h>
#include    <poll.h>
#include	<errno.h>
#include   <stdio.h>
#include   <stdlib.h>
#include   <stdarg.h>
#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<sys/ioctl.h>
#include	<arpa/inet.h>
#include	<sys/socket.h>
#include	<linux/if.h>
#include	<net/ethernet.h>
#include	<netpacket/packet.h>
#include	<netinet/if_ether.h>

char *my_ether_ntoa_r(u_char *hwaddr,char *buf,socklen_t size);
int PrintEtherHeader(struct ether_header *eh,FILE *fp);
int InitRawSocket(char *device,int promiscFlag,int ipOnly);

int	DebugPrintf(char *fmt,...);
int	DebugPerror(char *msg);

extern int	EndFlag;

typedef struct	{
    char	*Device1;
    int	DebugOut;

    char    *ip_A;
    char    *ip_B;
    char    *mac_A;
    char    *mac_B;
}PARAM;
//ここは手動で変える必要がある！
//PARAM	Param={"enp4s0","lo",1, "192.168.1.4", "192.168.1.110", "A4:5E:60:B7:29:C7", "B8:27:EB:4A:A3:53"};
//PARAM	Param={"enp4s0","lo",1, "192.168.1.7", "192.168.1.110", "08:00:27:CE:F8:80", "B8:27:EB:4A:A3:53"};
//PARAM	Param={"enp0s3","lo",1, "192.168.1.99", "192.168.1.110", "68:05:CA:06:F6:7B", "B8:27:EB:4A:A3:53"};
//PARAM	Param={"enp0s3","lo",0, "192.168.1.6", "192.168.1.99", "74:03:BD:7F:99:3E", "68:05:CA:06:F6:7B"};
PARAM   Param;

void setParam(char *devName, int isEnabledDebugOut, char *ip_addr_a, char *ip_addr_b, char *mac_addr_a, char *mac_addr_b);

typedef struct    {
    int    soc;
    u_char    hwaddr[6];
    struct in_addr    addr,subnet,netmask;
}DEVICE;

extern DEVICE	Device[2];

int str2macaddr(char *macstr, uint8_t macaddr[6]);

int AnalyzePacket(int deviceNo,u_char *data,int size);

int Bridge();

int DisableIpForward();

void EndSignal(int sig);

typedef struct  {
    struct ether_header      eh;
    struct ether_arp   arp;
}PACKET_ARP;

char *my_inet_ntoa_r(struct in_addr *addr,char *buf,socklen_t size);
int GetDeviceInfo(char *device,u_char hwaddr[6],struct in_addr *uaddr,struct in_addr *subnet,struct in_addr *mask);
int SendArpPacket(int isRequest, int soc,in_addr_t target_ip,u_char target_mac[6],in_addr_t my_ip,u_char my_mac[6]);

#endif /* NETUTIL_H_ */
