/*
 * netutil.c
 *
 *  Created on: 2017/12/26
 *      Author: user1
 */



#include   "netutil.h"

PARAM Param={"enp0s3","lo",1, "192.168.0.28", "192.168.0.32", "D0:E1:40:98:DE:9A", "B8:27:EB:4A:A3:53"}; //JIKKA MBP-RASPPI
int EndFlag = 0;

int InitRawSocket(char *device,int promiscFlag,int ipOnly){
struct ifreq	ifreq;
struct sockaddr_ll	sa;
int	soc;

	if(ipOnly){
		if((soc=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP)))<0){
			DebugPerror("socket");
			return(-1);
		}
	}
	else{
		if((soc=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
			DebugPerror("socket");
			return(-1);
		}
	}

	memset(&ifreq,0,sizeof(struct ifreq));
	strncpy(ifreq.ifr_name,device,sizeof(ifreq.ifr_name)-1);
	if(ioctl(soc,SIOCGIFINDEX,&ifreq)<0){
		DebugPerror("ioctl");
		close(soc);
		return(-1);
	}
	sa.sll_family=PF_PACKET;
	if(ipOnly){
		sa.sll_protocol=htons(ETH_P_IP);
	}
	else{
		sa.sll_protocol=htons(ETH_P_ALL);
	}
	sa.sll_ifindex=ifreq.ifr_ifindex;
	if(bind(soc,(struct sockaddr *)&sa,sizeof(sa))<0){
		DebugPerror("bind");
		close(soc);
		return(-1);
	}

	if(promiscFlag){
		if(ioctl(soc,SIOCGIFFLAGS,&ifreq)<0){
			DebugPerror("ioctl");
			close(soc);
			return(-1);
		}
		ifreq.ifr_flags=ifreq.ifr_flags|IFF_PROMISC;
		if(ioctl(soc,SIOCSIFFLAGS,&ifreq)<0){
			DebugPerror("ioctl");
			close(soc);
			return(-1);
		}
	}

	return(soc);
}

char *my_ether_ntoa_r(u_char *hwaddr,char *buf,socklen_t size)
{
	snprintf(buf,size,"%02x:%02x:%02x:%02x:%02x:%02x",
		hwaddr[0],hwaddr[1],hwaddr[2],hwaddr[3],hwaddr[4],hwaddr[5]);

	return(buf);
}

int PrintEtherHeader(struct ether_header *eh,FILE *fp)
{
char	buf[80];

	fprintf(fp,"ether_header----------------------------\n");
	fprintf(fp,"ether_dhost=%s\n",my_ether_ntoa_r(eh->ether_dhost,buf,sizeof(buf)));
	fprintf(fp,"ether_shost=%s\n",my_ether_ntoa_r(eh->ether_shost,buf,sizeof(buf)));
	fprintf(fp,"ether_type=%02X",ntohs(eh->ether_type));
	switch(ntohs(eh->ether_type)){
		case	ETH_P_IP:
			fprintf(fp,"(IP)\n");
			break;
		case	ETH_P_IPV6:
			fprintf(fp,"(IPv6)\n");
			break;
		case	ETH_P_ARP:
			fprintf(fp,"(ARP)\n");
			break;
		default:
			fprintf(fp,"(unknown)\n");
			break;
	}

	return(0);
}

//-----

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

int str2macaddr(char *macstr, uint8_t macaddr[6]){
    int values[6];
    int i;

    if( 6 == sscanf( macstr, "%x:%x:%x:%x:%x:%x%c",
                    &values[0], &values[1], &values[2],
                    &values[3], &values[4], &values[5] ) )
    {
        /* convert to uint8_t */
        for( i = 0; i < 6; ++i )
            macaddr[i] = (uint8_t) values[i];
        return 1;
    }
    else
    {
        /* invalid mac */
        DebugPrintf("Invalid MAC format\n");
        return -1;
    }
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


//-----

//--------------


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
