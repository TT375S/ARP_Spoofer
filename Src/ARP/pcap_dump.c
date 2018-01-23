/*
 * pcap_dump.c
 *
 *  Created on: 2017/12/26
 *      Author: user1
 */

#include "pcap_dump.h"

//---pcapDump用----
char pcapDumpFileName[50] = "undefined";    //保存するpcapファイル名

//pcapファイルの先頭に書き込む
struct pcap_file_header{
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;   //タイムゾーン。GMT+1:00なら-3600になるらしいが、tcpdumpはここを0でダンプするのでそれに合わせる
    uint32_t sigfigs;
    uint32_t snaplen;   //最大パケット長。0xFF、つまり65535を指定するらしいが、このプログラムは2048までしか対応していない
    uint32_t linktype;
};



//pcapファイルを準備
void pcap_init(){
    //保存用ファイルネーム作成
    pcapDumpFileName[0] = '\0';
    strcat(pcapDumpFileName, "pcapDump-");
    time_t timer;
    timer = time(NULL);          /* 経過時間を取得 */
    char *stringTime;
    stringTime = ctime(&timer);
    
    stringTime[strlen(stringTime)] = '\0';  /* 改行削除  */
    strcat(pcapDumpFileName, stringTime);
    strcat(pcapDumpFileName, ".pcap");
    
    struct pcap_file_header *pfhdr =  (struct pcap_file_header *) malloc(sizeof(struct pcap_file_header));
    pfhdr->magic = TCPDUMP_MAGIC;
    pfhdr->version_major = PCAP_VERSION_MAJOR;
    pfhdr->version_minor = PCAP_VERSION_MINOR;
    pfhdr->thiszone = 0;   //前述の通り、tcpdumpに合わせて0にしてしまう
    pfhdr->snaplen = 65535;
    pfhdr->sigfigs = 0;
    pfhdr->linktype = DLT_EN10MB;

    FILE *fpw = fopen(pcapDumpFileName, "ab");
    fwrite(pfhdr, sizeof(struct pcap_file_header), 1, fpw);
    fclose(fpw);

    free(pfhdr);
}

//パケットの先頭に書き込む
struct pcap_pkthdr{
    //struct timeval ts; //この構造体を用いると、x86とx64の違いなのか、ひとつ64bitで保存されてしまいズレる
    uint32_t ts_sec;    //このように32bitで保存しとく
    uint32_t ts_usec;

    uint32_t caplen;
    uint32_t len;
};

//パケット追記する
void pcap_write(u_char *data, int dsize){
    struct pcap_pkthdr pkthdr;
    struct timeval ts;
    struct timezone tz;
    gettimeofday(&ts, &tz);

    pkthdr.ts_sec = (uint32_t)ts.tv_sec;
    pkthdr.ts_usec = (uint32_t)ts.tv_usec;
    pkthdr.caplen = dsize;
    pkthdr.len = dsize;

    FILE *fpw = fopen(pcapDumpFileName, "ab");
    fwrite(&pkthdr, sizeof(struct pcap_pkthdr), 1, fpw);
    fwrite(data, dsize, 1, fpw);
    fclose(fpw);
}

//---pcapDump用ここまで----
