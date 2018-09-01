/*
 * pcap_dump.h
 *
 *  Created on: 2017/12/26
 *      Author: user1
 */

#ifndef PCAP_DUMP_H_
#define PCAP_DUMP_H_

#include    <stdint.h>
#include    <stdio.h>
#include    <stdlib.h>
#include    <unistd.h>
#include    <sys/time.h>
#include    <time.h>
#include    <string.h>

#define TCPDUMP_MAGIC 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define DLT_EN10MB 1

void pcap_init();
void pcap_write(u_char *data, int dsize);

#endif /* PCAP_DUMP_H_ */
