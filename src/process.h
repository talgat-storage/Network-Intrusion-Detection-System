#ifndef PROCESS_H
#define PROCESS_H

#include "libraries.h"

void process_packet (u_char *, const struct pcap_pkthdr *, const u_char *);

#endif
