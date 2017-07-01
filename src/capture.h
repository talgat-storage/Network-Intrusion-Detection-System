#ifndef CAPTURE_H
#define CAPTURE_H

#include "libraries.h"

pcap_t *pcap_init (void);
int pcap_datalink_offset (pcap_t *);

#endif
