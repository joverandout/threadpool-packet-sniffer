#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>
#include "dispatch.h"
#include "sniff.h"
#include <stdlib.h>


struct counting *analyse(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose,
              struct list *list
              );

#endif
