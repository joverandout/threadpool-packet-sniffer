#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include "sniff.h"
#include "analysis.h"

struct counting *dispatch(struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose,
              struct list *list
              );


typedef struct counting{
    unsigned int number_of_syn_attacks;
    unsigned int number_of_arp_attacks;
    unsigned int number_of_blacklisted_IDs;
} counting;

#endif
