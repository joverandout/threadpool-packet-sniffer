#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

#include "dispatch.h"

void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);

struct listelement;

struct listelement{
  long val;
  struct listelement *next;
};

struct Packet{
  struct pcap_pkthdr *header;
  const unsigned char *packet;
};

struct list{
  struct listelement *head;
};





#endif
