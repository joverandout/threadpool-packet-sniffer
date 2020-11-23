#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);

struct listelement{
  long val;
  struct listelement *next;
};

struct packetListElement{
  const unsigned char *packet;
  const struct pcap_pkthdr *header;
  struct packetListElement *next;
};

struct list{
  struct listelement *head;
};


struct packetList{
  struct packetListElement *head;
};

#endif
