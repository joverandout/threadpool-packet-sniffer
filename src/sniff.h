#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);

struct listelement{
  long val;
  struct listelement *next;
};

struct listElementPacket{
  struct pcap_pkthdr *header;
  const unsigned char *packet;
  struct listElementPacket *next;
};

struct list{
  struct listelement *head;
};

struct listOfPackets{
  struct headerListElement *head;
};



#endif
