#include "analysis.h"
#include "dispatch.h"
#include "sniff.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <string.h>

#define byte unsigned char

struct ARPpacket {
	struct	arphdr ea_hdr;	
	uint8_t arp_sha[ETH_ALEN];
	uint8_t arp_spa[4];	
	uint8_t arp_tha[ETH_ALEN];
	uint8_t arp_tpa[4];
};

void addIpToTheList(struct list *linkedList, struct iphdr* iplayer){
  if(linkedList->head == NULL){
    struct listelement *newElement = (struct listelement *) malloc(sizeof(struct listelement));
    newElement->val = iplayer->saddr;
    newElement->next = NULL; 
    linkedList->head = newElement;
    printf("ip: %lu", linkedList->head->val);
    return;
  }
  else{
    struct listelement *temporaryElement = linkedList->head;
    while(1){
      if(temporaryElement->next != NULL){
        temporaryElement = temporaryElement->next;
        if(temporaryElement->val == iplayer->saddr){
          // printf("EQUAL %lu and %lu", temporaryElement->val && iplayer->saddr);
          return;
        }
      }
      else{
        if(temporaryElement->val == iplayer->saddr){
          // printf("EQUAL %lu and %lu", temporaryElement->val && iplayer->saddr);
          return;
        }
        struct listelement *newElement = (struct listelement *) malloc(sizeof(struct listelement));
        newElement->val = iplayer->saddr;
        newElement->next = NULL;
        temporaryElement->next=newElement;
        // printf("NEW %lu", newElement->val);
        return;
      }     
    }
  }
}

struct counting *analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose,
             struct list *linkedList
             ){
  printf("DOES IT EVEN GET HERE\n");
  //define a new counting variable
  counting *tempCounters = malloc(sizeof(struct counting));
  tempCounters->number_of_arp_attacks = 0;
  tempCounters->number_of_syn_attacks = 0;
  tempCounters->number_of_syn_IPS = 0;
  tempCounters->number_of_blacklisted_IDs=0;

  struct ether_header *linklayer = (struct ether_header *) packet;
  struct iphdr *iplayer = (struct iphdr *) (packet+14);
  struct tcphdr *tcplayer = (struct tcphdr *) (packet+14 + iplayer->ihl*4);

  if(tcplayer->syn){
    if(!(tcplayer->urg && tcplayer->ack && tcplayer->psh && tcplayer->rst && tcplayer->fin)){
        printf("SYN\n");
        // printf("packet ip: %lu", iplayer->saddr);
        tempCounters->number_of_syn_attacks= tempCounters->number_of_syn_attacks+1;
        // printf("linked: %d", linkedList->head);
        addIpToTheList(linkedList, iplayer);
        // printf("before: %d\n", tempCounters->number_of_syn_attacks);
    }
  }



  if(ntohs(linklayer->ether_type) == ETHERTYPE_IP){
      const unsigned char *ip = packet + ETH_HLEN + (4*iplayer->ihl);
      const char *http = (char *) (ip+(4*tcplayer->doff));
      int i;

      int x = header->len - ((sizeof(struct ether_header) + 4*(iplayer->ihl)+4*(tcplayer->doff)));
     
      if(x > 0){
      unsigned char *new_string = malloc(sizeof(char)*(x+1));
      if((ntohs(tcplayer->dest) == 80)){
        // printf("destination: %d\n",ntohs(tcplayer->dest));
        for (i = 0; i < x; i++)
        {
          char c = (char) http[i];
          new_string[i] = c;
        }
        new_string[x] = '\0';
      }    
      if (strstr(new_string, "www.google.co.uk") && (ntohs(tcplayer->dest) == 80)){
        printf("BEFORE BL: %d\n", tempCounters->number_of_blacklisted_IDs); 
        tempCounters->number_of_blacklisted_IDs = tempCounters->number_of_blacklisted_IDs+1;
        printf("AFTER BL: %d\n", tempCounters->number_of_blacklisted_IDs); 
      }
    }
  }

  if(ntohs(linklayer->ether_type) == ETHERTYPE_ARP){
    const unsigned char *linklayerStripPackets = packet + ETH_HLEN;
    struct ARPpacket *arp_Packet = (struct ARPpacket *) linklayerStripPackets;
    struct arphdr *arp_Header = (struct arphdr *) &arp_Packet->ea_hdr;


    printf("%d <--> %d\n", ntohs(arp_Header->ar_op), ARPOP_REPLY);

    if(ntohs(arp_Header->ar_op) == ARPOP_REPLY){
      //increment arp counter here
      //Detect ARP poisoning attack
      printf("Arp before: %d\n", tempCounters->number_of_arp_attacks);
      tempCounters->number_of_arp_attacks=tempCounters->number_of_arp_attacks+1;
      printf("Arp after: %d\n", tempCounters->number_of_arp_attacks);
    }
  }    

  if(verbose == 1) printpacket(packet, 1000);
  
  return tempCounters;
}

//procedure to print out the raw packet and so check if data is correct
void printpacket(const unsigned char *packet, int length){
  int i, j;
  for (i = 0; i < length/4; i++) //number of lines
  {
    for (j = 0; j < 4; j++) //prevents more than 4 bytes on a line
    {
      printf("%02x  ", *(packet+(i*4)+j)); // print a byte
    }
    printf("\n"); //and a line
  }
}
