#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <signal.h>


#include "dispatch.h"
#include "sniff.h"

int synIpCount = 0;
struct list *linkedList;
struct counting *finalCount;
struct packetList *packets;
pthread_t threads[2];

int runthreads = 1;
int threadsExist = 0;

pthread_mutex_t packetLock = PTHREAD_MUTEX_INITIALIZER;


// Application main sniffing loop

void controlCHandler(int a){
  endThreads();
  if(linkedList->head!=NULL) recursivelyFreeMemory(linkedList->head);
  printf("\nall linked list data freed\n");
  recursivelyFreePackets(packets);
  printf("all packet data freed\n");
  printf("========================================================\n");
  finalPrint(synIpCount-1);
  printf("========================================================\n");
  exit(0);
}

void recursivelyFreeMemory(struct listelement *currentListElement){
  if(currentListElement->next != NULL){
    recursivelyFreeMemory(currentListElement->next);
  }
  //free(currentListElement);
  synIpCount++;
}

void recursivelyFreePackets(struct packetListElement *currentListElement){
  if(currentListElement->next != NULL){
    recursivelyFreeMemory(currentListElement->next);
  }
  synIpCount++;
  //free(currentListElement->packet);
  //free(currentListElement);
}

void finalPrint(int synIP){
  printf("Intrusion Detection Report:\n");
  printf("%d SYN packets detected from %d different IPs (syn attack)\n", finalCount->number_of_syn_attacks, synIP);
  printf("%d ARP responses (cache poisoning)\n", finalCount->number_of_arp_attacks);
  printf("%d URL Blacklist violations\n", finalCount->number_of_blacklisted_IDs);
  //free(finalCount);
}

void *threadFunction(){
  counting *localCountsPerThread = malloc(sizeof(struct counting));

	localCountsPerThread->number_of_arp_attacks = 0;
	localCountsPerThread->number_of_blacklisted_IDs = 0;
	localCountsPerThread->number_of_syn_attacks = 0;

  printf("THREAD\n");

  while(runthreads){
    pthread_mutex_lock(&packetLock);
    if(packets->head != NULL){
      printf("not null\n");
      struct packetListElement *temporaryThreadPacket = packets->head;
      packets->head = temporaryThreadPacket->next;

      struct counting *temp = dispatch(temporaryThreadPacket->header, temporaryThreadPacket->packet, 0, linkedList);

      pthread_mutex_unlock(&packetLock);

      localCountsPerThread->number_of_arp_attacks += temp->number_of_arp_attacks;
      localCountsPerThread->number_of_syn_attacks += temp->number_of_syn_attacks;
      printf("ARP: %d\n", temp->number_of_arp_attacks);
      localCountsPerThread->number_of_blacklisted_IDs += temp->number_of_blacklisted_IDs;

      // free((void *)temporaryThreadPacket->packet);
      // free(temp);
      // free(temporaryThreadPacket);
    }
    else{
      pthread_mutex_unlock(&packetLock);
    }
  }
  pthread_exit((void *) localCountsPerThread);
}

void endThreads(){
  runthreads=0;
  if(threadsExist){
    int i;
    for (i = 0; i < 2; i++)
    {
      void* ptr;
      pthread_join(threads[i], &ptr);

      printf("segfault here\n");
      struct counting *localCountsPerThread = (struct counting *)ptr;

      finalCount->number_of_arp_attacks += localCountsPerThread->number_of_arp_attacks;
      finalCount->number_of_syn_attacks += localCountsPerThread->number_of_syn_attacks;
      finalCount->number_of_blacklisted_IDs += localCountsPerThread->number_of_blacklisted_IDs;
    
      //free(ptr);
    }
  }
}

void initialiseStructs(){
  linkedList = malloc(sizeof(struct list));
  finalCount = malloc(sizeof(struct counting));
  packets = malloc(sizeof(struct packetList));
  packets->head = NULL;
  linkedList->head = NULL;  
}

void makeThreads(){
  int i;
  for (i = 0; i < 2; i++)
  {
    pthread_create(&threads[i], NULL, &threadFunction, NULL);
  }

  threadsExist = 1;
}

void sniff(char *interface, int verbose) {
  initialiseStructs();
  signal(SIGINT, &controlCHandler);
  // Open network interface for packet capture
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);
  if (pcap_handle == NULL) {
    // printf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    // printf("SUCCESS! Opened %s for capture\n", interface);
  }
  // Capture packets (very ugly code)
  struct pcap_pkthdr header;
  const unsigned char *packet;

  makeThreads();

  while (1) {
    // Capture a  packet
    packet = pcap_next(pcap_handle, &header);
    if (packet == NULL) {
      // pcap_next can return null if no packet is seen within a timeout
      if (verbose) {
        // printf("No packet received. %s\n", pcap_geterr(pcap_handle));
      }
      }
      else {
      // Optional: dump raw data to terminal
      if (verbose) {
        dump(packet, header.len);
      }

      //we have a packet now so add it to the packet queue

      struct packetListElement *toAdd = malloc(sizeof(struct packetListElement));
      toAdd->packet = packet;
      toAdd->header = &header;
      toAdd->next =NULL;


      pthread_mutex_lock(&packetLock);

      if(packets->head == NULL) //there is no packets in the queue
      {
        packets->head = toAdd;
        printf("added\n");
      }
      else{
        recursivelAddToQueue(packets->head, toAdd);
        printf("added recursively\n");
      }

      pthread_mutex_unlock(&packetLock);


      // Dispatch packet for processing
      
    }
  }
}





void recursivelAddToQueue(struct packetListElement *head, struct packetListElement *toAdd){
  if(head->next == NULL){
    head->next = toAdd;
  }
  else{
    recursivelAddToQueue(head->next, toAdd);
  }
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  // printf("\n\n === PACKET %ld HEADER ===", pcount);
  // printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    // printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      // printf(":");
    }
  }
  // printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    // printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      // printf(":");
    }
  }
  // printf("\nType: %hu\n", eth_header->ether_type);
  // printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        // printf("%02x ", payload[i]);
      } else {
        // printf ("   "); // Maintain padding for partial lines
      }
    }
    // printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        // printf("%c", byte);
      } else {
        // printf(".");
      }
    }
    // printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
