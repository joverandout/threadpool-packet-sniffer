#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>

#include "analysis.h"
#include "sniff.h"


struct thread_arg{
  counting *valuesPerThread;
};

struct counting* totalCount;
pthread_t tid1, tid2;
pthread_mutex_t queue_mutex;
struct thread_arg location1, location2;
struct listOfPackets *packets;


void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose,
              int *synCount,
              struct list *linkedList
              ) {
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.


  // counting *tempCounters = analyse(header, packet, verbose, linkedList);


  // printf("arp counter: %d\n", tempCounters->number_of_arp_attacks);
  // printf("syn counter: %d\n", tempCounters->number_of_syn_attacks);
  //printf("blacklisted counter: %d\n", tempCounters->number_of_blacklisted_IDs);

  pthread_create(&tid1, NULL, threadProcess, (void *) &location1);
  pthread_create(&tid2, NULL, threadProcess, (void *) &location2);

  struct listElementPacket *nextPacket = malloc(sizeof(struct listElementPacket));

  nextPacket->header = header;
  nextPacket->packet = packet;
  nextPacket->next = NULL;

  //As a new packet comes in make sure to lock to prevent an error
  pthread_mutex_lock(&queue_mutex);

  //Add the packet to the list
  recursivelyAddToPacketList(packets, nextPacket);

  pthread_mutex_unlock(&queue_mutex);
  //then unlock again
}


void recursivelyAddToPacketList(struct listElementPacket *head, struct listElementPacket * toAdd){
  if(head == NULL){
    head == toAdd;
    return;
  }  
  if(head->next == NULL){
    head->next=  toAdd;
    return;
  }
  else{
    recursivelyAddToPacketList(head->next, toAdd);
  }
}



void endOfThreading(struct list *linkedList){
  totalCount = malloc(sizeof(struct counting));
  int totalNumberOfUniqueSynIps = countSynIps(linkedList->head, 0);
  
  printf("Intrusion Detection Report:");
  printf("%d SYN packets detected from %d different IPs (syn attack)", totalNumberOfUniqueSynIps, totalCount->number_of_syn_attacks);
  printf("%d ARP responses (cache poisoning)", totalCount->number_of_arp_attacks);
  printf("%d URL Blacklist violations", totalCount->number_of_blacklisted_IDs);
}

int countSynIps(struct listelement *currentListElement, int count){
  if(currentListElement->next != NULL){
    count++;
    countSynIps(currentListElement->next, count);
  }
  return count;
}



//This is the process run by each of the threads
void *threadProcess(void *arg, struct list *linkedList){
  //this is the count for the individual thread 
  struct counting *threadCount = malloc(sizeof(struct counting));

  struct thread_arg *sptr =( struct thread_arg*) arg;

  threadCount->number_of_arp_attacks=0;
  threadCount->number_of_blacklisted_IDs=0;
  threadCount->number_of_syn_attacks=0;


  while(1){
    pthread_mutex_lock(&queue_mutex);
    //check theres a packet in the list
    if(packets->head != NULL){
      //get packet and assign the address to the next packet

      pthread_mutex_unlock(&queue_mutex);

      //This is just a counting struct to pass the analyse function
      struct counting *temporaryCount = malloc(sizeof(struct counting));
      //This is the result of the analyse function
      struct counting *resultOfAnalyse = analyse(packets->head->header, packets->head->packet, 0, linkedList);

      packets->head = packets->head.next;

      threadCount->number_of_arp_attacks=threadCount->number_of_arp_attacks+resultOfAnalyse->number_of_arp_attacks;
      threadCount->number_of_blacklisted_IDs=threadCount->number_of_blacklisted_IDs+resultOfAnalyse->number_of_blacklisted_IDs;
      threadCount->number_of_syn_attacks=threadCount->number_of_syn_attacks+resultOfAnalyse->number_of_syn_attacks;

      free(temporaryCount);
      free(resultOfAnalyse);
    }
    else{
      pthread_mutex_unlock(&queue_mutex);
    }
  }

  return threadCount;
}

