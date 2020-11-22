#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>

#include "analysis.h"
#include "sniff.h"

struct counting* totalCount;


void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose,
              int *synCount,
              struct list *linkedList
              ) {
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  counting *tempCounters = analyse(header, packet, verbose, linkedList);
  // printf("arp counter: %d\n", tempCounters->number_of_arp_attacks);
  // printf("syn counter: %d\n", tempCounters->number_of_syn_attacks);
  //printf("blacklisted counter: %d\n", tempCounters->number_of_blacklisted_IDs);


  pthread_mutex_lock()
  //As a new packet comes in make sure to lock to prevent an error

  pthread_mutex_unlock()
  //then unlock
}

void threadCreation(){
  int i;
  for (i = 0; i < 2; i++) //create 2 threads
  {
    pthread_create();
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
void *threadProcess(){

}

