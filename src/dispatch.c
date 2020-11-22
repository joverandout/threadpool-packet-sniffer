#include "dispatch.h"

#include <pthread.h>
#include <pcap.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>

#include "analysis.h"
#include "sniff.h"

struct listOfPackets *packets;
unsigned long pcount = 0;
char exitThreads = 0;
char run = 0;

struct linkedList *newList;

pthread_mutex_t queue_mutex=PTHREAD_MUTEX_INITIALIZER;

void dispatch(struct pcap_pkthdr *header, const unsigned char *packet, int verbose, struct list *list)
{
    newList = list;
    unsigned char *newPacket = malloc((sizeof(char)*header->len)+1);
    if(newPacket ==NULL){
        memcpy(newPacket, packet, header->len);
    }
    newPacket[sizeof(char)*header->len] = '\0';

    struct listElementPacket *packetToUse = malloc(sizeof(struct listElementPacket));
    if(packetToUse==NULL) exit (1);

    packetToUse->header = header;
    packetToUse->packet = packet;
    packetToUse->next = NULL;

    pthread_mutex_lock(&queue_mutex);

    recursivelyAddPackets(packets, packetToUse);

    pthread_mutex_unlock(&queue_mutex);
}

void recursivelyAddPackets(struct listElementPacket *head, struct listElementPacket *toAdd){
    if(head == NULL) head = toAdd;
    else if(head->next == NULL) head->next = toAdd;
    else recursivelyAddPackets(head->next, toAdd);
}

void *threading(){
    struct counting *threadCount = malloc(sizeof(struct counting));
    if (threadCount == NULL) exit(1);

    threadCount->number_of_arp_attacks=0;
    threadCount->number_of_blacklisted_IDs=0;
    threadCount->number_of_syn_attacks=0;

    while(run == 0){
        pthread_mutex_lock(&queue_mutex);

        if(packets->head != NULL){
            struct listElementPacket *header = packets->head;
            packets->head = header->next;

            pthread_mutex_unlock(&queue_mutex);

            struct counting *temporaryCount = analyse(header->header, header->packet, 0, newList);

            threadCount->number_of_arp_attacks += temporaryCount->number_of_arp_attacks;
            threadCount->number_of_blacklisted_IDs += temporaryCount->number_of_blacklisted_IDs;
            threadCount->number_of_syn_attacks += temporaryCount->number_of_syn_attacks;

            free((void *)header->packet);
            free(header);
            free(temporaryCount);
        }
        else{
            pthread_mutex_unlock(&queue_mutex);
        }
    }

    return (void *)threadCount;
}