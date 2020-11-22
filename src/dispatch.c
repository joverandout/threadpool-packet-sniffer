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

pthread_mutex_t queue_mutex=PTHREAD_MUTEX_INITIALIZER;

void dispatch(struct pcap_pkthdr *header, const unsigned char *packet, int verbose, struct list *list)
{
    unsigned char *newPacket = malloc((sizeof(char)*header->len)+1);
    if(newPacket ==NULL){
        memcpy(newPacket, packet, header->len);
    }
    newPacket[sizeof(char)*header->len] = '\0';

    struct listElementPacket *packetToUse = malloc(sizeof(struct listElementPacket));
    if(packetToUse==NULL) exit(1);

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