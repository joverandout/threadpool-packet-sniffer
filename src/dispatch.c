#include "dispatch.h"

#include <pthread.h>
#include <pcap.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>

#include "analysis.h"
#include "sniff.h"

struct listOfPackets *packets;
unsigned long pcount = 0;
char threadsMade = 0;
char run = 1;

struct linkedList *newList;

pthread_mutex_t queue_mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_t thread1, thread2;

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

void declareThreads(){
    threadsMade = 1;

    //SEG FAULT CAUSED AT CREATE
    pthread_create(thread1, NULL, &threading, NULL);
    pthread_create(thread2, NULL, &threading, NULL);

    packets = malloc(sizeof(struct listOfPackets));
    packets->head = NULL;
}

void finsih(){
    run = 0;
    if(threadsMade){
        struct counting *total = malloc(sizeof(struct counting));
        if(total == NULL) exit (1);
        total->number_of_arp_attacks = 0;
        total->number_of_blacklisted_IDs=0;
        total->number_of_syn_attacks=0;

        int i;
        void* ptr;	
        pthread_join(thread1, &ptr);
        
        struct counting* thread_count = (struct counters *)ptr;
        addToTotal(total, thread_count);

        free(ptr);

        pthread_join(thread2, &ptr);
        
        thread_count = (struct counters *)ptr;
        addToTotal(total, thread_count);

        free(ptr);


        printf("\n\n === Packet Sniffing Report === \n");
		printf("ARP Poision Attacks = %ld\n", total->number_of_arp_attacks);
		printf("SYN Attacks = %ld\n", total->number_of_syn_attacks);
		printf("Blacklisted Requests = %ld\n\n\n", total->number_of_blacklisted_IDs);
		
		//Free the total_count counters struct
		free(total);
    }
}


void addToTotal(struct counting *total, struct counting *addToTotal){
    total->number_of_arp_attacks += addToTotal->number_of_arp_attacks;
    total->number_of_blacklisted_IDs += addToTotal->number_of_blacklisted_IDs;
    total->number_of_syn_attacks += addToTotal->number_of_syn_attacks;
}