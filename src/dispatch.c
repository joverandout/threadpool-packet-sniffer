#include "dispatch.h"

#include <pcap.h>

#include "analysis.h"
#include "sniff.h"

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose,
              int *synCount,
              struct list *list
              ) {
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  counting *tempCounters = analyse(header, packet, verbose, list);
  // printf("arp counter: %d\n", tempCounters->number_of_arp_attacks);
  // printf("syn counter: %d\n", tempCounters->number_of_syn_attacks);
  //printf("blacklisted counter: %d\n", tempCounters->number_of_blacklisted_IDs);
}
