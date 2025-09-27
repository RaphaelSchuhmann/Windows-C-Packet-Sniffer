#include <pcap.h>
#include <stdio.h>

int main(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;

    // Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        return 1;
    }

    printf("Available Npcap devices:\n");
    int i = 0;
    for (d = alldevs; d; d = d->next) {
        printf("%d: %s", ++i, d->name);  // pcap device string
        if (d->description) printf("  (%s)", d->description); // friendly name
        printf("\n");
    }

    pcap_freealldevs(alldevs);
    return 0;
}
