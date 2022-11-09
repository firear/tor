#include "io.h"
#include <pcap.h>
#include <stdlib.h>
#include <time.h>

typedef struct rawio_tunnel_t {
    // 远端ip与port
    struct sockaddr_in baddr;

    int timeout;

    // for icmp
    int id;
    int seq;
    // for kcp
    void* ktun;
} rawio_tunnel;

/* prototype of the packet handler */
void packet_handler(
    uint8_t* param,
    const struct pcap_pkthdr* header,
    const uint8_t* pkt_data);

int doit()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

#if _WIN32
    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls()) {
        fprintf(stderr, "Couldn't load Npcap\n");
        exit(1);
    }
#endif
    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    /* Jump to the selected adapter */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++) {
    }

#if _WIN32
    /* Open the device */
    adhandle = pcap_open(d->name, // name of the device
        65536, // portion of the packet to capture
               // 65536 guarantees that the whole packet will
               // be captured on all the link layers
        PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
        1000, // read timeout
        NULL, // authentication on the remote machine
        errbuf // error buffer
    );
#else
    adhandle = pcap_open_live(d->name, 65536, 0, 100, errbuf);
#endif
    if (adhandle == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    printf("\nlistening on %s...\n", d->description);

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    return 0;
}
