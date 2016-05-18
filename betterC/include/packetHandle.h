#ifndef PACKET_HANDLE_H
#define PACKET_HANDLE_H

#include <pcap/pcap.h>

#define FILEPATH_REGEX "pcap.(....).[0-9]{10}"

#define REPLICA_MAX_LEN 4

/*
 * Parses the packet and extracts DNS data from the packet.
 */
void handlePacketCB(uint8_t *arg, const struct pcap_pkthdr *header,
    const uint8_t *packet);

/*
 * Analyze the PCAP file. The parameters are the PCAP file, and the callback
 * to handle each packet.
 */
void analyzePCAP(char *filePath,
    void (*cb)(uint8_t *, const struct pcap_pkthdr *, const uint8_t *));

#endif

