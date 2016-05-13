#ifndef PACKET_HANDLE_H
#define PACKET_HANDLE_H

/*
 * Parses the packet and extracts DNS data from the packet.
 */
void handlePacket(uint8_t *arg, const struct pcap_pkthdr *header,
    const uint8_t *packet);

/*
 * Analyze the PCAP file. The parameters are the PCAP file, and the callback
 * to handle each packet.
 */
void analyzePCAP(const char *filePath,
    void (*cb)(uint8_t *, const struct pcap_pkthdr *, const uint8_t *));

#endif

