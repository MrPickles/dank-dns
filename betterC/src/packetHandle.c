#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

void handlePacket(uint8_t *arg, const struct pcap_pkthdr *header,
    const uint8_t *packet) {
  const int datalinkOffset = *((int *)arg);

  // Grab IP information, and apply any necessary rules.
  const struct ip *headerIP = (const struct ip *)(packet + datalinkOffset);
  const uint8_t *payloadIP = (uint8_t *)headerIP + (headerIP->ip_hl * 4);
  uint32_t destIP = ntohl(headerIP->ip_dst.s_addr);
  uint32_t sourceIP = ntohl(headerIP->ip_src.s_addr);

  if (headerIP->ip_v != 4) {
    return;
  }

  // Grab the UDP information, and apply any necessary rules.
  const struct udphdr *headerUDP = (const struct udphdr *)payloadIP;
  const uint8_t *payloadUDP = (uint8_t *)headerUDP + 8;
  const uint16_t payloadUDPSize = ntohs(headerUDP->len) - 8;
  uint16_t sourcePort = ntohs(headerUDP->source);
  uint16_t destPort = ntohs(headerUDP->dest);

  // TODO(aliu): Find out if this block is necessary.
  if (payloadUDPSize > 2048) {
    fprintf(stderr, "Payload > 2048 bytes, skipping\n");
    return;
  }

  // TODO(aliu1): Parse DNS-specific data.
}

void analyzePCAP(const char *filePath,
    void (*cb)(uint8_t *, const struct pcap_pkthdr *, const uint8_t *)) {

  char pcapErrorMsg[PCAP_ERRBUF_SIZE] = { 0 };
  pcap_t *pcap = pcap_open_offline(filePath, pcapErrorMsg);
  if (pcap == NULL) {
    fprintf(stderr, "Could not open '%s' with pcap - %s\n", filePath,
        pcapErrorMsg);
    exit(1);
  }

  struct bpf_program bpf;
  if (pcap_compile(pcap, &bpf, "udp port 53", 1, 0) < 0) {
    fprintf(stderr, "Could not compile filter - %s\n", pcap_geterr(pcap));
    exit(1);
  }
  if (pcap_setfilter(pcap, &bpf) < 0) {
    fprintf(stderr, "Could not set filter - %s\n", pcap_geterr(pcap));
    exit(1);
  }
  pcap_freecode(&bpf);

  int datalinkType = pcap_datalink(pcap);
  int datalinkOffset;

  // Set data link offset based on data type.
  switch(datalinkType) {
    case DLT_LINUX_SLL:
      datalinkOffset = 16;
      break;
    case DLT_EN10MB:
      datalinkOffset = 14;
      break;
    case DLT_IEEE802:
      datalinkOffset = 22;
      break;
    case DLT_NULL:
      datalinkOffset = 4;
      break;
    case DLT_SLIP:
    case DLT_PPP:
      datalinkOffset = 24;
      break;
    case DLT_RAW:
      datalinkOffset = 0;
      break;
    default:
      fprintf(stderr, "Unknown datalink type %d\n", datalinkType);
      exit(1);
  }

  if (pcap_loop(pcap, -1, cb, (uint8_t *)&datalinkOffset) < 0) {
    fprintf(stderr, "Call to pcap_loop() failed - %s\n", pcap_geterr(pcap));
    exit(1);
  }

}

