#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <sysexits.h>
#include <sys/wait.h>

#include "util.h"

int packetCount = 0;

void handlePacketCB(uint8_t *arg, const struct pcap_pkthdr *header,
    const uint8_t *packet) {

  const int datalinkOffset = *((int *)arg);

  // Grab IP information, and apply any necessary rules.
  const struct ip *headerIP = (const struct ip *)(packet + datalinkOffset);
  const uint8_t *payloadIP = (uint8_t *)headerIP + (headerIP->ip_hl * 4);
  uint32_t destIP = ntohl(headerIP->ip_dst.s_addr);
  uint32_t sourceIP = ntohl(headerIP->ip_src.s_addr);

  // TODO(zxlin): Parse IPv6?
  if (headerIP->ip_v != 4) {
    return;
  }

  // Grab the UDP information, and apply any necessary rules.
  const struct udphdr *headerUDP = (const struct udphdr *)payloadIP;
  const uint8_t *payloadUDP = (uint8_t *)headerUDP + 8;
  const uint16_t payloadUDPSize = ntohs(headerUDP->len) - 8;
  uint16_t sourcePort = ntohs(headerUDP->source);
  uint16_t destPort = ntohs(headerUDP->dest);

  UNUSED(destIP);
  UNUSED(sourceIP);
  UNUSED(destPort);
  UNUSED(sourcePort);
  UNUSED(payloadUDP);

  // TODO(aliu1): Find out if this block is necessary.
  if (payloadUDPSize > 2048) {
    fprintf(stderr, "Payload > 2048 bytes, skipping\n");
    return;
  }

  packetCount++;

  // TODO(aliu1): Parse DNS-specific data.
}

void parsePCAPStream(void (*cb)(uint8_t *, const struct pcap_pkthdr *, const uint8_t *)) {
  char pcapErrorMsg[PCAP_ERRBUF_SIZE] = { 0 };
  pcap_t *pcap = pcap_open_offline("-", pcapErrorMsg); // open stdin for stream

  if (pcap == NULL) {
    fprintf(stderr, "Could not open pcap - %s\n",
        pcapErrorMsg);
    exit(1);
  }

  // Apply libpcap filter
  struct bpf_program bpf;
  if (pcap_compile(pcap, &bpf, "udp port 53", 1, 0) < 0) { // filter only DNS data
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

  // Loops as the pcap stream is being processed, cb will be called for every available packet
  if (pcap_loop(pcap, -1, cb, (uint8_t *)&datalinkOffset) < 0) {
    fprintf(stderr, "Call to pcap_loop() failed - %s\n", pcap_geterr(pcap));
    exit(1);
  }

}

void analyzePCAP(char *filePath,
    void (*cb)(uint8_t *, const struct pcap_pkthdr *, const uint8_t *)) {

  pid_t child_pid;
  int fd[2];
  pipe(fd);

  if ((child_pid = fork()) < 0) {
    perror("fork() failed");
    exit(1);
  }

  if (child_pid == 0) { // is child
    // set up pipe back to parent
    close(fd[0]);
    dup2(fd[1], STDOUT_FILENO);

    // exec zcat
    char *cmd[3];
    cmd[0] = "zcat";
    cmd[1] = filePath;
    cmd[2] = NULL;
    int exec_stat = execvp("zcat", cmd);
    if (exec_stat == -1) {
      fprintf(stderr, "Failed to execute zcat\n");
      exit(1);
    }

    close(fd[1]);
  } else { // is parent
    close(fd[1]);
    dup2(fd[0], STDIN_FILENO);

    // call the streaming parser
    parsePCAPStream(cb);
    close(fd[0]);
    wait(NULL);
    printf("done %s | packets: %d\n", filePath, packetCount);
    packetCount = 0;
  }

}

