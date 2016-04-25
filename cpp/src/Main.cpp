#include <assert.h>
#include <dirent.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "Config.h"
#include "ParseDNS.h"

using namespace std;

struct Packet {
  uint64_t uniqueID;
  uint64_t time;
  uint64_t curCaptureTime;
  uint64_t lastCaptureTime;
  uint64_t overallCaptureTime;
  uint32_t sourceIP;
  uint32_t destIP;
  uint8_t payload[2048];
  size_t size;
};

////////////////////////////////////////////////////////////////////////////////
// HandlePacket
//
// Called from pcap_loop, this function breaks down the packet into its parts
// (IP, UDP, DNS) and calls all appropriate analysis functions with the
// necessary information. The compiled pcap rule limits calls to this function
// to UDP packets arriving/leaving on port 53 for the old/new IP addresses.
//

struct QRPacketPair {
  Packet query;
  Packet response;
  bool ready;
};

// Holding query+response pairs for future in-order processing
QRPacketPair *packets;
int packetProc = 0;
int packetAdd = 0;

// Keeping track of the amount of captured time
uint64_t totalCaptureTime = 0;
uint64_t lastCaptureTime = 0;
uint64_t captureStartTime = 0;
uint64_t captureLastTime = 0;
bool isFirstCapturePacket = false;
bool isFirstCapture = true;

void processQueryResponse(QRPacketPair *pPair) {
  DNSQuery query = { 0 };
  Packet *q = &pPair->query;
  Packet *r = &pPair->response;

  // Parsing the DNS response for error conditions
  query.error = dnsParseResponse(r->payload, r->size);

  // Parsing the DNS query
  if(dnsParseQuery(&query, q->payload, q->size) < 0) {
    assert(false && "Failed to parse a successful DNS query");
  }

  // TODO(aliu1): Process the parsed DNS query here. 
}

void handlePacket(uint8_t *arg, const struct pcap_pkthdr *header,
                  const uint8_t *packet) {
  const int datalinkOffset = *((int *)arg);
  uint64_t time = TIME_S2US(header->ts.tv_sec) + header->ts.tv_usec;

  // Updating the capture time keeping
  if(isFirstCapturePacket) {
    captureStartTime = time;
    captureLastTime = time;
    isFirstCapturePacket = false;
  }
  captureLastTime = time;

  // Grabbing IP information, and applying any necessary rules
  const struct ip *headerIP = (const struct ip *)(packet + datalinkOffset);
  const uint8_t *payloadIP = (uint8_t *)headerIP + (headerIP->ip_hl * 4);
  uint32_t destIP = ntohl(headerIP->ip_dst.s_addr);
  uint32_t sourceIP = ntohl(headerIP->ip_src.s_addr);

  if(headerIP->ip_v != 4) {
    return;
  }

  // Grabbing the UDP information, and applying any necessary rules
  const struct udphdr *headerUDP = (const struct udphdr *)payloadIP;
  const uint8_t *payloadUDP = (uint8_t *)headerUDP + 8;
  const uint16_t payloadUDPSize = ntohs(headerUDP->len) - 8;
  uint16_t sourcePort = ntohs(headerUDP->source);
  uint16_t destPort = ntohs(headerUDP->dest);

  if(payloadUDPSize > 2048) {
    fprintf(stderr, "Payload > 2048 bytes, skipping\n");
    return;
  }

  // Grabbing just a tiny bit of DNS information, namely the query ID
  // in order to do query->response matching
  int queryID = dnsParseID(payloadUDP, payloadUDPSize);
  if(queryID >= 0) {
    // If this is a query, add it to the queue and packet info map so that  we
    // can later match it up with it's response
    if(destIP == OLD_ADDRESS || destIP == NEW_ADDRESS) {
      uint64_t uniqueID = ((uint64_t)sourceIP << 32) | ((uint64_t)sourcePort << 16) | queryID;

      packets[packetAdd].query.uniqueID = uniqueID;
      packets[packetAdd].query.time = time;
      packets[packetAdd].query.curCaptureTime = captureLastTime - captureStartTime;
      packets[packetAdd].query.lastCaptureTime = lastCaptureTime;
      packets[packetAdd].query.overallCaptureTime = totalCaptureTime;
      packets[packetAdd].query.sourceIP = sourceIP;
      packets[packetAdd].query.destIP = destIP;
      packets[packetAdd].query.size = payloadUDPSize;
      memcpy(packets[packetAdd].query.payload, payloadUDP, payloadUDPSize);

      packets[packetAdd].ready = false;
      packetAdd++;
    } else {
      // Otherwise, this is a result so look for the query packet and pair them
      uint64_t uniqueID = ((uint64_t)destIP << 32) | ((uint64_t)destPort << 16) | queryID;

      for(int i = packetAdd - 1; i >= packetProc; i--) {
        if(packets[i].query.uniqueID == uniqueID) {
          packets[i].response.uniqueID = uniqueID;
          packets[i].response.time = time;
          packets[i].response.curCaptureTime = captureLastTime - captureStartTime;
          packets[i].response.lastCaptureTime = lastCaptureTime;
          packets[i].response.overallCaptureTime = totalCaptureTime;
          packets[i].response.sourceIP = sourceIP;
          packets[i].response.destIP = destIP;
          packets[i].response.size = payloadUDPSize;
          memcpy(packets[i].response.payload, payloadUDP, payloadUDPSize);
          packets[i].ready = true;

          break;
        }
      }
    }
  }

  // Going through the list to check if we can process any more packets. We want
  // to issue packets in the same order as they arrived, just in case analysis
  // expects times to flow as such
  while((packetProc < packetAdd) && packets[packetProc].ready) {
    processQueryResponse(&packets[packetProc]);
    packetProc++;
  }
}

inline uint64_t getTimeMilliseconds() {
  struct timespec curTime;
  clock_gettime(CLOCK_REALTIME, &curTime);
  return ((uint64_t)curTime.tv_sec * 1000) + (curTime.tv_nsec / 1000000);
}

int main(int argc, char **argv) {
  if(argc < 3) {
    fprintf(stderr, "Usage: %s <capture dir> <output dir> [start file #] [end file #]\n", argv[0]);
    exit(1);
  }

  int numEntries;
  struct dirent **entries;
  if((numEntries = scandir(argv[1], &entries, NULL, alphasort)) < 0) {
    fprintf(stderr, "Could not scan directory '%s'\n", argv[1]);
    exit(1);
  }

  char outputDir[512];
  sprintf(outputDir, "%s/output_%ld", argv[2], time(NULL));
  if(mkdir(outputDir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
    fprintf(stderr, "Could not create output directory '%s'\n", outputDir);
    exit(1);
  }

  packets = new QRPacketPair[200000];

  // Using this file to record the capture length (in time) for each file
  char filePath[512];
  sprintf(filePath, "%s/%s", outputDir, "capturelen.log");

  int numEntriesParsed = 0;

  int eStart = (argc >= 4) ? atoi(argv[3]) : 0;
  int eEnd = (argc == 5) ? atoi(argv[4]) : numEntries;

  int child_processes = 0;
  for(int e = eStart; e < eEnd; e++) {
    if(entries[e]->d_type == DT_REG) {
      pid_t child_pid;
      if ((child_pid = fork()) < 0) {
        fprintf(stderr, "Failed to fork\n");
        exit(1);
      }
      if (child_pid) {
        child_processes++;
      } else {
        uint64_t startProcTime = getTimeMilliseconds();

        char filePath[512];
        sprintf(filePath, "%s/%s", argv[1], entries[e]->d_name);

        static double totalProcTime = 0;
        double perFileProcTime = (e > eStart) ? (totalProcTime / (e - eStart)) : 0;
        printf("\rProcessing file %s [%04d/%04d] (Avg Proc Time = %lf ms)\n",
               filePath, (e - eStart), (eEnd - eStart), perFileProcTime);
        fflush(stdout);

        char pcapErrorMsg[PCAP_ERRBUF_SIZE] = { 0 };
        pcap_t *pcap = pcap_open_offline(filePath, pcapErrorMsg);
        if(pcap == NULL) {
          fprintf(stderr, "Could not open '%s' with pcap - %s\n", filePath,
                  pcapErrorMsg);
          exit(1);
        }

        struct bpf_program bpf;
        if(pcap_compile(pcap, &bpf, "udp port 53 and (dst host " OLD_ADDRESS_STR
                        " or dst host " NEW_ADDRESS_STR " or src host "
                       OLD_ADDRESS_STR " or src host " NEW_ADDRESS_STR ")",
                       1, 0) < 0) {
          fprintf(stderr, "Could not compile filter - %s\n", pcap_geterr(pcap));
          exit(1);
        }
        if(pcap_setfilter(pcap, &bpf) < 0) {
          fprintf(stderr, "Could not set filter - %s\n", pcap_geterr(pcap));
          exit(1);
        }
        pcap_freecode(&bpf);

        int datalinkType = pcap_datalink(pcap);

        int datalinkOffset;
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

        isFirstCapturePacket = true;

        if(pcap_loop(pcap, -1, handlePacket, (uint8_t *)&datalinkOffset) < 0) {
          fprintf(stderr, "Call to pcap_loop() failed - %s\n", pcap_geterr(pcap));
          exit(1);
        }

        // Going through the list to check if we can process any more packets, with
        // the relaxed ordering constraint now that we have no more to add/pair
        while(packetProc < packetAdd) {
          if(packets[packetProc].ready) {
            processQueryResponse(&packets[packetProc]);
          }
          packetProc++;
        }
        packetAdd = 0;
        packetProc = 0;

        // Keeping track of captured time
        isFirstCapture = false;
        lastCaptureTime = (captureLastTime - captureStartTime);
        totalCaptureTime += lastCaptureTime;

        uint64_t endProcTime = getTimeMilliseconds();
        totalProcTime += (endProcTime - startProcTime);

        numEntriesParsed++;
        pcap_close(pcap);

        // Terminate child process.
        exit(0);
      }
    }
    free(entries[e]);
  }

  // Reap all child processes.
  for (int i = 0; i < child_processes; i++) {
    wait(NULL);
  }

  free(entries);
}

