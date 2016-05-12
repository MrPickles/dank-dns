#ifndef PACKET_H
#define PACKET_H

typedef struct {
  uint64_t uniqueID;
  uint64_t time;
  uint64_t curCaptureTime;
  uint64_t lastCaptureTime;
  uint64_t overallCaptureTime;
  uint32_t sourceIP;
  uint32_t destIP;
  uint8_t payload[2048];
  size_t size;
} packet_t;


typedef struct {
  packet_t query;
  packet_t answer;
} dns_pair;

typedef struct {
  uint16_t id;       /* query identification number */
  uint8_t  flags1;   /* first byte of flags */
  uint8_t  flags2;   /* second byte of flags */
  uint16_t qdcount;  /* number of question entries */
  uint16_t ancount;  /* number of answer entries */
  uint16_t nscount;  /* number of authority entries */
  uint16_t arcount;  /* number of resource entries */
} dns_header;

typedef struct {
  char *name;
  uint16_t type;
  uint16_t class;
  uint16_t ttl;
  uint16_t rdlength;
  char *rdata;
} dns_record;

typedef struct {
  
} dns_t;

#endif
