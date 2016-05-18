#ifndef DNS_H
#define DNS_H

#include <inttypes.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "util.h"

typedef struct {
  uint16_t id;       /* query identification number */
  uint8_t  flags1;   /* first byte of flags */
  uint8_t  flags2;   /* second byte of flags */
  uint8_t qr;        /* question/response */
  bool aa;           /* authoritative answer */
  bool tc;           /* truncation flag */
  bool rd;           /* recursion desired */
  bool ra;           /* recursion available */
  uint16_t rc;       /* response code */
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
  int error;
  struct timeval packetTime;
  struct in_addr reqIP;
  struct in_addr resIP;
  dns_header header;
  // For now, we only support one question record.
  dns_record question;
  bool isDNSSEC;
  char *replica;
} dns_t;

/*
 * Takes a DNS query packet and parses out the data. This function only parses
 * DNS responses and ignores queries, since the DNS response will have all the
 * data that a query contains.
 */
int parseDNS(dns_t *out, const uint8_t *packet, const uint16_t size);

bool qr_dns(const dns_t *dns);
bool aa_dns(const dns_t *dns);
bool tc_dns(const dns_t *dns);
bool rd_dns(const dns_t *dns);
bool ra_dns(const dns_t *dns);
uint8_t opcode_dns(const dns_t *dns);
uint8_t rcode_dns(const dns_t *dns);

#endif

