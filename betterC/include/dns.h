#ifndef DNS_H
#define DNS_H

#include <inttypes.h>

#include "util.h"

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
  int error;
  dns_header header;
  dns_record record;
  bool isDNSSEC;
} dns_t;

/*
 * Takes a DNS query packet and parses out the data. This function only parses
 * DNS responses and ignores queries, since the DNS response will have all the
 * data that a query contains.
 */
int parseDNS(dns_t *out, const uint8_t *packet, const uint16_t size);

#endif

