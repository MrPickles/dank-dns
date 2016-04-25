#ifndef PARSE_DNS_H
#define PARSE_DNS_H

#include <list>
#include <stdint.h>
#include <string>
#include <string.h>

#include "nameser.h"

#define DNS_ERR_NONE 0
#define DNS_ERR_FORMAT_ERROR 1
#define DNS_ERR_SERVER_FAILURE 2
#define DNS_ERR_NAME_ERROR 3
#define DNS_ERR_NOT_IMPLEMENTED 4
#define DNS_ERR_REFUSED 5

typedef struct {
  std::string qname;
  std::list<std::string> qnameParts;
  uint16_t qtype;
  uint16_t qclass;
} DNSQuestion;

typedef struct {
  int error;
  HEADER header;
  DNSQuestion question;
  bool isDNSSEC;
} DNSQuery;

void dnsParseInit();
int dnsParseID(const uint8_t *data, uint32_t size);
int dnsParseResponse(const uint8_t *data, uint32_t size); 
int dnsParseQuery(DNSQuery *query, const uint8_t *data, uint32_t size); 

bool dnsIsValidType(uint16_t value);
bool dnsIsValidClass(uint16_t value); 
bool dnsIsValidTLD(const char *name);

#endif // PARSE_DNS_H

