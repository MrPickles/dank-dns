#include "dns.h"

int parseDNS(dns_t *out, const uint8_t *packet, const uint16_t size) {
  // Check for valid header size or if packet is a query.
  if (size < 16 || !out || !packet || !(packet[2] >> 7)) {
    return -1;
  }

  // Set header fields.
  out->header.id = ntohs(*((uint16_t *)packet));
  out->header.flags1 = packet[2];
  out->header.flags2 = packet[3];
  out->header.qdcount = ntohs(*((uint16_t *)(packet + 4)));
  out->header.ancount = ntohs(*((uint16_t *)(packet + 6)));
  out->header.nscount = ntohs(*((uint16_t *)(packet + 8)));
  out->header.arcount = ntohs(*((uint16_t *)(packet + 10)));

  return 0;
}

