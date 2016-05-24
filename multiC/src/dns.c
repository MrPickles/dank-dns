#include "dns.h"

#include <arpa/inet.h>
#include <stdlib.h>

int parseDNS(dns_t *out, const uint8_t *packet, const uint16_t size) {
  // Check for valid header size or if packet is a query.
  if (size < 16 || !out || !packet || !(packet[2] >> 7 & 1)) {
    return -1;
  }

  // Set header fields.
  out->header.id = ntohs(*((uint16_t *)packet));
  out->header.flags1 = packet[2];
  out->header.flags2 = packet[3];
  out->header.qr = out->header.flags1 >> 7 & 1;
  out->header.aa = out->header.flags1 >> 2 & 1;
  out->header.tc = out->header.flags1 >> 1 & 1;
  out->header.rd = out->header.flags1 >> 0 & 1;
  out->header.ra = out->header.flags2 >> 7 & 1;
  out->header.rc = out->header.flags2 & 0x0F;
  out->header.qdcount = ntohs(*((uint16_t *)(packet + 4)));
  out->header.ancount = ntohs(*((uint16_t *)(packet + 6)));
  out->header.nscount = ntohs(*((uint16_t *)(packet + 8)));
  out->header.arcount = ntohs(*((uint16_t *)(packet + 10)));

  // Parse question.
  // TODO(aliu1): Support multiple questions.
  int index = 12;
  int name_len = 0;
  while (index < size && packet[index]) {
    name_len += packet[index] + 1;
    index += packet[index] + 1;
  }

  // Check if the packet is too short. There must at least be 4 bytes left
  // for the type and class.
  if (index + 4 > size) {
    return -1;
  }

  if (name_len) {
    out->question.name = calloc(name_len + 1, sizeof(char));
  } else {
    // Specifically set the name for root server names.
    out->question.name = calloc(2, sizeof(char));
    out->question.name[0] = '.';
  }

  // Load in the question name.
  index = 12;
  int str_index = 0;
  while (packet[index]) {
    int octet_len = packet[index++];
    for (int i = 0; i < octet_len; i++) {
      out->question.name[str_index++] = packet[index++];
    }
    out->question.name[str_index++] = '.';
  }
  index++;

  out->question.type = ntohs(*((uint16_t *)(packet + index)));
  out->question.class = ntohs(*((uint16_t *)(packet + index + 2)));
  index +=4;

  if (out->header.arcount) {
    // Relevant DNSSEC data should be the final section of the packet.
    index = size - 11;
    uint8_t name = packet[index];
    uint16_t type = ntohs(*(uint16_t *)(packet + index + 1));
    uint16_t udpSize = ntohs(*(uint16_t *)(packet + index + 3));
    uint8_t extRCODE = packet[index + 5];
    uint8_t edns0Ver = packet[index + 6];
    uint16_t z = ntohs(*(uint16_t *)(packet + index + 7));
    uint16_t dataSize = ntohs(*(uint16_t *)(packet + index + 9));

    UNUSED(name);
    UNUSED(udpSize);
    UNUSED(extRCODE);
    UNUSED(edns0Ver);
    UNUSED(dataSize);

    if (type == 0x0029 && z == 0x8000) {
      out->isDNSSEC = true;
    }
  }

  return 0;
}

