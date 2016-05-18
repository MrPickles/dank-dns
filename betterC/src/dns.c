#include "dns.h"

#include <arpa/inet.h>
#include <stdlib.h>

int parseDNS(dns_t *out, const uint8_t *packet, const uint16_t size) {
  // Check for valid header size or if packet is a query.
  if (size < 16 || !out || !packet || !(packet[2] >> 7)) {
    return -1;
  }

  // Set header fields.
  out->header.id = ntohs(*((uint16_t *)packet));
  out->header.flags1 = packet[2];
  out->header.flags2 = packet[3];
  out->header.qr = qr_dns(out);
  out->header.aa = aa_dns(out);
  out->header.tc = tc_dns(out);
  out->header.rd = rd_dns(out);
  out->header.ra = ra_dns(out);
  out->header.rc = opcode_dns(out);
  out->header.rc = rcode_dns(out);
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

bool qr_dns(const dns_t *dns) {
  return dns->header.flags1 >> 7;
}

bool aa_dns(const dns_t *dns) {
  return (dns->header.flags1 << 5) >> 7;
}

bool tc_dns(const dns_t *dns) {
  return (dns->header.flags1 << 6) >> 7;
}

bool rd_dns(const dns_t *dns) {
  return (dns->header.flags1 << 7) >> 7;
}

bool ra_dns(const dns_t *dns) {
  return dns->header.flags2 >> 7;
}

uint8_t opcode_dns(const dns_t *dns) {
  return (dns->header.flags1 << 1) >> 4;
}

uint8_t rcode_dns(const dns_t *dns) {
  return (dns->header.flags2 << 4) >> 4;
}

