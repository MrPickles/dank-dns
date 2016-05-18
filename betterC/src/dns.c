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
    out->record.name = calloc(name_len + 1, sizeof(char));
  } else {
    // Specifically set the name for root server names.
    out->record.name = calloc(2, sizeof(char));
    out->record.name[0] = '.';
  }

  // Load in the question name.
  index = 12;
  int str_index = 0;
  while (packet[index]) {
    int octet_len = packet[index++];
    for (int i = 0; i < octet_len; i++) {
      out->record.name[str_index++] = packet[index++];
    }
    out->record.name[str_index++] = '.';
  }
  index++;

  out->record.type = ntohs(*((uint16_t *)(packet + index)));
  out->record.class = ntohs(*((uint16_t *)(packet + index + 2)));

  return 0;
}

