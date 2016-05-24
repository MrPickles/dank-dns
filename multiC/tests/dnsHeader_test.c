#include "test.h"

#include <stdlib.h>
#include <string.h>

#include "dns.h"

int main() {
  print_section("DNS Parsing Test");
  print_state("Empty packets should fail", parseDNS(NULL, NULL, 0) == -1);

  unsigned char dnsQuery[] = {
    0x82, 0x1e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x06, 0x61, 0x31, 0x37,
    0x2d, 0x30, 0x37, 0x03, 0x72, 0x73, 0x77, 0x03,
    0x6b, 0x72, 0x32, 0x00, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x80,
    0x00, 0x00, 0x00
  };

  dns_t dns = {0};
  print_state("Parsing should ignore DNS query packets",
      parseDNS(&dns, dnsQuery, sizeof(dnsQuery)) == -1);

  unsigned char payload1[] = {
    0x82, 0x1e, 0x86, 0x03, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x06, 0x61, 0x31, 0x37,
    0x2d, 0x30, 0x37, 0x03, 0x72, 0x73, 0x77, 0x03,
    0x6b, 0x72, 0x32, 0x00, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80,
    0x00, 0x00, 0x00
  };
  memset(&dns, 0, sizeof(dns));
  parseDNS(&dns, payload1, sizeof(payload1));

  print_state("Header 1 ID Check", dns.header.id == 0x821e);
  print_state("Header 1 Flag Check",
      dns.header.flags1 == 0x86 && dns.header.flags2 == 0x03);
  print_state("Header 1 Question Count", dns.header.qdcount == 1);
  print_state("Header 1 Answer Count", dns.header.ancount == 0);
  print_state("Header 1 Authority Count", dns.header.nscount == 0);
  print_state("Header 1 Additional Count", dns.header.arcount == 1);
  print_state("Header 1 Domain Name Check",
      !strcmp(dns.question.name, "a17-07.rsw.kr2."));
  print_state("Header 1 Question Type Check", dns.question.type == 1);
  print_state("Header 1 Question Class Check", dns.question.class == 1);
  free(dns.question.name);

  unsigned char payload2[] = {
    0x2b, 0xcb, 0x84, 0x00, 0x00, 0x01, 0x00, 0x0e,
    0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x02, 0x00,
    0x01, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x07,
    0xe9, 0x00, 0x00, 0x14, 0x01, 0x6d, 0x0c, 0x72,
    0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76,
    0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x07, 0xe9,
    0x00, 0x00, 0x04, 0x01, 0x6a, 0xc0, 0x1e, 0x00,
    0x00, 0x02, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00,
    0x00, 0x04, 0x01, 0x6c, 0xc0, 0x1e, 0x00, 0x00,
    0x02, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00,
    0x04, 0x01, 0x63, 0xc0, 0x1e, 0x00, 0x00, 0x02,
    0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x04,
    0x01, 0x64, 0xc0, 0x1e, 0x00, 0x00, 0x02, 0x00,
    0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x04, 0x01,
    0x6b, 0xc0, 0x1e, 0x00, 0x00, 0x02, 0x00, 0x01,
    0x00, 0x07, 0xe9, 0x00, 0x00, 0x04, 0x01, 0x67,
    0xc0, 0x1e, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
    0x07, 0xe9, 0x00, 0x00, 0x04, 0x01, 0x68, 0xc0,
    0x1e, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x07,
    0xe9, 0x00, 0x00, 0x04, 0x01, 0x65, 0xc0, 0x1e,
    0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x07, 0xe9,
    0x00, 0x00, 0x04, 0x01, 0x62, 0xc0, 0x1e, 0x00,
    0x00, 0x02, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00,
    0x00, 0x04, 0x01, 0x66, 0xc0, 0x1e, 0x00, 0x00,
    0x02, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00,
    0x04, 0x01, 0x61, 0xc0, 0x1e, 0x00, 0x00, 0x02,
    0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x04,
    0x01, 0x69, 0xc0, 0x1e, 0x00, 0x00, 0x2e, 0x00,
    0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x93, 0x00,
    0x02, 0x08, 0x00, 0x00, 0x07, 0xe9, 0x00, 0x56,
    0xe1, 0xa8, 0x10, 0x56, 0xd4, 0x6b, 0x00, 0xd5,
    0x15, 0x00, 0x04, 0x86, 0x93, 0xc0, 0x08, 0x71,
    0x13, 0x68, 0xeb, 0xf4, 0x2f, 0xdf, 0x32, 0x66,
    0x78, 0x43, 0x12, 0xfb, 0xf6, 0x23, 0x08, 0x19,
    0x4b, 0xd2, 0xf2, 0x92, 0xf7, 0x7e, 0x38, 0x16,
    0xce, 0x5b, 0x8a, 0x94, 0x3e, 0xa7, 0x2f, 0xec,
    0xee, 0xa1, 0x3b, 0x0a, 0x67, 0x66, 0x80, 0x8d,
    0x4f, 0xca, 0x1f, 0x14, 0x3f, 0x4d, 0x10, 0x35,
    0x94, 0x5e, 0xb2, 0xbf, 0xe6, 0x24, 0x92, 0x3e,
    0x2b, 0xc1, 0x97, 0x31, 0x42, 0xc2, 0x3e, 0x11,
    0x64, 0x7b, 0x0e, 0xb6, 0x88, 0x21, 0xc3, 0x5e,
    0xa2, 0xfa, 0x57, 0x14, 0x49, 0xe9, 0xc3, 0x8a,
    0x43, 0xe7, 0xf0, 0xe4, 0x3f, 0x46, 0x6e, 0x7e,
    0xf4, 0x81, 0x0a, 0xd4, 0x84, 0xa7, 0x29, 0xec,
    0xb2, 0xc1, 0x15, 0xe0, 0x20, 0x8d, 0xf0, 0xd9,
    0x75, 0x0f, 0x97, 0xaa, 0x8b, 0x96, 0x79, 0x5a,
    0xf8, 0xeb, 0x31, 0x75, 0x39, 0x0a, 0xef, 0x42,
    0x6c, 0xbf, 0xc0, 0xd1, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x36, 0xee, 0x80, 0x00, 0x04, 0xc6, 0x29,
    0x00, 0x04, 0xc0, 0xb3, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x36, 0xee, 0x80, 0x00, 0x04, 0xc0, 0xe4,
    0x4f, 0xc9, 0xc0, 0x59, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x36, 0xee, 0x80, 0x00, 0x04, 0xc0, 0x21,
    0x04, 0x0c, 0xc0, 0x68, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x36, 0xee, 0x80, 0x00, 0x04, 0xc7, 0x07,
    0x5b, 0x0d, 0xc0, 0xa4, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x36, 0xee, 0x80, 0x00, 0x04, 0xc0, 0xcb,
    0xe6, 0x0a, 0xc0, 0xc2, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x36, 0xee, 0x80, 0x00, 0x04, 0xc0, 0x05,
    0x05, 0xf1, 0xc0, 0x86, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x36, 0xee, 0x80, 0x00, 0x04, 0xc0, 0x70,
    0x24, 0x04, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00,
    0x00, 0x80, 0x00, 0x00, 0x00
  };
  memset(&dns, 0, sizeof(dns));
  parseDNS(&dns, payload2, sizeof(payload1));

  print_state("Header 2 ID Check", dns.header.id == 0x2bcb);
  print_state("Header 2 Flag Check",
      dns.header.flags1 == 0x84 && dns.header.flags2 == 0x00);
  print_state("Header 2 Question Count", dns.header.qdcount == 1);
  print_state("Header 2 Answer Count", dns.header.ancount == 14);
  print_state("Header 2 Authority Count", dns.header.nscount == 0);
  print_state("Header 2 Additional Count", dns.header.arcount == 8);
  print_state("Header 2 Domain Name Check",
      !strcmp(dns.question.name, "."));
  print_state("Header 2 Question Type Check", dns.question.type == 2);
  print_state("Header 2 Question Class Check", dns.question.class == 1);
  free(dns.question.name);

  print_section("Test response");
  unsigned char response[] = {
    0xf3, 0x1a, 0x84, 0x03, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x01, 0x07, 0x66, 0x70, 0x6a,
    0x75, 0x73, 0x6b, 0x69, 0x00, 0x00, 0x1c, 0x00,
    0x01, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x01,
    0x51, 0x80, 0x00, 0x40, 0x01, 0x61, 0x0c, 0x72,
    0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76,
    0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00,
    0x05, 0x6e, 0x73, 0x74, 0x6c, 0x64, 0x0c, 0x76,
    0x65, 0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2d,
    0x67, 0x72, 0x73, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    0x78, 0x2a, 0x38, 0xe9, 0x00, 0x00, 0x07, 0x08,
    0x00, 0x00, 0x03, 0x84, 0x00, 0x09, 0x3a, 0x80,
    0x00, 0x01, 0x51, 0x80, 0x00, 0x00, 0x29, 0x10,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  memset(&dns, 0, sizeof(dns));
  parseDNS(&dns, response, sizeof(payload1));

  print_state("This is a response", dns.header.qr == 1);
  print_state("This is an authoritative answer", dns.header.aa == true);
  print_state("This message is not truncated", dns.header.tc == false);
  print_state("Recursion is not desired", dns.header.rd == false);
  print_state("Recursion is not available on the server", dns.header.ra == false);
  print_state("Response code is 3", dns.header.rc == 3);
  print_state("Question Count", dns.header.qdcount == 1);
  print_state("Answer Count", dns.header.ancount == 0);
  print_state("Authority Count", dns.header.nscount == 1);
  print_state("Additional Count", dns.header.arcount == 1);

  print_section("Test DNSSEC");

  unsigned char dnssec[] = {
    0x20, 0xa3, 0x81, 0xa0, 0x00, 0x01, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x01, 0x04, 0x69, 0x65, 0x74,
    0x66, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x30,
    0x00, 0x01, 0xc0, 0x0c, 0x00, 0x30, 0x00, 0x01,
    0x00, 0x00, 0x04, 0x7c, 0x01, 0x08, 0x01, 0x01,
    0x03, 0x05, 0x03, 0x01, 0x00, 0x01, 0xab, 0xe3,
    0x43, 0x51, 0xfa, 0xa4, 0x4f, 0x05, 0x57, 0xc2,
    0xc6, 0x3f, 0x4c, 0x10, 0x04, 0x55, 0x4b, 0xd0,
    0x43, 0x3d, 0x05, 0x17, 0xea, 0xc7, 0x3f, 0x69,
    0xfe, 0xc6, 0x7e, 0xf0, 0x00, 0x72, 0xab, 0x21,
    0x47, 0x2d, 0xd6, 0x5c, 0x1e, 0x83, 0x86, 0x17,
    0xb0, 0xa0, 0x07, 0x93, 0x8a, 0x60, 0xcb, 0xc6,
    0x3a, 0x0c, 0xac, 0xb9, 0x84, 0x25, 0xa0, 0xf9,
    0x70, 0x6e, 0xae, 0xd6, 0xb3, 0x95, 0xb2, 0xc1,
    0xbb, 0xad, 0x6d, 0x7c, 0x86, 0xdb, 0x89, 0x4c,
    0x5b, 0x2e, 0x23, 0x8a, 0x39, 0x49, 0x52, 0xc6,
    0x85, 0xad, 0x2e, 0x44, 0xbd, 0x4b, 0xb8, 0xc9,
    0xd9, 0xae, 0x45, 0xcf, 0xd3, 0x1a, 0x71, 0x17,
    0x9c, 0xdd, 0x57, 0x42, 0x43, 0xbe, 0xc1, 0xa2,
    0x13, 0xe1, 0xc2, 0xed, 0xae, 0x67, 0x16, 0x8e,
    0x86, 0x3c, 0x3a, 0xab, 0x9d, 0xea, 0x50, 0xda,
    0x25, 0xd8, 0xf5, 0x70, 0xaa, 0xf6, 0x9d, 0x7d,
    0x4d, 0xae, 0x63, 0x11, 0xa3, 0x02, 0x2e, 0xdc,
    0x32, 0x15, 0xb4, 0x66, 0xd0, 0x26, 0x6c, 0xe9,
    0xba, 0x4a, 0x43, 0x55, 0x96, 0x98, 0x30, 0xc0,
    0x26, 0xf0, 0xce, 0x6f, 0xcf, 0x85, 0x36, 0xbd,
    0x10, 0x95, 0x11, 0x32, 0xe0, 0x0e, 0x84, 0x3b,
    0xae, 0x1b, 0x22, 0x0f, 0x5d, 0xbb, 0x27, 0xc8,
    0x15, 0x13, 0x18, 0xce, 0xf0, 0x1d, 0x35, 0xd7,
    0x78, 0xc2, 0x6a, 0x36, 0xc5, 0x45, 0xc3, 0x2d,
    0x52, 0xd1, 0x53, 0x8c, 0x7e, 0x33, 0xee, 0x35,
    0xcf, 0xd9, 0x9c, 0xc3, 0x71, 0x7b, 0x20, 0xa5,
    0xee, 0x0b, 0x60, 0x5b, 0x9e, 0x9c, 0x54, 0x00,
    0x71, 0x10, 0x51, 0x94, 0x4e, 0xa8, 0x6b, 0x29,
    0x07, 0x47, 0xba, 0xe5, 0x3e, 0xaa, 0xa6, 0xc3,
    0x9f, 0x27, 0x20, 0x42, 0xc9, 0x50, 0x5a, 0x0c,
    0x71, 0xbf, 0xc1, 0x75, 0x12, 0xe0, 0x6f, 0x24,
    0xde, 0xba, 0xb1, 0x65, 0x9f, 0x1b, 0xc0, 0x0c,
    0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 0x04, 0x7c,
    0x01, 0x08, 0x01, 0x00, 0x03, 0x05, 0x03, 0x01,
    0x00, 0x01, 0xd0, 0xc4, 0x09, 0xa8, 0xc7, 0x69,
    0x38, 0xdf, 0x4a, 0x83, 0x53, 0x63, 0x9f, 0x16,
    0x70, 0x16, 0xa1, 0xd4, 0x1c, 0x4f, 0x29, 0x52,
    0x07, 0x07, 0x3e, 0x08, 0x7c, 0xb8, 0xdf, 0xa8,
    0xcb, 0xe2, 0xba, 0x6e, 0x25, 0x80, 0xab, 0x4a,
    0x64, 0xb7, 0xbd, 0xec, 0x38, 0x09, 0xe7, 0xf3,
    0x50, 0xac, 0xd1, 0x06, 0x19, 0x09, 0xab, 0xe9,
    0xf2, 0xaf, 0x52, 0x3e, 0xbb, 0x71, 0xfa, 0xd9,
    0x52, 0x88, 0xd9, 0xd9, 0xc1, 0x91, 0x8b, 0x35,
    0x61, 0x82, 0x43, 0xaa, 0x67, 0xdb, 0x1c, 0x69,
    0x35, 0x57, 0x36, 0xe5, 0xcb, 0x33, 0x94, 0xf0,
    0xed, 0x55, 0x8e, 0x54, 0x87, 0x1e, 0x79, 0x70,
    0x2e, 0xb8, 0x7d, 0xa6, 0x3c, 0x88, 0x84, 0x57,
    0xa3, 0x21, 0x25, 0x85, 0x2c, 0x5b, 0xa7, 0x6f,
    0x98, 0xdb, 0x09, 0xe1, 0x7c, 0x02, 0x80, 0xd8,
    0x2b, 0xa0, 0x09, 0x97, 0x86, 0x83, 0x04, 0x89,
    0x61, 0x23, 0x04, 0x1f, 0xb0, 0x8d, 0x86, 0x50,
    0xe4, 0x6b, 0x59, 0x1c, 0x11, 0x4a, 0x55, 0x70,
    0x02, 0x49, 0x64, 0xe2, 0x0a, 0xd7, 0x5d, 0x1d,
    0xcb, 0x9e, 0x39, 0xe4, 0x95, 0x3e, 0x2e, 0x56,
    0x1f, 0xde, 0x15, 0x96, 0xe6, 0xe1, 0x1d, 0xf8,
    0xb2, 0xb4, 0xd3, 0xd9, 0x2e, 0xb3, 0x9b, 0x85,
    0x40, 0x87, 0x4f, 0xa9, 0x34, 0xb4, 0xd1, 0x3a,
    0xa6, 0x12, 0xe8, 0x1e, 0x75, 0xd6, 0x53, 0xee,
    0xaf, 0xa6, 0xc6, 0x29, 0xcf, 0xa1, 0xa1, 0x33,
    0x0f, 0xd1, 0xf4, 0x11, 0x71, 0x5b, 0x93, 0xdd,
    0x3c, 0x52, 0x16, 0x06, 0x0a, 0x16, 0x93, 0x6f,
    0xd7, 0x15, 0x54, 0x52, 0x28, 0x6f, 0x4b, 0xaf,
    0xad, 0x5b, 0xdb, 0x3d, 0x51, 0xd7, 0x6e, 0xb1,
    0x79, 0x4c, 0x2f, 0xc3, 0x8e, 0x91, 0x57, 0x2d,
    0xe1, 0x6a, 0x75, 0x77, 0xbc, 0xd3, 0xbb, 0x2c,
    0xce, 0x47, 0x9e, 0x2a, 0x9a, 0x61, 0xc9, 0x41,
    0x6e, 0x19, 0xc0, 0x0c, 0x00, 0x2e, 0x00, 0x01,
    0x00, 0x00, 0x04, 0x7c, 0x01, 0x1c, 0x00, 0x30,
    0x05, 0x02, 0x00, 0x00, 0x07, 0x08, 0x52, 0xd0,
    0x71, 0x87, 0x50, 0xef, 0x30, 0xaf, 0xb2, 0x12,
    0x04, 0x69, 0x65, 0x74, 0x66, 0x03, 0x6f, 0x72,
    0x67, 0x00, 0x16, 0x32, 0x8f, 0xe1, 0x3c, 0x5a,
    0xef, 0x54, 0xd2, 0x1a, 0x5b, 0xda, 0x00, 0x3d,
    0xf9, 0x0c, 0xc6, 0xf9, 0x7d, 0xf4, 0x80, 0x98,
    0xa1, 0x18, 0x34, 0x52, 0x2a, 0x81, 0xc2, 0x02,
    0x9e, 0xd1, 0xec, 0x55, 0xb3, 0xcf, 0x26, 0xc6,
    0x73, 0xb0, 0x92, 0x75, 0x74, 0xd0, 0xe8, 0x80,
    0x72, 0x0e, 0x80, 0x9b, 0x88, 0xff, 0x67, 0xe9,
    0xd0, 0xb5, 0x1e, 0x0b, 0xd4, 0x72, 0x0e, 0x89,
    0xed, 0x0d, 0x23, 0xe7, 0x31, 0x94, 0x72, 0x9e,
    0x8e, 0x3a, 0x3f, 0xe2, 0x24, 0x8d, 0x07, 0x73,
    0x8d, 0x90, 0x8f, 0x74, 0xa3, 0x81, 0xe6, 0x99,
    0x02, 0x6c, 0xac, 0x3f, 0x9a, 0xc0, 0x17, 0xd8,
    0xd5, 0x2f, 0xc7, 0x28, 0xef, 0x6f, 0x3c, 0x53,
    0xa9, 0x93, 0x1d, 0x80, 0x21, 0x0d, 0xf1, 0xc1,
    0xd5, 0x4c, 0x51, 0x30, 0x79, 0x79, 0x3d, 0xc8,
    0x8e, 0x07, 0xe5, 0xc3, 0xa8, 0x53, 0x60, 0xfb,
    0x03, 0x31, 0xbc, 0x92, 0xbb, 0x7a, 0xd4, 0x76,
    0x83, 0x40, 0x48, 0xeb, 0xa6, 0xd9, 0x2f, 0xa0,
    0xd0, 0xd7, 0xe2, 0xe7, 0x0a, 0x91, 0x4e, 0x0f,
    0xee, 0xf2, 0x32, 0x2e, 0xc9, 0xe9, 0x4d, 0x6b,
    0xaf, 0x73, 0xc1, 0x9a, 0x58, 0x3e, 0xdd, 0x29,
    0xe5, 0x37, 0x46, 0xd6, 0x5a, 0x39, 0xb0, 0xdd,
    0xab, 0x11, 0x0f, 0xf9, 0xb3, 0xef, 0x11, 0x0a,
    0x9c, 0x30, 0xf4, 0xbe, 0xce, 0xf0, 0x01, 0x0a,
    0x08, 0x29, 0x0a, 0xd8, 0xef, 0x36, 0x68, 0xe3,
    0x18, 0x9d, 0xe2, 0x41, 0xe6, 0xb8, 0xdc, 0xf1,
    0x1e, 0xfa, 0x17, 0x30, 0x6b, 0x41, 0xd7, 0xbf,
    0x85, 0x36, 0x3a, 0xaa, 0xef, 0xee, 0x2f, 0x0e,
    0xe3, 0x74, 0xb5, 0x2e, 0xb9, 0xa7, 0x06, 0xe6,
    0xa4, 0xc4, 0x2c, 0x4b, 0xdf, 0xdd, 0xe0, 0x3c,
    0x59, 0x9f, 0x28, 0x31, 0x4c, 0xc5, 0x2d, 0x7f,
    0x53, 0xe1, 0xa4, 0x69, 0x65, 0x52, 0x21, 0x8b,
    0xa9, 0xc4, 0xc0, 0x0c, 0x00, 0x2e, 0x00, 0x01,
    0x00, 0x00, 0x04, 0x7c, 0x01, 0x1c, 0x00, 0x30,
    0x05, 0x02, 0x00, 0x00, 0x07, 0x08, 0x52, 0xd0,
    0x71, 0x95, 0x50, 0xef, 0x30, 0xaf, 0x9e, 0x04,
    0x04, 0x69, 0x65, 0x74, 0x66, 0x03, 0x6f, 0x72,
    0x67, 0x00, 0x48, 0xe6, 0x29, 0x52, 0x6d, 0xed,
    0x2e, 0x74, 0x41, 0xa4, 0xd2, 0x49, 0x78, 0xbc,
    0xf3, 0xc3, 0xb6, 0xb7, 0xf8, 0xf8, 0x3a, 0xbb,
    0xe6, 0xf5, 0x2c, 0xd2, 0x86, 0x44, 0x12, 0xfc,
    0x6e, 0x2f, 0x01, 0x5b, 0x6f, 0xe0, 0x5d, 0x0e,
    0x55, 0x27, 0x92, 0x7f, 0x44, 0x57, 0x22, 0x28,
    0x3f, 0xed, 0xd5, 0x28, 0x79, 0xa2, 0x98, 0x7d,
    0x5b, 0x18, 0x0e, 0xcd, 0x8b, 0x47, 0x13, 0xf8,
    0x0a, 0x78, 0xf0, 0x95, 0xbe, 0x14, 0xa9, 0x22,
    0xb5, 0x10, 0xd8, 0xc9, 0x6e, 0x15, 0xe2, 0x1d,
    0x8f, 0x8a, 0xd8, 0xd7, 0x6d, 0xf8, 0x9e, 0x13,
    0xab, 0x34, 0xd0, 0x9c, 0xb9, 0x83, 0x0a, 0xac,
    0xc2, 0xda, 0xd4, 0xd7, 0x6c, 0x19, 0xbf, 0xf3,
    0xd0, 0x4d, 0xf0, 0x10, 0x30, 0xd4, 0xf6, 0x20,
    0xb9, 0x4f, 0x0b, 0xed, 0x37, 0x7b, 0x0d, 0x9a,
    0xaf, 0x26, 0x6e, 0xfb, 0x5e, 0x94, 0xc9, 0x62,
    0x69, 0xa2, 0xd0, 0x6b, 0xcb, 0x25, 0xae, 0x1a,
    0x99, 0xf3, 0x17, 0x12, 0x5b, 0xb7, 0x26, 0x07,
    0x1d, 0xa5, 0x58, 0xc0, 0x0b, 0xc3, 0x1d, 0xcb,
    0xf3, 0xeb, 0xe1, 0xa4, 0x35, 0xe6, 0x23, 0x5d,
    0x60, 0x88, 0x9f, 0x2d, 0xd4, 0xaa, 0x58, 0x00,
    0x35, 0xf1, 0x9f, 0x18, 0xce, 0xca, 0x22, 0x2c,
    0x9a, 0x59, 0xa8, 0x24, 0x0f, 0x34, 0x28, 0x49,
    0xe4, 0x05, 0x60, 0x97, 0xa7, 0x18, 0x06, 0xc5,
    0x3e, 0xa7, 0xe0, 0x1c, 0x56, 0xf7, 0xa4, 0xbc,
    0xa2, 0xce, 0xed, 0x52, 0xd5, 0x9e, 0x80, 0xd5,
    0x9e, 0xbf, 0xe1, 0x11, 0x33, 0x5f, 0xc9, 0xe1,
    0x7a, 0x6d, 0x7c, 0x03, 0x18, 0xeb, 0xa9, 0x46,
    0xf0, 0x55, 0xdb, 0xc7, 0x9c, 0x62, 0x83, 0x46,
    0x89, 0xbe, 0xd3, 0x9e, 0xb0, 0x9a, 0x93, 0xc4,
    0x6a, 0x71, 0xcf, 0xad, 0x84, 0x0a, 0x87, 0x93,
    0xb3, 0xaf, 0x69, 0x31, 0x6a, 0x92, 0x9a, 0x36,
    0x0e, 0x6c, 0x00, 0x00, 0x29, 0x0f, 0xa0, 0x00,
    0x00, 0x80, 0x00, 0x00, 0x00
  };

  memset(&dns, 0, sizeof(dns));
  parseDNS(&dns, dnssec, sizeof(payload1));

  print_state("This has DNSSEC", dns.isDNSSEC == true);

  return 0;
}

