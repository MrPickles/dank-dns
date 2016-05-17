#include "test.h"

#include <stdlib.h>

#include "dns.h"

int main() {
  print_section("DNS Header Test");
  print_state("Empty packets should fail", parseDNS(NULL, NULL, 0) == -1);
  return 0;
}

