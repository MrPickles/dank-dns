#include "test.h"

int main() {
  print_section("Sample Test");
  // Add summary as first parameter, and boolean as the second.
  print_state("1 + 1 == 2", 1 + 1 == 2);
  return 0;
}

