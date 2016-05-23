#include "test.h"

#include <stdio.h>
#include <stdlib.h>

void print_state(char *name, int val) {
  if (name) {
    printf("%s: ", name);
  }
  if (val == 0) {
    printf(ANSI_COLOR_RED "Failed\n" ANSI_COLOR_RESET);
    exit(EXIT_FAILURE);
  }
  printf(ANSI_COLOR_GREEN "Passed\n" ANSI_COLOR_RESET);
}

void print_section(char *title) {
  printf("\n------------\n%s\n------------\n", title);
}
