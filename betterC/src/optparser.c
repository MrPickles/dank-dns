#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void optparser(int argc, char *argv[], int *workers, char **inputFiles[], int *inputFilesLength) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s -i <pcap.gz files> [-w <worker count>]\n", argv[0]);
    exit(1);
  }
  int index = 1;
  int inputStart = 0, inputEnd = 0;
  while (index < argc) {
    if (strcmp("-i", argv[index]) == 0) {
      inputStart = index + 1;
      index++;
    } else if (strcmp("-w", argv[index]) == 0) {
      if (inputEnd != 0) {
        inputEnd = index - 1;
      }
      if (index + 1 >= argc || (strncmp("-", argv[index + 1], 1) == 0)) {
        fprintf(stderr, "-w must specify an integer\n");
        exit(1);
      }
      *workers = atoi(argv[index + 1]);
      index = index + 2;
    } else if (strncmp("-", argv[index], 1) == 0) {
      fprintf(stderr, "Invalid option %s specified\n", argv[index]);
      exit(1);
    } else if (inputStart > 0) {
      inputEnd = index;
      index++;
    }  else {
      index++;
    }
  }
  if (inputEnd == 0) {
    fprintf(stderr, "Usage: %s -i <pcap.gz files> [-w <worker count>]\n", argv[0]);
    exit(1);
  }

  *inputFiles = argv + inputStart;
  *inputFilesLength = inputEnd - inputStart + 1;
}
