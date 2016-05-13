#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <inttypes.h>

#include "packetHandle.h"

#define DEBUG

int main(int argc, char *argv[]) {
  char filePath[] = "pcap.sekr.2016030100";
  analyzePCAP(filePath, handlePacket);
  return 0;
}

