#include "protocol.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

ssize_t send_job(int fd, const uint32_t length, const uint8_t *payload) {
  uint32_t network_len = htonl(length);
  ssize_t len_sent = write(fd, &network_len, sizeof(network_len));
  if (len_sent != sizeof(network_len)) {
    return -1;
  }

  ssize_t payload_sent = write(fd, payload, length);
  if (payload_sent != length) {
    return -1;
  }
  return len_sent + payload_sent;
}

ssize_t recv_job(int fd, uint32_t *length, uint8_t **payload) {
  uint32_t network_len;
  ssize_t len_recvd = read(fd, &network_len, sizeof(network_len));
  if (len_recvd != sizeof(network_len)) {
    return -1;
  }
  *length = ntohl(network_len);

  *payload = calloc(*length, sizeof(uint8_t));
  ssize_t payload_recvd = read(fd, *payload, *length);
  if (payload_recvd != *length) {
    return -1;
  }
  return len_recvd + payload_recvd;
}

