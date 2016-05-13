#include "worker.h"

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "protocol.h"
#include "util.h"

void *worker_job(void *args) {
  worker_t *worker = (worker_t *)args;
  int read_fd = worker->parent_to_worker_fd[0];
  int write_fd = worker->worker_to_parent_fd[1];

  // TODO(aliu1): Connect to database, if applicable.

  while (1) {
    uint8_t opcode = 0;
    uint8_t readyCode = READY_CODE;
    ssize_t written_bytes = write(write_fd, &readyCode, 1);
    ssize_t read_bytes = read(read_fd, &opcode, 1);

    UNUSED(written_bytes);
    UNUSED(read_bytes);

    if (opcode == TERMINATE_CODE) {
#if DEBUG
      printf("worker %d received a terminate code\n", worker->index);
#endif
      return NULL;
    } else if (opcode == JOB_CODE) {
#if DEBUG
      printf("worker %d received job code\n", worker->index);
#endif
      uint32_t length = 0;
      uint8_t *payload = NULL;
      ssize_t job_bytes_recvd = recv_job(read_fd, &length, &payload);
#if DEBUG
      printf("worker %d received file \"%s\"\n", length, payload);
#endif

      // TODO(aliu1): Process the file here.
      UNUSED(job_bytes_recvd);
      free(payload);
    } else {
      fprintf(stderr, "Invalid opcode received.\n");
    }
  }
  return NULL;
}

