#include <dirent.h>
#include <err.h>
#include <inttypes.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "packetHandle.h"
#include "protocol.h"
#include "util.h"
#include "worker.h"

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <pcap dir> [<worker count>]\n", argv[0]);
    exit(1);
  }

  // Scan PCAP directory.
  int numEntries;
  struct dirent **entries;
  if((numEntries = scandir(argv[1], &entries, NULL, alphasort)) < 0) {
    fprintf(stderr, "Could not scan directory '%s'\n", argv[1]);
    exit(1);
  }

  // Calculate number of worker threads.
  int workerCount = -1;
  if (argc > 2) {
    workerCount = atoi(argv[2]);
  }
  // Set number of workers to number of cores by default.
  if (workerCount < 1) {
    workerCount = sysconf(_SC_NPROCESSORS_ONLN);
  }

  worker_t *workers = calloc(workerCount, sizeof(worker_t));
  struct pollfd *pollfds = calloc(workerCount, sizeof(struct pollfd));

  // Initialize worker threads.
  for (int i = 0; i < workerCount; i++) {
    // Open pipe between worker and mediator.
    if (pipe(workers[i].parent_to_worker_fd) < 0) {
      err(EX_OSERR, "pipe error");
    }
    if (pipe(workers[i].worker_to_parent_fd) < 0) {
      err(EX_OSERR, "pipe error");
    }
    workers[i].index = i;

    // Set worker sockets to polling list.
    pollfds[i].fd = workers[i].worker_to_parent_fd[0];
    pollfds[i].events = POLLIN;
    pollfds[i].revents = 0;

    // Spawn worker threads.
    pthread_t tid;
    if (pthread_create(&tid, NULL, worker_job, &workers[i])) {
      err(EX_OSERR, "failed to spawn worker thread");
    }
    // Automatically free thread resources.
    pthread_detach(tid);
  }

  // Dispatch all jobs.
  for (int i = 0; i < numEntries; i++) {
    // Ignore directories or irrelevant file types.
    if (entries[i]->d_type != DT_REG) {
      continue;
    }

    // Poll for ready worker.
    for (int i = 0; i < workerCount; i++) {
      pollfds[i].events = POLLIN | POLLPRI;
      pollfds[i].revents = 0;
    }

    if (poll(pollfds, workerCount, -1) == -1) {
      err(EX_OSERR, "poll error");
      exit(1);
    }

    int read_fd = -1;
    int write_fd = -1;
    for (int i = 0; i < workerCount; i++) {
      if (pollfds[i].revents) {
        read_fd = pollfds[i].fd;
        write_fd = workers[i].parent_to_worker_fd[1];
        break;
      }
    }

    if (read_fd == -1 || write_fd == -1) {
      fprintf(stderr, "Polling found invalid file descriptors.\n");
      exit(1);
    }

    // Communicate with available worker.
    uint8_t opcode = 0;
    uint8_t jobCode = JOB_CODE;
    ssize_t read_bytes = read(read_fd, &opcode, 1);

    if (opcode != READY_CODE) {
      fprintf(stderr, "Invalid opcode from worker.\n");
      exit(1);
    }

    // Send job to worker.
    ssize_t written_bytes = write(write_fd, &jobCode, 1);
    ssize_t job_bytes_sent = send_job(write_fd,
        strlen(entries[i]->d_name) + 1, (uint8_t *)entries[i]->d_name);

    UNUSED(written_bytes);
    UNUSED(read_bytes);
    UNUSED(job_bytes_sent);
  }

  // Terminate worker threads.
  int workersLeft = workerCount;
  while (workersLeft > 0) {
    // Poll for ready worker.
    for (int i = 0; i < workerCount; i++) {
      pollfds[i].events = POLLIN | POLLPRI;
      pollfds[i].revents = 0;
    }

    if (poll(pollfds, workerCount, -1) == -1) {
      err(EX_OSERR, "poll error");
      exit(1);
    }

    int read_fd = -1;
    int write_fd = -1;
    for (int i = 0; i < workerCount; i++) {
      if (pollfds[i].revents) {
        read_fd = pollfds[i].fd;
        write_fd = workers[i].parent_to_worker_fd[1];
        break;
      }
    }

    if (read_fd == -1 || write_fd == -1) {
      fprintf(stderr, "Polling found invalid file descriptors.\n");
      exit(1);
    }

    // Send opcode to mark that jobs are done and worker should terminate.
    uint8_t opcode = 0;
    uint8_t terminateCode = TERMINATE_CODE;
    ssize_t read_bytes = read(read_fd, &opcode, 1);
    ssize_t written_bytes = write(write_fd, &terminateCode, 1);

    UNUSED(written_bytes);
    UNUSED(read_bytes);

    if (opcode != READY_CODE) {
      fprintf(stderr, "Invalid opcode from worker.\n");
      exit(1);
    }

    workersLeft--;
  }

  free(workers);
  free(pollfds);
  printf("done; press something to continue\n");
  char w;
  scanf("%c", &w);
  return 0;
}

