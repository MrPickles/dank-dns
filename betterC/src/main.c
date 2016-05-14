#include <dirent.h>
#include <err.h>
#include <inttypes.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <sys/stat.h>

#include "packetHandle.h"
#include "protocol.h"
#include "util.h"
#include "worker.h"
#include "optparser.h"

int main(int argc, char *argv[]) {
  
  int workerCount = -1;
  char **files;
  int numEntries;

  optparser(argc, argv, &workerCount, &files, &numEntries);

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

    // Spawn worker processes.
    if ((workers[i].pid = fork()) < 0) {
      perror("fork() failed");
      exit(1);
    }

    if (workers[i].pid == 0) { // is child process
      worker_job(&workers[i]);
      exit(0); // once worker is done, exit immediately
    }
  }

  // Dispatch all jobs.
  for (int i = 0; i < numEntries; i++) {
    struct stat path_stat;
    stat(files[i], &path_stat);
    if (!S_ISREG(path_stat.st_mode)) {
      continue; // if not regular file, skip
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
        strlen(files[i]) + 1, (uint8_t *)files[i]);

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

