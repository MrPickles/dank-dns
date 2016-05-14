#ifndef WORKER_H
#define WORKER_H

#include <pthread.h>

typedef struct {
  int parent_to_worker_fd[2];
  int worker_to_parent_fd[2];
  int index;
  pid_t pid;
} worker_t;

void worker_job(worker_t *worker);

#endif

