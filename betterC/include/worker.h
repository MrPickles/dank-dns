#ifndef WORKER_H
#define WORKER_H

typedef struct {
  int parent_to_worker_fd[2];
  int worker_to_parent_fd[2];
  int index;
} worker_t;

void *worker_job(void *args);

#endif

