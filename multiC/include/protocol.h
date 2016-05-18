#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <inttypes.h>
#include <sys/types.h>

// Opcode from parent to worker announcing new job.
#define JOB_CODE       0xDF
// Opcode from worker to parent announcing ready state.
#define READY_CODE     0xCE
// Opcode from parent to worker announcing no more jobs.
#define TERMINATE_CODE 0xFB

/*
 * Sends a job to a worker thread. The parameters are the file descriptor, the
 * payload length (host byte order), and the payload to send. Although the
 * length parameter is in host byte order, it will be send in network byte order
 * by the protocol.
 */
ssize_t send_job(int fd, const uint32_t length, const uint8_t *payload);

/*
 * Receives a job from the parent. The parameters are the file descriptor, a
 * pointer to the payload length, and the memory address of a pointer to the
 * payload. The function will modify the pointer to the length, putting the
 * appropriate length in host byte order. The function will allocate memory to
 * the payload itself, which is why it needs a pointer to the payload pointer.
 * Needless to say, when calling this function, you need a integer and a
 * pointer, and you will pass the memory address of those two. You also should
 * free the payload memory yourself.
 */
ssize_t recv_job(int fd, uint32_t *length, uint8_t **payload);

#endif

