#ifndef SR_H
#define SR_H

#include <stdbool.h>
#include "gbn.h"

#define RTT 16.0
#define WINDOWSIZE 6
#define SEQSPACE 7
#define NOTINUSE (-1)

/* Function declarations */
int ComputeChecksum(struct pkt packet);
bool IsCorrupted(struct pkt packet);

/* Sender (A) functions */
void A_output(struct msg message);
void A_input(struct pkt packet);
void A_timerinterrupt(void);
void A_init(void);

/* Receiver (B) functions */
void B_output(struct msg message);
void B_input(struct pkt packet);
void B_timerinterrupt(void);
void B_init(void);

#endif