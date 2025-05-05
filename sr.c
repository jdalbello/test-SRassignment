#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "sr.h"

int ComputeChecksum(struct pkt packet)
{
  int checksum = 0;
  int i;

  checksum = packet.seqnum;
  checksum += packet.acknum;
  for ( i=0; i<20; i++ )
    checksum += (int)(packet.payload[i]);

  return checksum;
}

bool IsCorrupted(struct pkt packet)
{
  if (packet.checksum == ComputeChecksum(packet))
    return (false);
  else
    return (true);
}


/********* Sender (A) variables and functions ************/
static struct pkt buffer[WINDOWSIZE];  /* array for storing packets waiting for ACK */
static int windowfirst, windowlast;    /* array indexes of the first/last packet awaiting ACK */
static int windowcount;                /* the number of packets currently awaiting an ACK */
static int A_nextseqnum;               /* the next sequence number to be used by the sender */

/* New bool variable to track if packet has been ACKed */
static bool ackStatus[WINDOWSIZE];

/* called from layer 5 (application layer), passed the message to be sent to other side */
void A_output(struct msg message)
{
  struct pkt sendpkt;
  int i;

  /* if not blocked waiting on ACK */
  if ( windowcount < WINDOWSIZE) {
    if (TRACE > 1)
      printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");

    /* create packet */
    sendpkt.seqnum = A_nextseqnum;
    sendpkt.acknum = NOTINUSE;
    for ( i=0; i<20 ; i++ )
      sendpkt.payload[i] = message.data[i];
    sendpkt.checksum = ComputeChecksum(sendpkt);

    /* put packet in window buffer */
    windowlast = (windowlast + 1) % WINDOWSIZE;
    buffer[windowlast] = sendpkt;
    ackStatus[windowlast] = false; /* Marks the packet as unACKed*/
    windowcount++;

    /* send out packet */
    if (TRACE > 0)
      printf("Sending packet %d to layer 3\n", sendpkt.seqnum);
    tolayer3 (A, sendpkt);

    /* start timer if first packet in window */
    if (windowcount == 1)
      starttimer(A,RTT);

    /* get next sequence number, wrap back to 0 */
    A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
  }
  /* if blocked,  window is full */
  else {
    if (TRACE > 0)
      printf("----A: New message arrives, send window is full\n");
    window_full++;
  }
}


/* called from layer 3, when a packet arrives for layer 4
   In this practical this will always be an ACK as B never sends data.
*/
void A_input(struct pkt packet)
{
  int i;
  int ackedSeq;
  
  /* if received ACK is not corrupted */
  if (!IsCorrupted(packet)) {
    if (TRACE > 0)
      printf("----A: uncorrupted ACK %d is received\n",packet.acknum);
    total_ACKs_received++;

    /* extract acknowledgement number from received packet to local variable */
    ackedSeq = packet.acknum;

    /* find which buffer position contains the sequence number */
    for(i = 0; i < WINDOWSIZE; i++) {
      if(buffer[i].seqnum == ackedSeq && !ackStatus[i]) {
        /* mark current packet as ACKed */
        ackStatus[i] = true;
        new_ACKs++;

        /* push window forwards over all ACKed packets at the start of window */
        while(windowcount > 0 && ackStatus[windowfirst]) {
          windowfirst = (windowfirst + 1) % WINDOWSIZE;
          windowcount--;
        }

        /* restart timer if unACKed packets still exist */
        stoptimer(A);
        if(windowcount > 0)
          starttimer(A, RTT);

        break;
      }
    }
  } else {
    if (TRACE > 0)
      printf("----A: corrupted ACK is received, do nothing!\n");
  }
}

/* called when A's timer goes off */
void A_timerinterrupt(void)
{
  int i;
  
  if (TRACE > 0)
    printf("----A: time out, resend unACKed packets!\n");

  /* resend unACKed packets in window */
  for(i = 0; i < windowcount; i++) {
    int currentPosition = (windowfirst + i) % WINDOWSIZE;
    if(!ackStatus[currentPosition]) {
      if(TRACE > 0)
        printf("---A: resending packet %d\n", buffer[currentPosition].seqnum);
      tolayer3(A, buffer[currentPosition]);
      packets_resent++;
    }
  }

  /* restart the timer */
  stoptimer(A);
  if (windowcount > 0)
    starttimer(A, RTT);
}

/* the following routine will be called once (only) before any other */
/* entity A routines are called. You can use it to do any initialization */
void A_init(void)
{
  int i;
  
  /* initialise A's window, buffer and sequence number */
  A_nextseqnum = 0;  /* A starts with seq num 0, do not change this */
  windowfirst = 0;
  windowlast = -1;   /* windowlast is where the last packet sent is stored.
                     new packets are placed in winlast + 1
                     so initially this is set to -1
                   */
  windowcount = 0;

  /* initialise ackStatus array to false to track ACK status per packet */
  for(i = 0; i < WINDOWSIZE; i++) {
    ackStatus[i] = false;
  }
}

/********* Receiver (B)  variables and procedures ************/

static int expectedseqnum; /* the sequence number expected next by the receiver */
static int B_nextseqnum;   /* the sequence number for the next packets sent by B */
static struct pkt outOfOrderBuffer[WINDOWSIZE]; /* buffer for out of order packets */

/* called from layer 3, when a packet arrives for layer 4 at B*/
void B_input(struct pkt packet)
{
  struct pkt sendpkt;
  int i;
  int seqnum;
  int windowOffset;

  if(!IsCorrupted(packet)) {
    seqnum = packet.seqnum;

    /* send ACK for current packet */
    sendpkt.acknum = seqnum;
    sendpkt.seqnum = B_nextseqnum;
    B_nextseqnum = (B_nextseqnum + 1) % 2;

    for(i = 0; i < 20; i++)
      sendpkt.payload[i] = '0';
    sendpkt.checksum = ComputeChecksum(sendpkt);
    tolayer3(B, sendpkt);

    /* check if packet is the expected one */
    if(seqnum == expectedseqnum) {
      if(TRACE > 0)
        printf("----B: packet %d is correctly received, deliver to layer5!\n",seqnum);
      packets_received++;
      
      /* deliver to layer 5 */
      tolayer5(B, packet.payload);
      expectedseqnum = (expectedseqnum + 1) % SEQSPACE;
      
      /* check if next packets are in buffer */
      while(1) {
        int found = 0;
        for(i = 0; i < WINDOWSIZE; i++) {
          if(outOfOrderBuffer[i].seqnum == expectedseqnum) {
            if(TRACE > 1)
              printf("----B: delivering buffered packet %d\n", expectedseqnum);
            tolayer5(B, outOfOrderBuffer[i].payload);
            outOfOrderBuffer[i].seqnum = -1; /* mark as empty */
            expectedseqnum = (expectedseqnum + 1) % SEQSPACE;
            found = 1;
            break;
          }
        }
        if(!found) break;
      }
    } 
    /* handle packets that are out of order but within window */
    else {
      windowOffset = (seqnum - expectedseqnum + SEQSPACE) % SEQSPACE;
      if(windowOffset < WINDOWSIZE) {
        if(TRACE > 0)
          printf("----B: out of order packet %d received, buffering\n",seqnum);
        
        /* search for empty slot in out of order buffer */
        for(i = 0; i < WINDOWSIZE; i++) {
          if(outOfOrderBuffer[i].seqnum == -1) {
            outOfOrderBuffer[i] = packet;
            break;
          }
        }
      } else {
        if(TRACE > 0)
          printf("----B: packet %d outside window, ignoring\n", seqnum);
      }
    }
  } else {
    if(TRACE > 0)
      printf("----B: corrupted packet received, ignoring.\n");
  }
}

/* the following routine will be called once (only) before any other */
/* entity B routines are called. You can use it to do any initialization */
void B_init(void)
{
  int i;

  expectedseqnum = 0;
  B_nextseqnum = 1;

  /* initialise buffer to handle out of order packets */
  for(i = 0; i < WINDOWSIZE; i++) {
    /* mark all array entries as empty */
    outOfOrderBuffer[i].seqnum = -1;
  }
}

/* Unused functions for unidirectional transfer */
void B_output(struct msg message) {}
void B_timerinterrupt(void) {}