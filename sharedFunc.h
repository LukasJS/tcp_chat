
/* 	
 *  	sharedFuncs.h
 *  	Lukas Suess
 *  	program2
*/


#ifndef __SHARED_H__
#define __SHARED_H__

//function declarations
int sendInitPacket(int socketNum, char *header);
int packetType(uint8_t *buf);

//chat header
struct chat_header
{
    uint16_t pduLen;
    uint8_t flag;
} __attribute__ ((__packed__));

//Holds the handles in the dynamic table
struct handleBuff
{
    uint8_t h_buff[100];
} __attribute__ ((__packed__));

//Init packet
struct init_header
{
    uint16_t pduLen;
    uint8_t flag;
    uint8_t h_len;
} __attribute__ ((__packed__));

//chat header
struct message_header
{
    uint16_t pduLen;
    uint8_t flag;
    uint8_t send_hand_len;
    uint8_t send_handle[100];
    uint8_t num_dest;
    uint8_t dest_hand_len[9];
    uint8_t dest_handle[900];
    uint8_t text[200];
} __attribute__ ((__packed__));

#endif
