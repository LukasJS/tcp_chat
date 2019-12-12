/******************************************************************************
* sharedFuncs.c
*
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "sharedFunc.h"
#include "networks.h"
#include "gethostbyname6.h"

#define MAXBUF 1024
#define DEBUG_FLAG 1

int packetType(uint8_t* buf){
    uint8_t flag;
    memcpy(&flag, buf+2, sizeof(uint8_t));
    //printf("Packet Type: %d\n", flag);
    return flag;
}

void makeHeader(int pduLen, int flag, struct chat_header* ch_head){
    ch_head->flag = flag;
    ch_head->pduLen = pduLen;
}
