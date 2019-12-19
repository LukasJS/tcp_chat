/******************************************************************************
* myClient.c
* Program1
* Lukas Suess
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

#define MAXBUF 3500
#define DEBUG_FLAG 1
#define xstr(a) str(a)
#define str(a) #a


int recvFromServer(int socketNum, uint8_t* buffer);
//void sendToServer(int socketNum, int flag);
void sendToServer(int socketNum, uint8_t* packet, int sendLen);
void checkArgs(int argc, char * argv[]);
void initProcess(int socketNum, char* handle);
int sendInitPacket(int socketNum, char* header);
void userInput(int socketNum, char* handle);
void grabInput(fd_set *fileSet, char* buf, int socketNum, char* handle);
void messageProcess(int socket_num, char* input, char* handle);
void inputType(char inType, char* input, int socketNum, char* handle,
   fd_set* fileSet);
void getPacket(int socketNum);
uint8_t messagePacket(uint16_t pduLen, uint8_t totHandles, uint8_t* handLengths,
   char** handlesArr, char* token, char* handle, uint8_t* packet);
void printListPackets(int socketNum, uint8_t* packet);
void rcvExit(int socketNum);

int main(int argc, char * argv[])
{
  char *handle = argv[1];
	int socketNum = 0;         //socket descriptor

	checkArgs(argc, argv);

	/* set up the TCP Client socket  */
	socketNum = tcpClientSetup(argv[2], argv[3], DEBUG_FLAG);

	initProcess(socketNum, handle);
	//Get user input and send the appropriate packet
	userInput(socketNum, handle);

	close(socketNum);

	return 0;
}


//Skip past the instruction string and grab the total handles val.
char* parseInput(char* input){
    char* token;
    strtok(input, " ");
    token = strtok(NULL, " ");
    return token;
}

uint8_t makeHandArr(uint8_t* totHandles, uint8_t* handLengths,
 char** handlesArr, char* token){
    uint8_t dataLen = 0;
    int countHandles;

    if(*totHandles == 0){
       *totHandles = 1;
       handLengths[0] = strlen(token);
       handlesArr[0] = token;
       dataLen = handLengths[0] + sizeof(uint8_t);
       return dataLen;
    }
    for(countHandles = 0; countHandles < *totHandles; countHandles++){
        token = strtok(NULL, " ");
        //Handle string
        if(token == NULL){
            return -1;
        }
        handlesArr[countHandles] = token;
        //Handle length value
        handLengths[countHandles] = strlen(token);
        dataLen += handLengths[countHandles] + sizeof(uint8_t);
    }

    if(countHandles != *totHandles){
        return -1;
    }
    return dataLen;
}


void messageProcess(int socketNum, char* input, char* handle){
    uint16_t pduLen = sizeof(struct chat_header);
    uint8_t c_handLen = (uint8_t)strlen(handle);
    char* token;
    uint8_t totHandles;
    uint8_t handLengths[100];
    char* handlesArr[100];
    uint8_t dataLen = 0;
    uint8_t packet[MAXBUF];
    uint8_t offset = 0;
    char* txt;

    //Keep track of pdu length as we add data.
    pduLen += sizeof(uint8_t);
    pduLen += c_handLen;

    token = parseInput(input);
    totHandles = atoi(token);
    pduLen += sizeof(uint8_t);
    if(token == NULL){
       printf("Invalid command\n");
       return;
    }
    //Make arrays of lengs and strings and return bytes necessary
    dataLen = makeHandArr(&totHandles, handLengths, handlesArr, token);
    if(dataLen == -1){
        printf("Invalid Command\n");
        return;
    }
    pduLen += dataLen;

    txt = strtok(NULL, "\0");
    if(txt == NULL){
        printf("Invalid command\n");
        return;
    }
    pduLen += strlen(txt);
    offset = messagePacket(pduLen, totHandles, handLengths,
       handlesArr, token, handle, packet);


    memcpy(packet+offset, txt, strlen(txt));
    sendToServer(socketNum, packet, pduLen);
}

void inputDestHandle(uint8_t* packet, uint16_t* offset, uint8_t totHandles,
   uint8_t* handLengths, char** handlesArr){
    uint8_t len;
    int t;
    for(t = 0; t < totHandles; t++){
        len = handLengths[t];
        memcpy(packet + *offset, &len, sizeof(uint8_t));
        *offset += 1;
        memcpy(packet + *offset, handlesArr[t], len);
        *offset += len;
    }

}

uint8_t messagePacket(uint16_t pduLen, uint8_t totHandles, uint8_t* handLengths,
   char** handlesArr, char* token, char* handle, uint8_t* packet){
    uint8_t flag = 5;
    uint16_t len = pduLen;
    uint8_t c_handLen;
    uint16_t offset = 0;

    memcpy(packet, &len, sizeof(uint16_t));
    offset+=2;
    memcpy(packet+offset, &flag, sizeof(uint8_t));
    offset+=1;
    c_handLen = strlen(handle);
    memcpy(packet+offset, &c_handLen, sizeof(uint8_t));
    offset+=1;
    memcpy(packet+offset, handle, c_handLen *sizeof(uint8_t));
    offset+=c_handLen;

    memcpy(packet+offset, &totHandles, sizeof(uint8_t));
    offset+=1;
    //Loops through handles and adds length and string of handles.
    inputDestHandle(packet, &offset, totHandles, handLengths, handlesArr);

    return offset;
}


void broadProcess(int socketNum, char* input, char* handle){
    char* token;
    uint8_t packet[MAXBUF];
    uint16_t off = 0;
    uint16_t pduLen;
    uint8_t flag = 4;

    uint8_t c_handLen = strlen(handle);
    off+= sizeof(struct chat_header);

    memcpy(packet+off, &c_handLen, sizeof(uint8_t));
    off += sizeof(uint8_t);

    memcpy(packet+off, handle, c_handLen);
    off += c_handLen;

    strtok(input, " ");
    token = strtok(NULL, "\0");
    if(token == NULL){
        token = "";
    }
    memcpy(packet+off, token, strlen(token));

    pduLen = sizeof(struct chat_header) + sizeof(uint8_t) + c_handLen
+ strlen(token);
    memcpy(packet, &pduLen, sizeof(uint16_t));
    memcpy(packet+2, &flag, sizeof(uint8_t));

    sendToServer(socketNum, packet, pduLen);
}

void printListPackets(int socketNum, uint8_t* packet){
    uint8_t flag = 0;
    uint16_t numHandles;
    uint8_t handLen;
    uint8_t packetLen[2];

    numHandles = *(packet+sizeof(struct chat_header));
    flag = *(packet+sizeof(uint16_t));

    printf("Number of clients: %d\n", numHandles);
    int count = 0;
	  for(count = 0; count < numHandles; count++) {
    //flag = 12;
    //while(flag == 12){
        //printf("PacketLen recv\n");
        printf("RECV Return Len: %d\n", (int)recv(socketNum, packetLen, 2, MSG_PEEK));

        uint8_t packetBuf[(size_t)*packetLen];
        printf("packetLen Recieved: %d\n", (int)*packetLen);
        printf("RECV Return: %d\n", (int)recv(socketNum, packetBuf, (size_t)packetLen, 0));

        flag = *(packetBuf+sizeof(uint16_t));
        handLen = *(packetBuf+sizeof(struct chat_header));
        printf("Flag: %d", flag);
        //printf("%d %.*s\n", count, handLen, packet+4);
        if(flag == 12){
            printf(" %.*s\n", handLen, packetBuf+4);
        }
    }
}

void listProcess(int socketNum){
    uint16_t pduLen;
    uint8_t flag;
    uint8_t packet[MAXBUF];

    pduLen = sizeof(struct chat_header);
    flag = 10;

    memcpy(packet, &pduLen, sizeof(uint16_t));
    memcpy(packet+2, &flag, sizeof(uint8_t));

    sendToServer(socketNum, packet, pduLen);

    //printListPackets(socketNum);
}

void exitProcess(int socketNum, fd_set* fileSet){
    uint8_t packet[MAXBUF];
    uint8_t flag;
    uint16_t pduLen = sizeof(struct chat_header);
    flag = 8;

    memcpy(packet+sizeof(uint16_t), &flag, sizeof(uint8_t));
    memcpy(packet, &pduLen, sizeof(uint16_t));
    sendToServer(socketNum, packet, sizeof(struct chat_header));
}

void inputType(char inType, char* input, int socketNum, char* handle,
   fd_set *fileSet){
    if(inType == 'M' || inType == 'm'){
        messageProcess(socketNum, input, handle);

    } else if(inType == 'B' || inType == 'b'){
        broadProcess(socketNum, input, handle);

    } else if(inType == 'L' || inType == 'l'){
        listProcess(socketNum);

    } else if(inType == 'E' || inType == 'e'){
        exitProcess(socketNum, fileSet);

    } else {
        printf("Invalid command\n");
        return;
    }

}

void grabInput(fd_set *fileSet, char* buf, int socketNum, char* handle){
    if(FD_ISSET(STDIN_FILENO, fileSet)){
        fgets(buf, MAXBUF, stdin);
        if(FD_ISSET(STDIN_FILENO, fileSet)){
            if(buf[0] == '%'){
                //Determines type of command and calls appropriate handler
                inputType(buf[1], buf, socketNum, handle, fileSet);
            }else {
                printf("Invalid Command\n");
            }
        }
    }
}

void userInput(int socketNum, char* handle){
    char buf[MAXBUF];
    fd_set fileSet;

    while(1){
        printf("$: ");
        fflush(stdout);
        FD_SET(socketNum, &fileSet);
        FD_SET(STDIN_FILENO, &fileSet);
        if(select(socketNum+1, &fileSet, NULL, NULL, NULL) < 0){
            perror("select call");
            exit(-1);
        }
        grabInput(&fileSet, buf, socketNum, handle);
        if(FD_ISSET(socketNum, &fileSet)){
            getPacket(socketNum);
        }
    }
}

uint16_t skipDestHandles(int numHandles, uint8_t* packet, uint16_t off){
    int i;
    uint8_t handleLen = 0;
    for(i = 0; i < numHandles; i++){
         memcpy(&handleLen, packet+off, sizeof(uint8_t));
         off += sizeof(uint8_t) + handleLen;
    }
    return off;
}

void rcvMessage(uint8_t* packet){
    uint8_t numHandles;
    uint16_t pduLen;
    uint16_t off = 0;
    uint8_t senderHandLen;
    uint8_t* handle;
    int textLen = 0;

    pduLen = *(packet);
    off += sizeof(struct chat_header);
    senderHandLen = *(packet+off);
    off += sizeof(uint8_t);

    handle = packet+off;
    off += senderHandLen;

    numHandles = *(packet+off);
    off += sizeof(uint8_t);


    int i;
    uint8_t handleLen = 0;
    for(i = 0; i < numHandles; i++){
         handleLen = *(packet+off);
         off += sizeof(uint8_t) + handleLen;
    }

    textLen = pduLen - off;

    printf("\n%.*s: ", senderHandLen, handle);
    printf("%.*s", textLen, packet+off);

}

void rcvBroadcast(uint8_t* packet){
    uint16_t pduLen;
    uint16_t off = 0;
    uint8_t c_handLen;
    int txtSize;
    uint8_t* clientName;


    pduLen = *(packet);
    off += sizeof(struct chat_header);

    c_handLen = *(packet+off);
    off += sizeof(uint8_t);

    clientName = packet+off;
    off += c_handLen;

    txtSize = pduLen - c_handLen - sizeof(struct chat_header) - sizeof(uint8_t);
    printf("\n%.*s: ", c_handLen, clientName);
    printf("%.*s", txtSize, packet+off);
}

void rcvError(uint8_t* packet){
    uint8_t handLen;
    uint16_t pduLen;
    uint8_t off = sizeof(struct chat_header) + 1;
    pduLen = *(packet);
    handLen = pduLen - sizeof(struct chat_header) - sizeof(uint8_t);
    printf("\nClient with handle %.*s does not exist\n", handLen, packet+off);

}

void rcvExit(int socketNum){
    //Flag already checked.Just exit.
    close(socketNum);
    exit(0);
}

void getPacket(int socketNum){
    uint8_t packet[MAXBUF];

    recvFromServer(socketNum, packet);
    struct chat_header *head = (struct chat_header*)packet;
    if(head->flag == 5){
        //Message Packet recieved
        rcvMessage(packet);
    } else if(head->flag == 4){
        //Broadcast Packet received
        rcvBroadcast(packet);
    } else if(head->flag == 7){
        //Error Packet recieved
        rcvError(packet);
    } else if(head->flag == 9){
        //Error Packet recieved
        rcvExit(socketNum);
    } else if(head->flag == 11){
        printListPackets(socketNum, packet);
    } else {
        printf("Server Terminated\n");
    }
}

void initResponse(int socketNum, char* handle){
    uint8_t packetBuf[MAXBUF];
    int flag = 0;
    //Loop until a packet of flag 2=good is received
    while(flag != 2){
        recvFromServer(socketNum, packetBuf);
        flag = packetType(packetBuf);

        if(flag == 3){
            printf("Handle already in use: %s\n", handle);
            exit(-1);
        }
    }
}

int sendInitPacket(int socketNum, char* handle){
    uint8_t packet[MAXBUF];
    int handleLen = strlen(handle);
    int sent;
    //char* hand;

    struct init_header chatStruct;
    chatStruct.pduLen = handleLen + sizeof(struct init_header);
    chatStruct.flag = 1;
    chatStruct.h_len = handleLen;

    memcpy(packet, &chatStruct, sizeof(struct init_header));
    memcpy(packet+sizeof(struct init_header), handle, handleLen);

    sent =  send(socketNum, packet, chatStruct.pduLen, 0);
    if (sent < 0)
    {
        perror("send call");
        exit(-1);
    }
    return sent;
}

void initProcess(int socketNum, char* handle)
{
    sendInitPacket(socketNum, handle);
    //Get the response packet and check it's flag.
    initResponse(socketNum, handle);

}

void checkArgs(int argc, char * argv[])
{
	/* check command line arguments  */
	if (argc != 4)
	{
		printf("usage: %s handle host-name port-number \n", argv[0]);
		exit(1);
	}
}

int recvFromServer(int socketNum, uint8_t *buffer){
	int messageLen = 0;

	//now get the data from the client socket
	if ((messageLen = recv(socketNum, buffer, MAXBUF, 0)) < 0)
	{
		perror("recv call");
		exit(-1);
	}
      return messageLen;
}

void sendToServer(int socketNum, uint8_t* packet, int sendLen)
{
  int sent;
	sent =  send(socketNum, packet, sendLen, 0);
  printf("Sent from Client: %d\n", sent);
	if (sent < 0)
	{
		perror("send call");
		exit(-1);
        }
}
