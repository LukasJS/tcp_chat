/******************************************************************************
* tcp_server.c
*
* CPE 464 - Program 1
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

#include "networks.h"
#include "sharedFunc.h"

#define MAXBUF 3500
#define DEBUG_FLAG 1

void recvFromClient(int clientSocket);
int checkArgs(int argc, char *argv[]);
void initSetup(uint8_t *packet, int clientSocket);
void checkNewClient(int serverSocket, int *numSocket, fd_set* temp_sock_set);
void serviceClients(int serverSocket);
int getSockNum(uint8_t* handle, uint8_t d_handLen);
void sendListAmount(int clientSocket);
void sendListDone(int clientSocket);
void sendListHandles(int clientSocket, int index, uint8_t* clientHandle);
void initTable(void);
void exitClient(int clientSocket);

/* Global Variables */
int numHandles = 0;
int maxClientSocket = 4;
fd_set socket_set;
struct handleBuff *client_table;

int main(int argc, char *argv[])
{
	int serverSocket = 0;   //socket descriptor for the server socket
	int portNumber = 0;
	client_table = (struct handleBuff*) malloc(10*sizeof(struct handleBuff));
	//initTable();
	portNumber = checkArgs(argc, argv);

	//create the server socket
	serverSocket = tcpServerSetup(portNumber);
  serviceClients(serverSocket);

	return 0;
}

void initTable(){
		int i;
		for(i = 0; i < 100; i++){
			memset(client_table[i].h_buff, 0, 100);
		}
}
//Checks if there is a new client to accept
//And accepts it.
void checkNewClient(int serverSocket, int *numSocket, fd_set* temp_sock_set){
   int clientSocket;
   if(FD_ISSET(serverSocket, temp_sock_set)){
       if((clientSocket = tcpAccept(serverSocket, 1)) < 0){
           perror("Accept call");
           exit(-1);
       }
			 printf("ClientSocket: %d\n", clientSocket);
       if(clientSocket >= *numSocket){
           *numSocket = clientSocket + 1;
       }

       FD_SET(clientSocket, &socket_set);
       //handle the clients packet
       recvFromClient(clientSocket);
   }
}

//called in main after the server setup
//loops inside for sending packets
void serviceClients(int serverSocket){
    int numSocket;
    int loopSocket;
    fd_set temp_sock_set;

    numSocket = serverSocket + 1;
    FD_SET(serverSocket, &socket_set);

    if(listen(serverSocket, 100) < 0){
        perror("Listen call");
        exit(-1);
    }

    while(1){
        temp_sock_set = socket_set;

        if(select(numSocket, &temp_sock_set, NULL, NULL, NULL) < 0){
            perror("Select call");
            exit(-1);
        }

        //Check if the server socket needs to add a new client
        checkNewClient(serverSocket, &numSocket, &temp_sock_set);

        for(loopSocket = 0; loopSocket < maxClientSocket+1; loopSocket++){
            if(loopSocket != serverSocket && FD_ISSET(loopSocket, &temp_sock_set)){
                recvFromClient(loopSocket);
            }
        }
    }

}


void errorProcess(uint8_t* handle, uint8_t len, int socketNum){
    uint8_t packet[MAXBUF];
    uint8_t off = sizeof(struct chat_header);
    struct chat_header *head = (struct chat_header*)packet;
    int sent;

    head->pduLen = len + sizeof(struct chat_header) + 1;
    head->flag = 7;
    memcpy(packet+off, &len, sizeof(uint8_t));
    off += 1;

    memcpy(packet+off, handle, len);
    sent = send(socketNum, packet, head->pduLen, 0);
    if(sent < 0){
        perror("send call");
        exit(-1);
    }
}

void forwardMsg(uint8_t* packet, int s_clientSocket){
    uint16_t off = 0;
    uint8_t cHandLen;
    uint8_t totHandles;
    int loop;
    uint8_t destLen;
    uint16_t pduLen;
    uint8_t loopHand[101];
    int destSocket;
    int sent;

    //struct chat_header* head = (struct chat_header*)packet;

    memcpy(&pduLen, packet, sizeof(uint16_t));
    off+= sizeof(struct chat_header);

    memcpy(&cHandLen, packet+off, sizeof(uint8_t));
    off += cHandLen + sizeof(uint8_t);
        memcpy(&totHandles, packet+off, sizeof(uint8_t));
    off += sizeof(uint8_t);

    for(loop = 0; loop < totHandles; loop++){
        memcpy(&destLen, packet+off, sizeof(uint8_t));
        off += sizeof(uint8_t);

        memcpy(loopHand, packet+off, destLen);
        off += destLen;
        destSocket = getSockNum(loopHand, destLen);

        if(destSocket == -1){
            //Respond with error packet
            errorProcess(loopHand, destLen, s_clientSocket);
        } else {

            sent = send(destSocket, packet, pduLen, 0);
            if(sent < 0){
                perror("good packet send call");
                exit(-1);
            }
        }
    }
}

int getSockNum(uint8_t* handle, uint8_t d_handLen){
    int i;
    for(i = 0; i < 100; i++){
        int len = strlen((char*)client_table[i].h_buff);
				printf("sock Handle Len: %d\n", len);
        if((memcmp(client_table[i].h_buff, handle, d_handLen) == 0) && (d_handLen == len)){
            return i;
        }
    }
    return -1;
}

void forwardBrod(uint8_t* buf, int clientSocket){
    int i;
    int sent;
    uint16_t pduLen = *(buf);
    uint8_t emptyBlock[100];
    memset(emptyBlock, 0, 100);
    for(i = 0; i < 100; i++){
        if((i != clientSocket) && (client_table[i].h_buff[0] > 20)) {
            sent = send(i, buf, pduLen, 0);
            if(sent < 0){
                perror("send call");
                exit(-1);
            }
        }
    }
}

void listResponse(int clientSocket){
		int index;
		int handles_sent = 0;
		sendListAmount(clientSocket);

		for(index = 4; index < maxClientSocket; index++){
			if((uint8_t)client_table[index].h_buff[0] != 0){
					sendListHandles(clientSocket, index, client_table[index].h_buff);
					handles_sent++;
					printf("handles_sent: %d\n\n", handles_sent);
			}
		}
		sendListDone(clientSocket);
}

void sendListHandles(int clientSocket, int index, uint8_t* clientHandle){
		uint8_t packet[MAXBUF];
		int sent;
		int handleLen;

		struct chat_header *head = (struct chat_header*)packet;
		head->flag = 12;
		handleLen = strlen((char*)client_table[index].h_buff);
		printf("List Handle: %s\n", (char*)client_table[index].h_buff);
		printf("List Handle Len: %d\n", handleLen);

		head->pduLen = sizeof(struct chat_header) + sizeof(uint8_t) + handleLen;

		memcpy(packet+sizeof(struct chat_header), &handleLen, sizeof(uint8_t));
		memcpy(packet+sizeof(struct chat_header)+sizeof(uint8_t), client_table[index].h_buff, handleLen);
    sent = send(clientSocket, packet, head->pduLen, 0);
		printf("Amount sent: %d\n", sent);
    if(sent < 0){
        perror("send call");
        exit(-1);
    }
}

void sendListAmount(int clientSocket){
		uint8_t packet[MAXBUF];
		int sent;

		//Send flag = 11 packet
    struct chat_header *head = (struct chat_header*)packet;
    head->flag = 11;
    head->pduLen = sizeof(struct chat_header) + sizeof(uint8_t);

		memcpy(packet+sizeof(struct chat_header), &numHandles, sizeof(uint8_t));
		sent = send(clientSocket, packet, head->pduLen, 0);
		if(sent < 0){
				perror("send call");
				exit(-1);
		}
}

void sendListDone(int clientSocket){
		uint8_t packet[MAXBUF];
		int sent;

		//Send done packet
    struct chat_header *head = (struct chat_header*)packet;
    head->flag = 13;
    head->pduLen = sizeof(struct chat_header);
    sent = send(clientSocket, packet, head->pduLen, 0);
		printf("Send List Done amount: %d\n", sent);
    if(sent < 0){
        perror("send call");
         exit(-1);
    }
}


/*
void listResponse(int clientSocket){
    uint8_t packet[MAXBUF];
    int sent;
    uint8_t len;
    int i;
    //Send flag = 11 packet
    struct chat_header *head = (struct chat_header*)packet;
    head->flag = 11;
    head->pduLen = sizeof(struct chat_header) + sizeof(uint8_t);

    memcpy(packet+sizeof(struct chat_header), &numHandles, sizeof(uint8_t));
    sent = send(clientSocket, packet, head->pduLen, 0);
    if(sent < 0){
        perror("send call");
        exit(-1);
    }

    //Send a packet per handle known
    for(i = 0; i < 100; i++){
        head->flag = 12;
        len = strlen((char*)client_table[i].h_buff);
        head->pduLen = sizeof(struct chat_header) + sizeof(uint8_t) + len;

        if((client_table[i].h_buff[0] > 20)) {

            memcpy(packet+sizeof(struct chat_header), &len, sizeof(uint8_t));
            memcpy(packet+sizeof(struct chat_header)+sizeof(uint8_t), client_table[i].h_buff, len);
            sent = send(clientSocket, packet, head->pduLen, 0);
            if(sent < 0){
                perror("send call");
                exit(-1);
            }
        }
    }

    //Send done packet
    head->flag = 13;
    head->pduLen = sizeof(struct chat_header);
    sent = send(clientSocket, packet, head->pduLen, 0);
    if(sent < 0){
        perror("send call");
         exit(-1);
    }

}
*/
void exitResponse(int clientSocket){
    uint8_t packet[MAXBUF];
    int sent;
    struct chat_header *head = (struct chat_header*)packet;

    head->flag = 9;
    head->pduLen = sizeof(struct chat_header);

    //memcpy(client_table[clientSocket].h_buff, "\0", 100);
    sent = send(clientSocket, packet, sizeof(struct chat_header), 0);
		printf("Sent: %d\n", sent);
    if(sent < 0){
        perror("good packet send call");
        exit(-1);
    }


}

void exitClient(int clientSocket){
		memset(client_table[clientSocket].h_buff, 0, 100);
		numHandles--;
}

//grabs the packet then checks the flag and calls appropriate
//function.
void recvFromClient(int clientSocket)
{

		int flag;
		uint8_t buf[MAXBUF];
		int messageLen = 0;

		//now get the data from the client socket
		if ((messageLen = recv(clientSocket, buf, MAXBUF, 0)) < 0)
		{
				perror("recv call");
				exit(-1);
		}
		//printf("Message Len Recieved: %d\n", messageLen);
		if(messageLen == 0) {
				exitClient(clientSocket);
		} else {
        flag = *(buf+sizeof(uint16_t));
				printf("Flag Recieved: %d\n", flag);
        if(flag == 1){
            //INIT
            initSetup(buf, clientSocket);
        } else if(flag == 4){
            //Broadcast
            forwardBrod(buf, clientSocket);
        }else if(flag == 5){
            //Message
            forwardMsg(buf, clientSocket);
        }else if(flag == 8){
            //Exit
            exitResponse(clientSocket);
        }else if(flag == 10){
            //List
            listResponse(clientSocket);
        } else {
            //Disconnect the client
						return;
        }
		}
}

int checkArgs(int argc, char *argv[])
{
	// Checks args and returns port number
	int portNumber = 0;

	if (argc > 2)
	{
		fprintf(stderr, "Usage %s [optional port number]\n", argv[0]);
		exit(-1);
	}

	if (argc == 2)
	{
		portNumber = atoi(argv[1]);
	}

	return portNumber;
}

int checkHandle(uint8_t *client_handle, int handleLen){
    int loopHandle;
    for(loopHandle = 0; loopHandle < 100; loopHandle++){
        if(memcmp(client_handle, client_table[loopHandle].h_buff, handleLen) == 0){
            return 0;
        }
    }
    return 1;
}

void sendResponse(int clientSocket, int flag){
    int sent;
    uint8_t packet[MAXBUF];
    struct chat_header goodPacket;
    goodPacket.pduLen = sizeof(struct chat_header);
    goodPacket.flag = flag;
    memcpy(packet, &goodPacket, sizeof(struct chat_header));
    sent = send(clientSocket, packet, sizeof(struct chat_header), 0);
    if(sent < 0){
        perror("good packet send call");
        exit(-1);
    }
}

void initSetup(uint8_t *packet, int clientSocket){
    uint8_t handleLen = 100;
    uint8_t client_handle[100];
		memset(client_handle, 0, 100);
    //Grab handle from packet
    memcpy(&handleLen, packet + sizeof(struct chat_header), sizeof(uint8_t));
    memcpy(client_handle, packet + sizeof(struct chat_header) + 1, handleLen);

    if(checkHandle(client_handle, handleLen) == 1){
        //Check and realloc dynamic table
        if((numHandles % 10) == 0){
            client_table = realloc(client_table, sizeof(struct handleBuff)*(numHandles + 10));
						printf("Increase client_table size.\n");
        }
        memcpy(client_table[clientSocket].h_buff, client_handle, sizeof(uint8_t)*100);
        numHandles++;
				maxClientSocket++;
				printf("Incerment Handle and Socket: %d\n", numHandles);
        //Send success packet flag = 2
        sendResponse(clientSocket, 2);
    } else {
        //Send error packet flag = 3
        sendResponse(clientSocket, 3);
    }
}
