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
void checkNewClient(fd_set* temp_sock_set);
void serviceClients(void);
int getSockNum(uint8_t* handle, uint8_t d_handLen);
void serverListen(void);

/* Global Variables */
int numHandles = 0;
int serverSocket = 0;
int num_client_sockets = 0;
fd_set socket_set;
struct handleBuff *client_table;

int main(int argc, char *argv[])
{
	int portNumber = 0;
	client_table = (struct handleBuff*) malloc(10*sizeof(struct handleBuff));
	portNumber = checkArgs(argc, argv);
	
	//create the server socket
	serverSocket = tcpServerSetup(portNumber);
	
	//Listen for clients to service
	serverListen();
	
    serviceClients();
	
	return 0;
}

//Checks if there is a new client to accept
//And accepts it.
void checkNewClient(fd_set* temp_sock_set){
   int clientSocket;
   int debugFlag = 0;
   if(FD_ISSET(serverSocket, temp_sock_set)){
        clientSocket = tcpAccept(serverSocket, debugFlag); 
       
		num_client_sockets++;

        FD_SET(clientSocket, &socket_set);
        //handle the clients packet
        //recvFromClient(clientSocket);
   }  
}

//called in main after the server setup
//loops inside for sending packets
void serviceClients(){
    int i;
    fd_set temp_sock_set;
    

    FD_SET(serverSocket, &socket_set);
 

    while(1){
        temp_sock_set = socket_set;
        
        if(select(num_client_sockets, &temp_sock_set, NULL, NULL, NULL) < 0){
            perror("Select call");
            exit(-1);
        }

        //Check if the server socket needs to add a new client
        checkNewClient(&temp_sock_set);
 
        for(i = 0; i < num_client_sockets; i++){
            if(i != serverSocket && FD_ISSET(i, &temp_sock_set)){
                recvFromClient(i);
            }
        } 
    }

}

void serverListen(){
	if(listen(serverSocket, 100) < 0){
        perror("Listen call");
        exit(-1);
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
        if((memcmp(client_table[i].h_buff, handle, d_handLen) == 0) && (d_handLen == len)){
            return i;
        }
    }
    return -1;
}

void forwardBrod(uint8_t* buf, int clientSocket, int messageLen){
    int i;
    int sent;
    uint16_t pduLen = messageLen;
    
    for(i = 0; i < num_client_sockets; i++){
        if(i != clientSocket) {
            sent = send(i, buf, pduLen, 0);
            if(sent < 0){
                perror("send call");
                exit(-1);
            }
        }
    }
}

void listResponse(int clientSocket){
    uint8_t packet[MAXBUF];
    int sent;
    uint8_t len;
    int i;
    //Send flag = 11 packet
    struct chat_header *head = (struct chat_header*)packet;
    head->flag = 11;
    head->pduLen = sizeof(struct chat_header) + sizeof(uint8_t);

    //memcpy(packet, head, sizeof(chat_header));
    memcpy(packet+sizeof(struct chat_header), &numHandles, sizeof(uint8_t));
    sent = send(clientSocket, packet, head->pduLen, 0);
    if(sent < 0){
        perror("send call");
        exit(-1);
    }
    
    //Send a packet per handle known
    for(i = 0; i < num_client_sockets; i++){
        head->flag = 12;
        len = strlen((char*)client_table[i].h_buff);
        head->pduLen = sizeof(struct chat_header) + sizeof(uint8_t) + len;

        //memcpy(packet, head, sizeof(chat_header)); (Maybe need?)
        memcpy(packet+sizeof(struct chat_header), &len, sizeof(uint8_t));
        memcpy(packet+sizeof(struct chat_header)+sizeof(uint8_t), client_table[i].h_buff, len);
        sent = send(clientSocket, packet, head->pduLen, 0);
        if(sent < 0){
            perror("send call");
            exit(-1);
        }
    }

    //Send done packet
    head->flag = 13;
    head->pduLen = sizeof(struct chat_header);
    memcpy(packet, head, sizeof(struct chat_header));
    sent = send(clientSocket, packet, head->pduLen, 0);
    if(sent < 0){
        perror("send call");
         exit(-1);
    }
    
}

void exitResponse(int clientSocket){
    uint8_t packet[MAXBUF];
    int sent;
    struct chat_header *head = (struct chat_header*)packet;
    numHandles--;

    head->flag = 9;
    head->pduLen = sizeof(struct chat_header);

    memcpy(client_table[clientSocket].h_buff, "\0", 100);
    sent = send(clientSocket, packet, sizeof(struct chat_header), 0);
    if(sent < 0){
        perror("good packet send call");
        exit(-1);
    }


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
    printf("Recieved Packet socket num:%d\n", clientSocket);
    flag = packetType(buf);
        if(flag == 1){
            //INIT
            printf("INIT packet caught\n");
            initSetup(buf, clientSocket);
        } else if(flag == 4){
            //Broadcast
            forwardBrod(buf, clientSocket, messageLen);
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
    
    //Grab handle from packet
    memcpy(&handleLen, packet + sizeof(struct chat_header), sizeof(uint8_t));
    memcpy(client_handle, packet + sizeof(struct chat_header) + 1, handleLen);
    
    if(checkHandle(client_handle, handleLen) == 1){
        //Check and realloc dynamic table 
        if((num_client_sockets % 10) == 0){
            client_table = realloc(client_table, sizeof(struct handleBuff)*(num_client_sockets + 10));
        }
        memcpy(client_table[clientSocket].h_buff, client_handle, sizeof(uint8_t)*100);

        //Send success packet flag = 2
        sendResponse(clientSocket, 2);
    } else {
        //Send error packet flag = 3
        sendResponse(clientSocket, 3);
    } 
}
