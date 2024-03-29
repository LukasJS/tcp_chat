# Makefile for CPE464 tcp test code
# written by Hugh Smith - April 2019

CC= gcc
CFLAGS= -g -Wall
LIBS = 


all:   myClient myServer

myClient: myClient.c networks.o gethostbyname6.o sharedFunc.o
	$(CC) $(CFLAGS) -o cclient myClient.c networks.o gethostbyname6.o sharedFunc.o $(LIBS)

myServer: myServer.c networks.o gethostbyname6.o sharedFunc.o
	$(CC) $(CFLAGS) -o server myServer.c networks.o gethostbyname6.o sharedFunc.o $(LIBS)

.c.o:
	gcc -c $(CFLAGS) $< -o $@ $(LIBS)

cleano:
	rm -f *.o

clean:
	rm -f myServer myClient *.o




