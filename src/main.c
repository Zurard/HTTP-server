#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

int main() {
	// Disable output buffering
	setbuf(stdout, NULL);
 	setbuf(stderr, NULL);

	// You can use print statements as follows for debugging, they'll be visible when running tests.
	printf("Logs from your program will appear here!\n");

	// Uncomment this block to pass the first stage
	//
	int server_fd, client_addr_len; // server_fd is the socket file descriptor 
	struct sockaddr_in client_addr;
	
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	printf("Socket created with the number assigned as this  =============>> %d\n", server_fd);
	if (server_fd == -1) {
		printf("Socket creation failed: %s...\n", strerror(errno));
		return 1;
	}
	
	// Since the tester restarts your program quite often, setting SO_REUSEADDR
	// ensures that we don't run into 'Address already in use' errors
	int reuse = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		printf("SO_REUSEADDR failed: %s \n", strerror(errno));
		return 1;
	}
	
	struct sockaddr_in serv_addr = { .sin_family = AF_INET ,
									 .sin_port = htons(4221),
									 .sin_addr = { htonl(INADDR_ANY) },
									};
	
	if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
		printf("Bind failed: %s \n", strerror(errno));
		return 1;
	}
	
	int connection_backlog = 5;
	if (listen(server_fd, connection_backlog) != 0) {
		printf("Listen failed: %s \n", strerror(errno));
		return 1;
	}
	
	printf("Waiting for a client to connect...\n");
	client_addr_len = sizeof(client_addr);
	
   
   int client_fd= accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_len);

	char* client_ip= inet_ntoa(serv_addr.sin_addr);
	int client_port = ntohs(serv_addr.sin_port);

	
	printf("Client connected\n" ,
		   "Client IP ================>> %s\n"
		   "Client Port ================>> %d\n",
		   client_ip, client_port);

	//Client has been connected sucessfully now we try to understand and give a response based on that 
	// URL Extraction 	   

	char buffer[1024]; // buffer is of 1KB (due to mostly all headers fit inside it)
    int request_recieved = read(client_fd,buffer,sizeof(buffer)-1);
	buffer[request_recieved] = '\0'; 

    //this is the actual request : ------------>>
	printf("the HTTP request is given as %s" , buffer);

	/* -------this how the request looks like --------
	GET /hello HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: Mozilla/5.0\r\nAccept: */ /* \r\n\r\n 

*/
    char method[16];
    char target[256];
    char version[32];
    
    int i = 0, j = 0;

    // Parse Method
    while (buffer[i] != ' ' && buffer[i] != '\0') {
        method[j++] = buffer[i++];
    }
    method[j] = '\0';
    i++; // skip space
    j = 0;

    // Parse Request Target
    while (buffer[i] != ' ' && buffer[i] != '\0') {
        target[j++] = buffer[i++];
    }
    target[j] = '\0';
    i++; // skip space
    j = 0;

    // Parse HTTP Version
    while (buffer[i] != '\r' && buffer[i] != '\0') {
        version[j++] = buffer[i++];
    }
    version[j] = '\0';
	
	// now we have the method, target, and version parsed 
	printf("Parsed Method: %s\n", method);
	printf("Parsed Target: %s\n", target);
	printf("Parsed Version: %s\n", version);

	// Now we can send a response back to the client
	char* response ;
	if(!method || !target || !version) {
		response = "HTTP/1.1 400 NOT FOUND\r\n\r\n";
		int response_status = send(client_fd, response, strlen(response), 0);
		printf("Response sent, status ================>> %d\n", response_status);
		if (response_status == -1) {
			printf("Send failed: %s \n", strerror(errno));
			return 1;
		}
		return 1;
	}
	else {
		response = "HTTP/1.1 200 OK\r\n\r\n";
		int response_status = send(client_fd, response, strlen(response), 0);
		printf("Response sent, status ================>> %d\n", response_status);
	}


	char* response = "HTTP/1.1 200 OK\r\n\r\n";
	int response_status = send(client_fd, response, strlen(response), 0);
	printf("Response sent, status ================>> %d\n", response_status);
	if (response_status == -1) {
		printf("Send failed: %s \n", strerror(errno));
		return 1;
	}
	
	close(server_fd);

	 return 0;
}
