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
	int listening_port = ntohs(serv_addr.sin_port);
	printf("Server is listening on port %d\n", listening_port);
	// Now we can start listening for incoming connections
	if (listen(server_fd, connection_backlog) != 0) {
		printf("Listen failed: %s \n", strerror(errno));
		return 1;
	}
	
	printf("==============>>Waiting for a client to connect...\n");
	client_addr_len = sizeof(client_addr);
	
   
   int client_fd= accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_len);

	char* client_ip= inet_ntoa(serv_addr.sin_addr);
	int client_port = ntohs(serv_addr.sin_port);

	
	printf("Client connected\n");
	printf("Client IP: %s, Client Port: %d\n", client_ip, client_port);

	//Client has been connected sucessfully now we try to understand and give a response based on that 
	// URL Extraction 	   

    char buffer[1024];
    int request_received = read(client_fd, buffer, sizeof(buffer) - 1);
    buffer[request_received] = '\0';

    printf("the HTTP request is given as %s", buffer);

    char method[16];
    char target[256];
    char version[32];
	char* response ;

    // Find the first space
    char* first_space = strchr(buffer, ' ');
    int error  = 0;

    if (first_space == NULL) {
        // Handle error: invalid request line
        response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, response, strlen(response), 0);
		error = 1;
        return 1; // Or handle differently
    }

    // Extract method
    int method_len = first_space - buffer;
    if (method_len >= sizeof(method)) {
        // Handle error: method too long
         response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, response, strlen(response), 0);
		error = 1;
        return 1; // Or handle differently
    }
    strncpy(method, buffer, method_len);
    method[method_len] = '\0';

    // Find the second space (after the first space)
    char* second_space = strchr(first_space + 1, ' ');
    if (second_space == NULL) {
         // Handle error: invalid request line
        response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, response, strlen(response), 0);
		error =1;
        return 1; // Or handle differently
    }

    // Extract target
    int target_len = second_space - (first_space + 1);
     if (target_len >= sizeof(target)) {
        // Handle error: target too long
         response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, response, strlen(response), 0);
        error = 1;
		return 1; // Or handle differently
    }
    strncpy(target, first_space + 1, target_len);
    target[target_len] = '\0';

    // Find the carriage return (after the second space)
    char* crlf = strstr(second_space + 1, "\r\n");
     if (crlf == NULL) {
         // Handle error: invalid request line or missing CRLF
        response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, response, strlen(response), 0);
		error = 1;
        return 1; // Or handle differently
    }

    // Extract version
    int version_len = crlf - (second_space + 1);
    if (version_len >= sizeof(version)) {
        // Handle error: version too long
         response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, response, strlen(response), 0);
		error = 1;
        return 1; // Or handle differently
    }
    strncpy(version, second_space + 1, version_len);
    version[version_len] = '\0';
	
	if (error == 0 ){
		// Send a simple HTTP response
		response = "HTTP/1.1 200 OK\r\n";
		send(client_fd, response, strlen(response), 0);
		return 1;
	}
	// now we have the method, target, and version parsed 
	printf("Parsed Method: %s\n", method);
	printf("Parsed Target: %s\n", target);
	printf("Parsed Version: %s\n", version);
	memset(buffer, 0, sizeof(buffer));

	// close(server_fd);

	 return 0;
}
