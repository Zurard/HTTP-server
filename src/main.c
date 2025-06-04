#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h> //  to handle multiple clients who are trying to connect to the server

char *directory = NULL; // global directory variable
// function to handle multiple clients
void *handle_client(void *arg) {
  int client_fd = *(int *)arg;
  free(arg);

  char buffer[1024];
  int request_received = read(client_fd, buffer, sizeof(buffer) - 1);
  buffer[request_received] = '\0';

  printf("the HTTP request is given as %s", buffer);

  // parsing the request line , headers and request body
  // this is an request divided into three parts (Request Line ,Headers and
  // Request Body)
  char method[16];
  char target[64];
  char version[32];
  // char echo_str[256]; // if echo/{str} string is there - This was shadowing
  // the pointer below
  char file_name[256]; // if we need to extract the file name from the request
                       // for GET or POST method
  // char request_line[256]; // Unused variable

  char header[1024];
  char host[256];
  char encrytion[256]; // if encryption is there in the request
  char user_agent_val[256]; // if user-agent is there in the request
  char content_type[256];   // if content-type is there in the request
  char content_length_str[256]; // if content-length is there in the request
                                // (string representation)
  // char accept[256]; // Unused variable

  // char request_body[1024]; // Used dynamically or with `read` for safety
  // (removed fixed array here)

  char *response;

  // Find the first space
  char *first_space = strchr(buffer, ' ');
  int error = 0;

  if (first_space == NULL) {
    // Handle error: invalid request line
    response = "HTTP/1.1 400 Bad Request\r\n\r\n --- due to no space found ---";
    send(client_fd, response, strlen(response), 0);
    error = 1;
    close(client_fd);
    pthread_exit(NULL);
    return NULL; // Or handle differently
  }

  // Extract method
  int method_len = first_space - buffer;
  printf("Method length: %d, Max allowed: %zu\n", method_len, sizeof(method));
  if (method_len >= sizeof(method)) {
    // Handle error: method too long
    response = "HTTP/1.1 400 Bad Request\r\n\r\n--- due to method too long ---";
    send(client_fd, response, strlen(response), 0);
    error = 1;
    close(client_fd);
    pthread_exit(NULL);
    return NULL; // Or handle differently
  }
  strncpy(method, buffer, method_len);
  method[method_len] = '\0';
  printf("Parsed Method:>>>%s>>\n", method);

  // Find the second space (after the first space)
  char *second_space = strchr(first_space + 1, ' ');
  if (second_space == NULL) {
    // Handle error: invalid request line
    response =
        "HTTP/1.1 400 Bad Request\r\n\r\n --- due to no second space found ---";
    send(client_fd, response, strlen(response), 0);
    error = 1;
    close(client_fd);
    pthread_exit(NULL);
    return NULL; // Or handle differently
  }

  // Extract target
  int target_len = second_space - (first_space + 1);
  printf("Target length: %d, Max allowed: %zu\n", target_len, sizeof(target));
  if (target_len >= sizeof(target)) // invalid request line
  {
    // Handle error: target too long
    response = "HTTP/1.1 400 Bad Request\r\n\r\n ---- due to target too long ---";
    send(client_fd, response, strlen(response), 0);
    error = 1;
    close(client_fd);
    pthread_exit(NULL);
    return NULL;

  } else {
    strncpy(target, first_space + 1, target_len);
    target[target_len] = '\0';
    printf("--------------------->>>>>Parsed Target: %s\n", target);

    // extracting the version
    char *version_start = second_space + 1;
    printf("Version start position: %p\n", version_start);
    // Find the carriage return (after the second space)
    char *CRLF_requestLine = NULL;
    // this method is used to find the immediate CRLF after the version
    for (char *p = version_start; *p != '\0' && p[1] != '\0'; ++p) {
  if (p[0] == '\\' && p[1] == 'r' && p[2] == '\\' && p[3] == 'n') {
    CRLF_requestLine = p;
    break;
  }
  // Optional safety check: break after 32 chars (HTTP version strings are small)
  if (p - version_start > 32) {
    // If we're over 32 chars and still haven't found CRLF, 
    // just use a reasonable cutoff point for version
    CRLF_requestLine = version_start + 8; // HTTP/1.1 is 8 chars
    break;
  }
}
    printf("CRLF position: %p\n", CRLF_requestLine);
    if (CRLF_requestLine == NULL) {
      // Handle error: invalid request line or missing CRLF
      response =
          "HTTP/1.1 400 Bad Request\r\n\r\n --- due to no CRLF found ---";
      send(client_fd, response, strlen(response), 0);
      error = 1;
      close(client_fd);
      pthread_exit(NULL);
      return NULL; // Or handle differently
    }

    // Extract version
    int version_len = CRLF_requestLine - (second_space + 1);
    printf("Version length: %d, Max allowed: %zu\n", version_len,
           sizeof(version));
    if (version_len >= sizeof(version) || version_len <= 0) {
      // Handle error: version too long
      response =
          "HTTP/1.1 400 Bad Request\r\n\r\n---- due to version too long ---";

      send(client_fd, response, strlen(response), 0);
      error = 1;
      close(client_fd);
      pthread_exit(NULL);
      return NULL; // Or handle differently
    }
    strncpy(version, second_space + 1, version_len);
    version[version_len] = '\0';

    // extracting the headers
    char *header_start_in_buffer = CRLF_requestLine + 2; // Move past the \r\n
    // Find the end of headers (empty line \r\n\r\n) within the request buffer
    char *headers_end_in_buffer = strstr(header_start_in_buffer, "\r\n\r\n");

    if (headers_end_in_buffer != NULL) {
      // Copy only the header section into the 'header' buffer
      int header_length = headers_end_in_buffer - header_start_in_buffer;
      strncpy(header, header_start_in_buffer,
              header_length < sizeof(header) - 1 ? header_length
                                                 : sizeof(header) - 1);
      header[header_length < sizeof(header) - 1 ? header_length
                                                : sizeof(header) - 1] = '\0';
    } else {
      // If no empty line is found, consider the rest as headers (up to buffer
      // end)
      strncpy(header, header_start_in_buffer, sizeof(header) - 1);
      header[sizeof(header) - 1] = '\0';
    }
    printf("Parsed Headers:\n%s\n", header);

    // extracting the string after /echo/
    // -------------------------------------------
    char *echo_pos = strstr(target, "/echo/");
    if (echo_pos != NULL) {
      char *echo_str_ptr = echo_pos + strlen("/echo/");

      // Extracted the echo string
      printf("Extracted echo string: %s\n", echo_str_ptr);
      if (*echo_str_ptr != '\0') {

        // Prepare the response accordingly
        int echo_str_len = strlen(echo_str_ptr);

        // example of a response jsut while coding this shit
        //--HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length:
        // 3\r\n\r\nabc--
       
        char response_echo[2048];
         if (strstr(header, "Accept-Encoding")) {
           // now we need to extract all the encoding methods from the header
          char *encoding_start = strstr(header, "Accept-Encoding: ");
          if (encoding_start != NULL)
            {
              encoding_start += 17; // Move past "Accept-Encoding: "
              char *encoding_end = NULL;
              // now we will need to find the immediate CRLF after the encoding values 
              for(char *p = encoding_start; *p != '\0'; ++p) {
                if (p[0] == '\\' && p[1] == 'r' && p[2] == '\\' && p[3] == 'n') { // Corrected CRLF detection
                  encoding_end = p;
                  break;
                }
              }
              if (encoding_end)
              {
                int encoding_len = encoding_end - encoding_start;
                if (encoding_len >= sizeof(encrytion)) {
                  printf("Encoding length: %d, Max allowed: %zu\n", encoding_len,
                         sizeof(encrytion));
                  response = "HTTP/1.1 400 Bad Request\r\n\r\n--- due to "
                             "encoding too long ---";
                  send(client_fd, response, strlen(response), 0);
                  error = 1;
                  close(client_fd);
                  pthread_exit(NULL);
                  return NULL;
                } else {
                  strncpy(encrytion, encoding_start, encoding_len);
                  encrytion[encoding_len] = '\0';
                  printf("Parsed Accept-Encoding: %s\n", encrytion);
                  // now check if gzip is there in the encoding 
                  if (strstr(encrytion,"gzip")!=NULL)
                  {
                    snprintf(response_echo, sizeof(response_echo),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Encoding: gzip\r\n"
                    "Content-Length: %d\r\n\r\n%s", // Removed trailing \r\n here, as it's
                                                  // not part of content
                          echo_str_len, echo_str_ptr);
                    send(client_fd, response_echo, strlen(response_echo), 0);
                    close(client_fd);
                    pthread_exit(NULL);
                    return NULL;
                  }
                }
              }
            }
           snprintf(response_echo, sizeof(response_echo),
           "HTTP/1.1 200 OK\r\n"
           "Content-Type: text/plain\r\n"
          "Content-Length: %d\r\n\r\n%s", // Removed trailing \r\n here, as it's
                                        // not part of content
                 echo_str_len, echo_str_ptr);
           send(client_fd, response_echo, strlen(response_echo), 0);
          close(client_fd);
          pthread_exit(NULL);
          return NULL;
        }
       
        snprintf(response_echo, sizeof(response_echo),
                 "Content-Length: %d\r\n\r\n%s", // Removed trailing \r\n here, as it's
                                        // not part of content
                 echo_str_len, echo_str_ptr);
        send(client_fd, response_echo, strlen(response_echo), 0);
        close(client_fd);
        pthread_exit(NULL);
        return NULL;
      }
    }

    // extracting the user-agent from header if it's there in the request line
    printf("User-agent path found: %d\n",
           strstr(target, "/user-agent") != NULL);
    if (strstr(target, "/user-agent") != NULL) {
      char *user_agent_start = strstr(header, "User-Agent: ");
      if (user_agent_start != NULL) {
        user_agent_start += 12; // Move past "User-Agent: "
        char *user_agent_end = NULL;
        // now we need to find immediate CRLF after the user-agent
        for (char *p = user_agent_start; *p != '\0'; ++p) {
          if (p[0] == '\\' && p[1] == 'r' && p[2] == '\\' && p[3] == 'n') { // Corrected CRLF detection
            user_agent_end = p;
            break;
          }
        }
        if (user_agent_end) {
          int user_agent_len = user_agent_end - user_agent_start;
          if (user_agent_len >= sizeof(user_agent_val)) {
            printf("User-Agent length: %d, Max allowed: %zu\n", user_agent_len,
                   sizeof(user_agent_val));
            response = "HTTP/1.1 400 Bad Request\r\n\r\n--- due to user-agent "
                       "too long ---";
            send(client_fd, response, strlen(response), 0);
            error = 1;
            close(client_fd);
            pthread_exit(NULL);
            return NULL;
          } else {
            strncpy(user_agent_val, user_agent_start, user_agent_len);
            user_agent_val[user_agent_len] = '\0';
            char response_user_agent[512];
            snprintf(response_user_agent, sizeof(response_user_agent),
                     "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-"
                     "Length: %zu\r\n\r\n%s",
                     strlen(user_agent_val), user_agent_val);
            send(client_fd, response_user_agent,
                 strlen(response_user_agent), 0);
            close(client_fd);
            pthread_exit(NULL);
            printf("Parsed User-Agent: %s\n", user_agent_val);
            return NULL;
          }
        }
      }
    }

    printf("NO echo string found in the request now chekcing for file in the "
           "target\n");
    // extracting the file name from the request :
    char *file_pos = strstr(target, "/files/");
    printf("File position: %p\n", file_pos);
    if (file_pos != NULL) {
      file_pos += 7;
      char *file_end = strchr(target, '\0');
      printf("File end position: %p\n", file_end);
      if (file_end != NULL) {
        int file_len = file_end - file_pos;
        if (file_len >= sizeof(file_name)) {
          // handle error :
          response =
              "HTTP/1.1 400 Bad Request\r\n\r\n--- due to file name too long ---";
          send(client_fd, response, strlen(response), 0);
          error = 1;
          close(client_fd);
          pthread_exit(NULL);
          return NULL; // Add return here
        } else {
          strncpy(file_name, file_pos, file_len);
          file_name[file_len] = '\0';
          printf("Extracted file name: %s\n", file_name);

          char full_file_path[512];
          // Use the global directory variable here, not redeclaring const char
          // *directory = "/tmp";
          snprintf(full_file_path, sizeof(full_file_path), "%s/%s", directory,
                   file_name);
          printf("Full file path: %s\n", full_file_path);
          printf(strcmp(method,"POST") == 0 ? "POST method detected\n" : "Not a POST method\n");
          if (strcmp(method, "GET") == 0) 
          { 
            FILE *file = fopen(full_file_path, "r");
            if (file == NULL) {
              // Handle error: file not found
              response = "HTTP/1.1 404 Not Found\r\n\r\n"; // Added proper CRLF
                                                          // for body separator
              send(client_fd, response, strlen(response), 0);
              error = 1;
              close(client_fd);
              pthread_exit(NULL);
              return NULL; // Or handle differently
            } else {
              // File exists, read its content and send it back
              fseek(file, 0, SEEK_END);
              long file_size = ftell(file);
              fseek(file, 0, SEEK_SET);

              char *file_content = malloc(file_size + 1);
              if (file_content == NULL) {
                // Handle malloc error
                response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                send(client_fd, response, strlen(response), 0);
                fclose(file);
                close(client_fd);
                pthread_exit(NULL);
                return NULL;
              }
              fread(file_content, 1, file_size, file);
              fclose(file);
              file_content[file_size] = '\0'; // Null-terminate the content

              char response_file_header[512];
              snprintf(response_file_header, sizeof(response_file_header),
                       "HTTP/1.1 200 OK\r\nContent-Type: "
                       "application/octet-stream\r\nContent-Length: %ld\r\n\r\n",
                       file_size);
              send(client_fd, response_file_header,
                   strlen(response_file_header), 0);
              send(client_fd, file_content, file_size, 0); // Send raw content
              free(file_content);
              close(client_fd);
              pthread_exit(NULL);
              return NULL; // Or handle differently
            }
          } 
          else if (strcmp(method,"POST") == 0) { 
            // extacting the content-length from header
            int content_length_val = 0;
            char *content_length_start = strstr(header, "Content-Length: ");
            if (content_length_start != NULL) {
              content_length_start += 16; // Move past "Content-Length: "
              char *content_length_end = NULL;
              for (char *p = content_length_start; *p != '\0'; ++p) {
                if (p[0] == '\\' && p[1] == 'r' && p[2] == '\\' && p[3] == 'n') { // Corrected CRLF detection
                  content_length_end = p;
                  break;
                }
              }
              if (content_length_end) {
                int len_str = content_length_end - content_length_start;
                if (len_str >= sizeof(content_length_str)) {
                  response = "HTTP/1.1 400 Bad Request\r\n\r\n--- due to "
                             "content-length string too long ---";
                  send(client_fd, response, strlen(response), 0);
                  error = 1;
                  close(client_fd);
                  pthread_exit(NULL);
                  return NULL;
                }
                strncpy(content_length_str, content_length_start, len_str);
                content_length_str[len_str] = '\0';
                printf("Parsed Content-Length: %s\n", content_length_str);
                content_length_val = atol(content_length_str);
              }
            }

            if (content_length_val <= 0) {
              response = "HTTP/1.1 400 Bad Request\r\n\r\n--- Content-Length "
                         "missing or invalid for POST ---";
              send(client_fd, response, strlen(response), 0);
              error = 1;
              close(client_fd);
              pthread_exit(NULL);
              return NULL;
            }

            // Find the start of the request body in the original buffer
            char *body_start_in_buffer = strstr(buffer, "\\r\\n\\r\\n");
            printf("Body start position in buffer: %p\n", body_start_in_buffer);
            if (body_start_in_buffer != NULL) {
              body_start_in_buffer += content_length_val + 3; // Move past the "\r\n\r\n"

              FILE *file = fopen(full_file_path, "wb"); // Open in binary write
                                                         // mode
              if (file == NULL) {
                response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                send(client_fd, response, strlen(response), 0);
                error = 1;
                close(client_fd);
                pthread_exit(NULL);
                return NULL;
              }

              // Write the exact content_length_val bytes from the buffer
              // Starting from body_start_in_buffer
              fwrite(body_start_in_buffer, 1, content_length_val, file);
              fclose(file);

              response = "HTTP/1.1 201 Created\r\n\r\n"; // 201 for resource
                                                        // creation
              send(client_fd, response, strlen(response), 0);
              close(client_fd);
              pthread_exit(NULL);
              return NULL;

            } else {
              response =
                  "HTTP/1.1 400 Bad Request\r\n\r\n--- No request body found "
                  "for POST ---";
              send(client_fd, response, strlen(response), 0);
              error = 1;
              close(client_fd);
              pthread_exit(NULL);
              return NULL;
            }
          }
        }
      }
    }
  }

  // If none of the specific paths matched (e.g., target is just "/")
  // Send a simple HTTP 200 OK response
  response = "HTTP/1.1 200 OK\r\n\r\n";
  send(client_fd, response, strlen(response), 0);
  close(client_fd);
  pthread_exit(NULL);
  return NULL;
}

int main(int argc, char *argv[]) {
  // Disable output buffering
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  // You can use print statements as follows for debugging, they'll be visible
  // when running tests.
  printf("Logs from your program will appear here!\n");

  // Check if the directory argument is provided
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--directory") == 0 && i + 1 < argc) {
      directory = argv[i + 1];
      printf("File directory set to: %s\n", directory);
      i++; // Skip the next argument since we've used it
    }
  }

  // if no directory is provided, use a default directory
  if (directory == NULL) {
    directory = "."; // Default directory (current directory, not "/.")
    printf("No directory provided, using default: %s\n", directory);
  }

  // Set up the server socket
  int server_fd, client_addr_len; // server_fd is the socket file descriptor
  struct sockaddr_in client_addr;

  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  printf("Socket created with the number assigned as this  =============>> "
         "%d\n",
         server_fd);
  if (server_fd == -1) {
    printf("Socket creation failed: %s...\n", strerror(errno));
    return 1;
  }

  // Since the tester restarts your program quite often, setting SO_REUSEADDR
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
      0) {
    printf("SO_REUSEADDR failed: %s \n", strerror(errno));
    return 1;
  }

  struct sockaddr_in serv_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(4221),
      .sin_addr = {htonl(INADDR_ANY)},
  };

  if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
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

  while (1) {

    printf("Waiting for a client to connect...\r\n");
    client_addr_len = sizeof(client_addr);

    int client_fd =
        accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);

    char *client_ip = inet_ntoa(client_addr.sin_addr);
    int client_port = ntohs(client_addr.sin_port);

    printf("Client connected\n");
    printf("Client IP: %s, Client Port: %d\n", client_ip, client_port);

    // Create a new thread to handle this client
    pthread_t thread;
    int *client_fd_ptr = malloc(sizeof(int));
    if (client_fd_ptr == NULL) {
      printf("Failed to allocate memory for client_fd_ptr: %s\n",
             strerror(errno));
      close(client_fd);
      continue;
    }
    *client_fd_ptr = client_fd;

    if (pthread_create(&thread, NULL, handle_client, client_fd_ptr) != 0) {
      printf("Failed to create thread: %s\n", strerror(errno));
      close(client_fd);
      free(client_fd_ptr);
      continue;
    }

    // Detach the thread - we don't need to join it later
    pthread_detach(thread);
    // close(server_fd); // Don't close server_fd here, it's the listening
    // socket
  }
  return 0;
}