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
#include <sys/time.h> // For setsockopt SO_RCVTIMEO

#define WINDOW_SIZE 6
#define BUFFER_SIZE 1024
#define MAX_TREE_HEIGHT 256

// Huffman coding requires a priority queue, so we define the Node and MinHeap structures
typedef struct Node {
    char data;
    unsigned freq;
    struct Node *left, *right;
} Node;

typedef struct MinHeap {
    unsigned size;
    unsigned capacity;
    Node** array;
} MinHeap;


char *directory = NULL; // global directory variable

char* LZ77(const char* data);
char* huffman_encode(const char* data);

// Function to free the Huffman tree nodes
void freeHuffmanTree(Node* node) {
    if (node == NULL) {
        return;
    }
    freeHuffmanTree(node->left);
    freeHuffmanTree(node->right);
    free(node);
}

// Function to check if the connection should be closed
int should_close_connection(const char* header) {
    // By default in HTTP/1.1, connections are persistent
    // Close only if "Connection: close" header exists
    // Case-insensitive comparison would be better for real HTTP, but strstr is ok for now.
    return (strstr(header, "Connection: close") != NULL);
}


// function to convert any string to gzip format
// we will use LZ77(Sliding Window) compression algorithm to compress the string and Hoffman coding to encode the compressed data
char* convertGzip(const char *input)
{
  char* compressed_data = LZ77(input);
  if (compressed_data == NULL) {
    printf("LZ77 compression failed.\n");
    return NULL;
  }
  else {
    char* encoded_data = huffman_encode(compressed_data);
    if (encoded_data == NULL) {
      printf("Huffman encoding failed.\n");
      free(compressed_data);
      return NULL;
    }
    else {
      free(compressed_data); // Free the compressed data after encoding
      return encoded_data; // Return the Huffman encoded data
    }
  }
}

char* LZ77(const char* data) {
    int data_len = strlen(data);
    // Allocate compressed_data dynamically with a more robust size estimate
    // Or use realloc if growth is truly unpredictable.
    // Max potential size is around data_len * (max pair length + 1 literal byte)
    // E.g., for WINDOW_SIZE 6, a pair like "(ddd,d)c" is about 8-9 chars.
    // If every char is a literal, it's data_len * 1.
    // Let's use a heuristic for now, still prone to overflow but better than fixed small BUFFER_SIZE
    size_t initial_compressed_buffer_size = data_len * 10 + 1; // Heuristic: 10x larger than original
    char* compressed_data = (char*)malloc(initial_compressed_buffer_size);
    if (compressed_data == NULL) {
        printf("LZ77: Failed to allocate memory for compressed data.\n");
        return NULL;
    }
    compressed_data[0] = '\0'; // Initialize as empty string

    char sliding_window[WINDOW_SIZE + 1] = "";  // +1 for null terminator
    char pair[50]; // Buffer for sprintf, should be large enough for (offset,length)

    size_t current_compressed_len = 0;

    for (int i = 0; i < data_len; i++) {
        char current_char = data[i];
        char* match = strchr(sliding_window, current_char); // Finds first occurrence only

        // Check if there's enough space in compressed_data before strcat
        // This is a minimal check; a realloc strategy would be better
        if (current_compressed_len + 50 >= initial_compressed_buffer_size) { // 50 for a typical pair or literal
            // Simplified error for now instead of realloc
            printf("LZ77: Compressed data buffer overflowed.\n");
            free(compressed_data);
            return NULL;
        }

        if (match != NULL) {
            int position = match - sliding_window;
            int length = 1;  // Simplified: only matches single character

            // For a more robust LZ77, you would search for the longest match from 'data[i]'
            // into 'sliding_window' and update 'i' by 'length - 1'

            sprintf(pair, "(%d,%d)", position, length);
            strcat(compressed_data, pair);
            current_compressed_len += strlen(pair);

            // Append the literal. Note: in LZ77, a match means you output (offset, length)
            // If you append a literal AFTER a match, it's typically for the *next* unmatched character
            // or if the match was only partial. Your current simplified logic here means you output
            // (offset,1) AND the character itself, which is generally redundant for matches.
            // A more common LZ77 output is (offset,length) for a match, or (0, literal_char) for a literal.
            char literal[2] = {current_char, '\0'};
            strcat(compressed_data, literal);
            current_compressed_len += strlen(literal);

        } else {
            // No match — literal only
            char literal[2] = {current_char, '\0'};
            strcat(compressed_data, literal);
            current_compressed_len += strlen(literal);
        }

        // Update sliding window
        int win_len = strlen(sliding_window);
        if (win_len < WINDOW_SIZE) {
            sliding_window[win_len] = current_char;
            sliding_window[win_len + 1] = '\0';
        } else {
            // Remove first character, shift left
            memmove(sliding_window, sliding_window + 1, WINDOW_SIZE - 1);
            sliding_window[WINDOW_SIZE - 1] = current_char;
            sliding_window[WINDOW_SIZE] = '\0';
        }
    }
    return compressed_data; // This is already on heap
}

Node* newNode(char data, unsigned freq) {
    Node* temp = (Node*)malloc(sizeof(Node));
    temp->left = temp->right = NULL;
    temp->data = data;
    temp->freq = freq;
    return temp;
}

// Create MinHeap
MinHeap* createMinHeap(unsigned capacity) {
    MinHeap* minHeap = (MinHeap*)malloc(sizeof(MinHeap));
    minHeap->size = 0;
    minHeap->capacity = capacity;
    minHeap->array = (Node**)malloc(minHeap->capacity * sizeof(Node*));
    return minHeap;
}

// Swap two min heap nodes
void swapNode(Node** a, Node** b) {
    Node* t = *a;
    *a = *b;
    *b = t;
}

// Heapify
void minHeapify(MinHeap* minHeap, int idx) {
    int smallest = idx;
    int left = 2 * idx + 1;
    int right = 2 * idx + 2;

    if (left < minHeap->size && minHeap->array[left]->freq < minHeap->array[smallest]->freq)
        smallest = left;

    if (right < minHeap->size && minHeap->array[right]->freq < minHeap->array[smallest]->freq)
        smallest = right;

    if (smallest != idx) {
        swapNode(&minHeap->array[smallest], &minHeap->array[idx]);
        minHeapify(minHeap, smallest);
    }
}

// Build MinHeap
void buildMinHeap(MinHeap* minHeap) {
    int n = minHeap->size - 1;
    for (int i = (n - 1) / 2; i >= 0; i--)
        minHeapify(minHeap, i);
}

// Insert into MinHeap
void insertMinHeap(MinHeap* minHeap, Node* node) {
    ++minHeap->size;
    int i = minHeap->size - 1;

    // The condition for the while loop needs to be carefully checked.
    // It should insert the new node correctly while maintaining heap property.
    // This looks like an up-heap operation.
    while (i > 0 && node->freq < minHeap->array[(i - 1) / 2]->freq) {
        minHeap->array[i] = minHeap->array[(i - 1) / 2];
        i = (i - 1) / 2;
    }
    minHeap->array[i] = node;
}

// Extract minimum value node from MinHeap
Node* extractMin(MinHeap* minHeap) {
    if (minHeap->size == 0) return NULL; // Handle empty heap case
    Node* temp = minHeap->array[0];
    minHeap->array[0] = minHeap->array[minHeap->size - 1];
    --minHeap->size;
    minHeapify(minHeap, 0);
    return temp;
}

// Traverse the Huffman Tree and store codes in array
void storeCodes(Node* root, char* code, int top, char codes[256][MAX_TREE_HEIGHT]) {
    if (root->left) {
        code[top] = '0';
        storeCodes(root->left, code, top + 1, codes);
    }
    if (root->right) {
        code[top] = '1';
        storeCodes(root->right, code, top + 1, codes);
    }
    // If it's a leaf node
    if (!(root->left) && !(root->right)) {
        code[top] = '\0';
        strcpy(codes[(unsigned char)root->data], code);
    }
}

// Build Huffman Tree from frequencies
Node* buildHuffmanTree(const char *data, unsigned freq[256]) {
    MinHeap* minHeap = createMinHeap(256); // Capacity 256 for all possible byte values

    // Add leaf nodes to the min-heap
    for (int i = 0; i < 256; i++) {
        if (freq[i]) {
            insertMinHeap(minHeap, newNode(i, freq[i]));
        }
    }
    // No need to call buildMinHeap(minHeap) here, as insertMinHeap maintains heap property
    // However, if the initial insert was done without maintaining heap property, then buildMinHeap
    // would be needed after all insertions are complete. Your insertMinHeap seems to maintain it.

    // Handle edge case: empty input string or single character input
    // If size is 0 or 1, we can't build a proper tree or the single node is the root.
    if (minHeap->size == 0) {
        free(minHeap->array);
        free(minHeap);
        return NULL; // Or handle as an error
    }
    if (minHeap->size == 1) {
        Node* root = extractMin(minHeap); // The only node is the root
        free(minHeap->array); // Free the array within the MinHeap
        free(minHeap);         // Free the MinHeap structure itself
        return root;
    }


    while (minHeap->size > 1) { // Loop until only one node remains in min-heap
        // Extract the two minimum frequency nodes from min-heap
        Node* left = extractMin(minHeap);
        Node* right = extractMin(minHeap);

        // Create a new internal node with '$' as data (or some non-character placeholder)
        // and frequency equal to the sum of the two extracted nodes.
        // Make the two extracted nodes as left and right children of this new node.
        Node* top = newNode('$', left->freq + right->freq);
        top->left = left;
        top->right = right;

        // Add this new node to min-heap
        insertMinHeap(minHeap, top);
    }

    Node* root = extractMin(minHeap); // The remaining node is the root of the Huffman tree
    free(minHeap->array); // Free the array within the MinHeap
    free(minHeap);         // Free the MinHeap structure itself
    return root;
}


// Huffman Encode Function
char* huffman_encode(const char *data) {
    unsigned freq[256] = {0};
    int data_len = strlen(data);

    // Count frequencies
    if (data_len == 0) {
        char* empty_str = (char*)malloc(1);
        empty_str[0] = '\0';
        return empty_str;
    }

    for (int i = 0; i < data_len; i++)
        freq[(unsigned char)data[i]]++;

    // Build Huffman Tree
    Node* root = buildHuffmanTree(data, freq);
    if (root == NULL) {
        return NULL; // Handle case where tree couldn't be built (e.g., empty input)
    }

    // Generate codes
    char codes[256][MAX_TREE_HEIGHT];
    char code[MAX_TREE_HEIGHT];
    storeCodes(root, code, 0, codes);

    // Calculate exact size needed for encoded data string
    size_t encoded_len = 0;
    for (int i = 0; i < data_len; i++) {
        encoded_len += strlen(codes[(unsigned char)data[i]]);
    }

    // Encode data
    char *encoded_data = (char*)malloc(encoded_len + 1); // +1 for null terminator
    if (encoded_data == NULL) {
        freeHuffmanTree(root); // Free tree before returning NULL
        return NULL;
    }
    encoded_data[0] = '\0'; // Initialize as empty string

    for (int i = 0; i < data_len; i++) {
        strcat(encoded_data, codes[(unsigned char)data[i]]);
    }

    freeHuffmanTree(root); // Free the Huffman tree after encoding
    return encoded_data;
}


// function to handle multiple clients
void *handle_client(void *arg) {
  int client_fd = *(int *)arg;
  free(arg);
  int should_close = 0; // Flag to indicate if we should close the connection

  // Set a timeout for the socket
  struct timeval timeout;
  timeout.tv_sec = 15;  // 15 seconds timeout
  timeout.tv_usec = 0;
  setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  // Process requests in a loop
  while (!should_close) {
    char buffer[BUFFER_SIZE]; // Use BUFFER_SIZE for consistency
    memset(buffer, 0, BUFFER_SIZE); // Clear buffer before reading
    int request_received = read(client_fd, buffer, sizeof(buffer) - 1);

    // Check for connection closed, error, or timeout
    if (request_received <= 0) {
      if (request_received == 0) {
        printf("Client closed connection\n");
      } else {
        printf("Read error or timeout: %s (errno %d)\n", strerror(errno), errno);
      }
      break; // Exit the loop to close the socket
    }
    buffer[request_received] = '\0'; // Null-terminate the received data

    printf("Received HTTP request:\n%s\n", buffer); // Changed print message for clarity

    // Parsing variables (moved here for clarity within the loop)
    char method[16] = "";
    char target[64] = "";
    char version[32] = "";
    char file_name[256] = "";

    char header[1024] = ""; // To store extracted headers
    char encrytion[256] = "";
    char user_agent_val[256] = "";
    char content_length_str[256] = "";

    char *response_to_send = NULL; // Pointer to the response string
    int current_response_len = 0;

    // Find the first space
    char *first_space = strchr(buffer, ' ');
    if (first_space == NULL) {
      response_to_send = "HTTP/1.1 400 Bad Request\r\n\r\n --- due to no space found in request line ---";
      current_response_len = strlen(response_to_send);
      send(client_fd, response_to_send, current_response_len, 0);
      break; // Invalid request, close connection
    }

    // Extract method
    int method_len = first_space - buffer;
    if (method_len >= sizeof(method)) { // Ensure buffer size is respected
      response_to_send = "HTTP/1.1 400 Bad Request\r\n\r\n--- due to method too long ---";
      current_response_len = strlen(response_to_send);
      send(client_fd, response_to_send, current_response_len, 0);
      break; // Invalid request, close connection
    }
    strncpy(method, buffer, method_len);
    method[method_len] = '\0';

    // Find the second space (after the first space)
    char *second_space = strchr(first_space + 1, ' ');
    if (second_space == NULL) {
      response_to_send = "HTTP/1.1 400 Bad Request\r\n\r\n --- due to no second space found in request line ---";
      current_response_len = strlen(response_to_send);
      send(client_fd, response_to_send, current_response_len, 0);
      break; // Invalid request, close connection
    }

    // Extract target
    int target_len = second_space - (first_space + 1);
    if (target_len >= sizeof(target)) { // Ensure buffer size is respected
      response_to_send = "HTTP/1.1 400 Bad Request\r\n\r\n ---- due to target too long ---";
      current_response_len = strlen(response_to_send);
      send(client_fd, response_to_send, current_response_len, 0);
      break; // Invalid request, close connection
    }
    strncpy(target, first_space + 1, target_len);
    target[target_len] = '\0';

    // extracting the version (using correct \r\n detection)
    char *version_start = second_space + 1;
    char *CRLF_requestLine = strstr(version_start, "\r\n");
    if (CRLF_requestLine == NULL) {
      response_to_send = "HTTP/1.1 400 Bad Request\r\n\r\n --- due to no CRLF found after version ---";
      current_response_len = strlen(response_to_send);
      send(client_fd, response_to_send, current_response_len, 0);
      break; // Invalid request, close connection
    }

    // Extract version
    int version_len = CRLF_requestLine - version_start;
    if (version_len >= sizeof(version) || version_len <= 0) { // Ensure buffer size is respected
      response_to_send = "HTTP/1.1 400 Bad Request\r\n\r\n---- due to version too long or empty ---";
      current_response_len = strlen(response_to_send);
      send(client_fd, response_to_send, current_response_len, 0);
      break; // Invalid request, close connection
    }
    strncpy(version, version_start, version_len);
    version[version_len] = '\0';

    // extracting the headers
    char *header_start_in_buffer = CRLF_requestLine + 2; // Move past the first \r\n
    char *headers_end_in_buffer = strstr(header_start_in_buffer, "\r\n\r\n");

    if (headers_end_in_buffer != NULL) {
      int header_length = headers_end_in_buffer - header_start_in_buffer;
      // Copy only the header section into the 'header' buffer
      // Ensure not to overflow 'header' buffer
      size_t copy_len = (size_t)header_length < (sizeof(header) - 1) ? (size_t)header_length : (sizeof(header) - 1);
      strncpy(header, header_start_in_buffer, copy_len);
      header[copy_len] = '\0';
    } else {
      // If no empty line is found, consider the rest as headers (up to buffer end)
      // This might happen if the request is incomplete or malformed.
      size_t remaining_len = strlen(header_start_in_buffer);
      size_t copy_len = remaining_len < (sizeof(header) - 1) ? remaining_len : (sizeof(header) - 1);
      strncpy(header, header_start_in_buffer, copy_len);
      header[copy_len] = '\0';
      // If headers don't end with \r\n\r\n, it's often a malformed request
      printf("Warning: Headers did not end with CRLFCRLF. Malformed request or incomplete.\n");
    }

    // Check for Connection: close header
    should_close = should_close_connection(header);

    // --- Start of specific path handling ---

    // Root path "/"
    if (strcmp(target, "/") == 0) {
        response_to_send = "HTTP/1.1 200 OK\r\n\r\n";
        current_response_len = strlen(response_to_send);
        send(client_fd, response_to_send, current_response_len, 0);
        if (should_close) break; // Close if requested
        continue; // Process next request
    }

    // "/echo/" path
    char *echo_pos = strstr(target, "/echo/");
    if (echo_pos != NULL) {
      char *echo_str_ptr = echo_pos + strlen("/echo/");
      // The extracted echo string can be empty if target is just "/echo/"
      int echo_str_len = strlen(echo_str_ptr);
      char response_echo[2048]; // Large enough for headers + encoded data

      // Check for Accept-Encoding
      if (strstr(header, "Accept-Encoding: ") != NULL) {
        char *encoding_start = strstr(header, "Accept-Encoding: ") + strlen("Accept-Encoding: ");
        char *encoding_end = strstr(encoding_start, "\r\n"); // Find end of line
        if (encoding_end) {
          int encoding_len = encoding_end - encoding_start;
          if (encoding_len >= sizeof(encrytion)) {
            response_to_send = "HTTP/1.1 400 Bad Request\r\n\r\n--- Accept-Encoding value too long ---";
            current_response_len = strlen(response_to_send);
            send(client_fd, response_to_send, current_response_len, 0);
            break; // Close on error
          }
          strncpy(encrytion, encoding_start, encoding_len);
          encrytion[encoding_len] = '\0';

          if (strstr(encrytion, "gzip") != NULL) {
            char *gzip_echo_str = convertGzip(echo_str_ptr);
            if (!gzip_echo_str) { // Handle allocation/compression failure
              response_to_send = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
              current_response_len = strlen(response_to_send);
              send(client_fd, response_to_send, current_response_len, 0);
              break; // Close on error
            }
            int len_gzip_echo_str = strlen(gzip_echo_str);
            // snprintf handles potential buffer overflow by truncating
            snprintf(response_echo, sizeof(response_echo),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/plain\r\n"
                 "Content-Encoding: gzip\r\n"
                 "Content-Length: %d\r\n%s%s\r\n\r\n", // Add Connection: close if needed
                 len_gzip_echo_str,
                 should_close ? "Connection: close\r\n" : "",
                 gzip_echo_str);
            current_response_len = strlen(response_echo);
            send(client_fd, response_echo, current_response_len, 0);
            free(gzip_echo_str); // Free allocated gzip string

            if (should_close) break; // Close if requested
            continue; // Process next request
          }
        }
      }
      // Fallback for /echo/ without gzip or if gzip not supported
      snprintf(response_echo, sizeof(response_echo),
           "HTTP/1.1 200 OK\r\n"
           "Content-Type: text/plain\r\n"
           "Content-Length: %d\r\n%s\r\n%s",
           echo_str_len,
           should_close ? "Connection: close\r\n" : "",
           echo_str_ptr);
      current_response_len = strlen(response_echo);
      send(client_fd, response_echo, current_response_len, 0);
      if (should_close) break; // Close if requested
      continue; // Process next request
    }

    // "/user-agent" path
    if (strcmp(target, "/user-agent") == 0) { // Target is exactly "/user-agent"
      char *user_agent_start = strstr(header, "User-Agent: ");
      if (user_agent_start != NULL) {
        user_agent_start += strlen("User-Agent: ");
        char *user_agent_end = strstr(user_agent_start, "\r\n"); // Find end of line
        if (user_agent_end) {
          int user_agent_len = user_agent_end - user_agent_start;
          if (user_agent_len >= sizeof(user_agent_val)) {
            response_to_send = "HTTP/1.1 400 Bad Request\r\n\r\n--- User-Agent value too long ---";
            current_response_len = strlen(response_to_send);
            send(client_fd, response_to_send, current_response_len, 0);
            break; // Close on error
          }
          strncpy(user_agent_val, user_agent_start, user_agent_len);
          user_agent_val[user_agent_len] = '\0';
          char response_user_agent[512];
          snprintf(response_user_agent, sizeof(response_user_agent),
                   "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n%s\r\n%s",
                   strlen(user_agent_val),
                   should_close ? "Connection: close\r\n" : "",
                   user_agent_val);
          current_response_len = strlen(response_user_agent);
          send(client_fd, response_user_agent, current_response_len, 0);
          if (should_close) break; // Close if requested
          continue; // Process next request
        }
      }
      // Fallback if User-Agent header not found or malformed
      response_to_send = "HTTP/1.1 400 Bad Request\r\n\r\n--- User-Agent header not found or malformed ---";
      current_response_len = strlen(response_to_send);
      send(client_fd, response_to_send, current_response_len, 0);
      break; // Close on error
    }

    // "/files/" path
    char *file_pos = strstr(target, "/files/");
    if (file_pos != NULL) {
      file_pos += strlen("/files/"); // Move past "/files/"
      // The rest of the target is the file name
      char *file_end = strchr(file_pos, '\0'); // Find end of string (already null-terminated)
      if (file_end == NULL) { // Should not happen if target is properly null-terminated
          response_to_send = "HTTP/1.1 400 Bad Request\r\n\r\n--- Malformed file path ---";
          current_response_len = strlen(response_to_send);
          send(client_fd, response_to_send, current_response_len, 0);
          break; // Close on error
      }
      int file_len = file_end - file_pos;
      if (file_len >= sizeof(file_name)) {
        response_to_send = "HTTP/1.1 400 Bad Request\r\n\r\n--- due to file name too long ---";
        current_response_len = strlen(response_to_send);
        send(client_fd, response_to_send, current_response_len, 0);
        break; // Close on error
      }
      strncpy(file_name, file_pos, file_len);
      file_name[file_len] = '\0';

      char full_file_path[512];
      snprintf(full_file_path, sizeof(full_file_path), "%s/%s", directory, file_name);

      if (strcmp(method, "GET") == 0) {
        FILE *file = fopen(full_file_path, "r");
        if (file == NULL) {
          response_to_send = "HTTP/1.1 404 Not Found\r\n\r\n";
          current_response_len = strlen(response_to_send);
          send(client_fd, response_to_send, current_response_len, 0);
          if (should_close) break; // Close if requested
          continue; // File not found, but connection might persist
        }
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);

        char *file_content = malloc(file_size + 1);
        if (file_content == NULL) {
          response_to_send = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
          current_response_len = strlen(response_to_send);
          send(client_fd, response_to_send, current_response_len, 0);
          fclose(file);
          break; // Close on error
        }
        fread(file_content, 1, file_size, file);
        fclose(file);
        file_content[file_size] = '\0'; // Null-terminate for safety

        char response_file_header[512];
        snprintf(response_file_header, sizeof(response_file_header),
                 "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %ld\r\n%s\r\n",
                 file_size,
                 should_close ? "Connection: close\r\n" : ""); // Add Connection: close if needed
        send(client_fd, response_file_header, strlen(response_file_header), 0);
        send(client_fd, file_content, file_size, 0); // Send raw content
        free(file_content); // Free file content

        if (should_close) break; // Close if requested
        continue; // Process next request
      } else if (strcmp(method, "POST") == 0) {
        int content_length_val = 0;
        char *content_length_start = strstr(header, "Content-Length: ");
        if (content_length_start != NULL) {
          content_length_start += strlen("Content-Length: ");
          char *content_length_end = strstr(content_length_start, "\r\n");
          if (content_length_end) {
            int len_str = content_length_end - content_length_start;
            if (len_str >= sizeof(content_length_str)) {
              response_to_send = "HTTP/1.1 400 Bad Request\r\n\r\n--- Content-Length value too long ---";
              current_response_len = strlen(response_to_send);
              send(client_fd, response_to_send, current_response_len, 0);
              break; // Close on error
            }
            strncpy(content_length_str, content_length_start, len_str);
            content_length_str[len_str] = '\0';
            content_length_val = atoi(content_length_str); // Use atoi for integer conversion
          }
        }
        if (content_length_val <= 0) {
          response_to_send = "HTTP/1.1 400 Bad Request\r\n\r\n--- Content-Length missing or invalid for POST ---";
          current_response_len = strlen(response_to_send);
          send(client_fd, response_to_send, current_response_len, 0);
          break; // Close on error
        }

        // Find the start of the request body in the original buffer
        char *body_start_in_buffer = strstr(buffer, "\r\n\r\n");
        if (body_start_in_buffer != NULL) {
          body_start_in_buffer += 4; // Move past the "\r\n\r\n"

          FILE *file = fopen(full_file_path, "wb"); // Open in binary write mode
          if (file == NULL) {
            response_to_send = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
            current_response_len = strlen(response_to_send);
            send(client_fd, response_to_send, current_response_len, 0);
            break; // Close on error
          }
          // Ensure we don't read past the end of the buffer if content_length_val is too large
          size_t bytes_to_write = (request_received - (body_start_in_buffer - buffer));
          if (bytes_to_write > content_length_val) {
              bytes_to_write = content_length_val;
          }

          fwrite(body_start_in_buffer, 1, bytes_to_write, file);
          fclose(file);

          response_to_send = "HTTP/1.1 201 Created\r\n%s\r\n\r\n"; // 201 for resource creation
          // Use snprintf to construct the full response with potential Connection: close header
          char temp_response[128]; // Temp buffer for the 201 response header
          snprintf(temp_response, sizeof(temp_response), response_to_send,
                   should_close ? "Connection: close" : "");
          current_response_len = strlen(temp_response);
          send(client_fd, temp_response, current_response_len, 0);

          if (should_close) break; // Close if requested
          continue; // Process next request
        } else {
          response_to_send = "HTTP/1.1 400 Bad Request\r\n\r\n--- No request body found for POST ---";
          current_response_len = strlen(response_to_send);
          send(client_fd, response_to_send, current_response_len, 0);
          break; // Close on error
        }
      }
    }

    // Default 404 Not Found if none of the specific paths matched (or default path handling not done earlier)
    response_to_send = "HTTP/1.1 404 Not Found\r\n%s\r\n\r\n";
    char temp_response[128];
    snprintf(temp_response, sizeof(temp_response), response_to_send,
             should_close ? "Connection: close" : "");
    current_response_len = strlen(temp_response);
    send(client_fd, temp_response, current_response_len, 0);
    if (should_close) break; // Close if requested
    continue; // Process next request

  } // End of while (!should_close) loop

  // If the loop breaks, close the client socket
  close(client_fd);
  printf("Client connection closed (fd: %d).\n", client_fd);
  pthread_exit(NULL); // Terminate the thread
  return NULL; // Should not be reached
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
  int server_fd; // server_fd is the socket file descriptor
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
    socklen_t client_addr_len = sizeof(client_addr); // Correct type for accept

    int client_fd =
        accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);

    char *client_ip = inet_ntoa(client_addr.sin_addr);
    int client_port = ntohs(client_addr.sin_port);

    printf("Client connected (fd: %d)\n", client_fd);
    printf("Client IP: %s, Client Port: %d\n", client_ip, client_port);

    // Create a new thread to handle this client
    pthread_t thread;
    int *client_fd_ptr = malloc(sizeof(int));
    if (client_fd_ptr == NULL) {
      printf("Failed to allocate memory for client_fd_ptr: %s\n",
             strerror(errno));
      close(client_fd); // Close the client_fd if we can't create a thread for it
      continue;
    }
    *client_fd_ptr = client_fd;

    if (pthread_create(&thread, NULL, handle_client, client_fd_ptr) != 0) {
      printf("Failed to create thread: %s\n", strerror(errno));
      close(client_fd); // Close the client_fd if thread creation fails
      free(client_fd_ptr); // Free the allocated memory
      continue;
    }

    // Detach the thread - we don't need to join it later
    pthread_detach(thread);
  }
  return 0;
}