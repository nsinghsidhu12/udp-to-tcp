#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>

static void parse_arguments(int argc, char *argv[], char **client_ip_address, char **client_port_str,
                            char **server_ip_address, char **server_port_str, char **msg);

static void handle_arguments(const char *binary_name, const char *client_ip_address, const char *client_port_str,
                             const char *server_ip_address, const char *server_port_str, const char *message,
                             in_port_t *client_port, in_port_t *server_port);

static in_port_t parse_in_port_t(const char *binary_name, const char *port_str);

static void socket_bind(int sockfd, struct sockaddr_storage *addr, in_port_t port);

_Noreturn static void usage(const char *program_name, int exit_code, const char *message);

static void convert_address(const char *address, struct sockaddr_storage *addr, socklen_t *addr_len);

static int socket_create(int domain, int type, int protocol);

static void get_address_to_server(struct sockaddr_storage *addr, in_port_t port);

static void socket_close(int sockfd);

void file_data(FILE *file, int sockfd, struct sockaddr_storage *addr);

int file_check(char *file_path);

FILE *file_open(char *file_path);

void handle_timeout(int signal);

// Used to encode
struct PACKET {
    int seq_num;
    char data[1025];
} typedef Packet;

Packet *make_packet(int seq_num, int ack_num, char* flags, char* data);

#define UNKNOWN_OPTION_MESSAGE_LEN 24
#define BASE_TEN 10
#define LINE_LEN 1024

bool timeout_occured = 0;

int main(int argc, char *argv[]) {
    char *client_ip_address;
    char *client_port_str;
    in_port_t client_port;
    char *server_ip_address;
    char *server_port_str;
    in_port_t server_port;
    char *message;
    int sockfd;
    ssize_t bytes_sent;
    struct sockaddr_storage client_socket_addr;
    socklen_t client_socket_addr_len;
    struct sockaddr_storage server_socket_addr;
    socklen_t server_socket_addr_len;

    client_ip_address = NULL;
    client_port_str = NULL;
    server_ip_address = NULL;
    server_port_str = NULL;
    message = NULL;

    parse_arguments(argc, argv, &client_ip_address, &client_port_str, &server_ip_address, &server_port_str,
                    &message);
    handle_arguments(argv[0], client_ip_address, client_port_str, server_ip_address, server_port_str,
                     message, &client_port, &server_port);

    convert_address(client_ip_address, &client_socket_addr, &client_socket_addr_len);
    sockfd = socket_create(client_socket_addr.ss_family, SOCK_DGRAM, 0);
    socket_bind(sockfd, &client_socket_addr, client_port);

    convert_address(server_ip_address, &server_socket_addr, &server_socket_addr_len);
    get_address_to_server(&server_socket_addr, server_port);
//    bytes_sent = sendto(sockfd, message, strlen(message) + 1, 0,
//                        (struct sockaddr *) &server_socket_addr, server_socket_addr_len);
//
//    if (bytes_sent == -1) {
//        perror("sendto");
//        exit(EXIT_FAILURE);
//    }
//
//    printf("Sent %zu bytes: \"%s\"\n", (size_t) bytes_sent, message);
//
//    recvfrom(sockfd, message, strlen(message) + 1, 0, (struct sockaddr *) &server_socket_addr, &server_socket_addr_len);
//
//    printf("Received %zu bytes: \"%s\"\n", (size_t) bytes_sent, message);
    printf("%s", argv[5]);
    FILE *file = file_open(message);
    file_data(file, sockfd, &server_socket_addr);
    socket_close(sockfd);

    return EXIT_SUCCESS;
}

static void parse_arguments(int argc, char *argv[], char **client_ip_address, char **client_port_str,
                            char **server_ip_address, char **server_port_str, char **msg) {
    int opt;

    opterr = 0;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
            case 'h': {
                usage(argv[0], EXIT_SUCCESS, NULL);
            }
            case '?': {
                char message[UNKNOWN_OPTION_MESSAGE_LEN];

                snprintf(message, sizeof(message), "Unknown option '-%c'.", optopt);
                usage(argv[0], EXIT_FAILURE, message);
            }
            default: {
                usage(argv[0], EXIT_FAILURE, NULL);
            }
        }
    }

    if (optind + 4 >= argc) {
        usage(argv[0], EXIT_FAILURE, "Too few arguments.");
    }

    if (optind < argc - 5) {
        usage(argv[0], EXIT_FAILURE, "Too many arguments.");
    }

    *client_ip_address = argv[optind];
    *client_port_str = argv[optind + 1];
    *server_ip_address = argv[optind + 2];
    *server_port_str = argv[optind + 3];
    *msg = argv[optind + 4];
}

static void handle_arguments(const char *binary_name, const char *client_ip_address, const char *client_port_str,
                             const char *server_ip_address, const char *server_port_str, const char *message,
                             in_port_t *client_port, in_port_t *server_port) {
    if (client_ip_address == NULL) {
        usage(binary_name, EXIT_FAILURE, "The client ip address is required.");
    }

    if (client_port_str == NULL) {
        usage(binary_name, EXIT_FAILURE, "The client port is required.");
    }

    if (server_ip_address == NULL) {
        usage(binary_name, EXIT_FAILURE, "The server ip address is required.");
    }

    if (server_port_str == NULL) {
        usage(binary_name, EXIT_FAILURE, "The server port is required.");
    }

    if (message == NULL) {
        usage(binary_name, EXIT_FAILURE, "The message is required.");
    }

    *client_port = parse_in_port_t(binary_name, client_port_str);
    *server_port = parse_in_port_t(binary_name, server_port_str);
}

in_port_t parse_in_port_t(const char *binary_name, const char *str) {
    char *endptr;
    uintmax_t parsed_value;

    errno = 0;
    parsed_value = strtoumax(str, &endptr, BASE_TEN);

    if (errno != 0) {
        perror("Error parsing in_port_t");
        exit(EXIT_FAILURE);
    }

    // Check if there are any non-numeric characters in the input string
    if (*endptr != '\0') {
        usage(binary_name, EXIT_FAILURE, "Invalid characters in input.");
    }

    // Check if the parsed value is within the valid range for in_port_t
    if (parsed_value > UINT16_MAX) {
        usage(binary_name, EXIT_FAILURE, "in_port_t value out of range.");
    }

    return (in_port_t) parsed_value;
}

_Noreturn static void usage(const char *program_name, int exit_code, const char *message) {
    if (message) {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr, "Usage: %s <ip address> <port> <proxy ip address> <proxy port> [-h]\n", program_name);
    fputs("Options:\n", stderr);
    fputs("  -h  Display this help message\n", stderr);
    exit(exit_code);
}

static void convert_address(const char *address, struct sockaddr_storage *addr, socklen_t *addr_len) {
    memset(addr, 0, sizeof(*addr));

    if (inet_pton(AF_INET, address, &(((struct sockaddr_in *) addr)->sin_addr)) == 1) {
        addr->ss_family = AF_INET;
        *addr_len = sizeof(struct sockaddr_in);
    } else if (inet_pton(AF_INET6, address, &(((struct sockaddr_in6 *) addr)->sin6_addr)) == 1) {
        addr->ss_family = AF_INET6;
        *addr_len = sizeof(struct sockaddr_in6);
    } else {
        fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", address);
        exit(EXIT_FAILURE);
    }
}

static int socket_create(int domain, int type, int protocol) {
    int sockfd;

    sockfd = socket(domain, type, protocol);

    if (sockfd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

static void socket_bind(int sockfd, struct sockaddr_storage *addr, in_port_t port) {
    char addr_str[INET6_ADDRSTRLEN];
    socklen_t addr_len;
    void *vaddr;
    in_port_t net_port;

    net_port = htons(port);

    if (addr->ss_family == AF_INET) {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr = (struct sockaddr_in *) addr;
        addr_len = sizeof(*ipv4_addr);
        ipv4_addr->sin_port = net_port;
        vaddr = (void *) &(((struct sockaddr_in *) addr)->sin_addr);
    } else if (addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr = (struct sockaddr_in6 *) addr;
        addr_len = sizeof(*ipv6_addr);
        ipv6_addr->sin6_port = net_port;
        vaddr = (void *) &(((struct sockaddr_in6 *) addr)->sin6_addr);
    } else {
        fprintf(stderr, "Internal error: addr->ss_family must be AF_INET or AF_INET6, was: %d\n", addr->ss_family);
        exit(EXIT_FAILURE);
    }

    if (inet_ntop(addr->ss_family, vaddr, addr_str, sizeof(addr_str)) == NULL) {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    printf("Binding to: %s:%u\n", addr_str, port);

    if (bind(sockfd, (struct sockaddr *) addr, addr_len) == -1) {
        perror("Binding failed");
        fprintf(stderr, "Error code: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    printf("Bound to socket: %s:%u\n", addr_str, port);
}

static void get_address_to_server(struct sockaddr_storage *addr, in_port_t port) {
    if (addr->ss_family == AF_INET) {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr = (struct sockaddr_in *) addr;
        ipv4_addr->sin_family = AF_INET;
        ipv4_addr->sin_port = htons(port);
    } else if (addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr = (struct sockaddr_in6 *) addr;
        ipv6_addr->sin6_family = AF_INET6;
        ipv6_addr->sin6_port = htons(port);
    }
}

static void socket_close(int sockfd) {
    if (close(sockfd) == -1) {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}

void handle_timeout(int signal) {
    timeout_occured = 1;
}
// Rework this to implement go back n.

void file_data(FILE *file, int sockfd, struct sockaddr_storage *addr) {
    signal(SIGALRM, handle_timeout);
    char line[LINE_LEN];
    char *wordptr;
    int seq_num = 0;
    int base = 0;
    Packet *packets[10]; // Packets buffer to be used for selective repeat.
    ssize_t bytes_sent = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        char *word;
        word = strtok_r(line, " \t\n", &wordptr);
        while (word != NULL) {
            size_t word_len = strlen(word);
            if (word_len > UINT8_MAX) {
                fprintf(stderr, "Word exceeds maximum length\n");
                fclose(file);
                close(sockfd);
                exit(EXIT_FAILURE);
            }
            printf("Word: %s \n", word);
            Packet *packet = make_packet(seq_num, 0, "", word);
            packets[seq_num % 10] = packet;
            seq_num++;

            if (seq_num <= 10 + base) {
                for (int i = base; i < base + 10 && i < seq_num; i++) {
                    bytes_sent = sendto(sockfd, word, word_len, 0, (struct sockaddr *) addr, sizeof(*addr));
                }
            }

            timeout_occured = false;
            alarm((unsigned int) 0.01);

            //handle acks here
            // if ack received then
            // base++
            // reset the timer
            //


            if(timeout_occured) {
                for (int i = base; i < base + 10 && i < seq_num; i++) {
                    bytes_sent = sendto(sockfd, word, word_len, 0, (struct sockaddr *) addr, sizeof(*addr));
                }
                timeout_occured = false;
            }


            if (bytes_sent < 0) {
                perror("Error sending word content");
                fclose(file);
                close(sockfd);
                exit(EXIT_FAILURE);
            }
            word = strtok_r(NULL, " \t\n", &wordptr);

            for (int i = base; i < base + 10 && i < seq_num; i++) {
                // If ACK received for packet i, remove it from the buffer
//                free(packets[i % 10]->data);
//                free(packets[i % 10]->flags);
                free(packets[i % 10]);
            }
            base = seq_num; // Move the window forward
        }
    }

}

FILE *file_open(char *file_path) {
    FILE *file;
    file = fopen(file_path, "r");
    if (file == NULL) {
        perror("File doesn't exist");
        exit(EXIT_FAILURE);
    }
    if (!file_check(file_path)) {
        exit(EXIT_FAILURE);
    } else {
        return file;
    }
}

int file_check(char *file_path) {
    FILE *file = fopen(file_path, "r");
    fseek(file, 0, SEEK_END);
    fclose(file);
    int check;
    if (ftell(file) == 0) {
        fprintf(stderr, "File is empty.\n");
        check = 0;
    } else {
        check = 1;
    }
    return check;
}

Packet *make_packet(int seq_num, int ack_num, char* flags, char* data) {
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    if (packet == NULL) {
        perror("Error allocating memory for packet");
        exit(EXIT_FAILURE);
    }

    packet->seq_num = seq_num;
    strcpy(packet->data, data);

    return packet;
}
