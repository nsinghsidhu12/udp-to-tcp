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

static void parse_arguments(int argc, char *argv[], char **ip_address, char **port);

static void handle_arguments(const char *binary_name, const char *ip_address, const char *port_str, in_port_t *port);

static in_port_t parse_in_port_t(const char *binary_name, const char *port_str);

_Noreturn static void usage(const char *program_name, int exit_code, const char *message);

static void convert_address(const char *address, struct sockaddr_storage *addr);

static int socket_create(int domain, int type, int protocol);

static void socket_bind(int sockfd, struct sockaddr_storage *addr, in_port_t port);

static void handle_packet(int client_sockfd, struct sockaddr_storage *client_addr);

static void socket_close(int sockfd);

void send_ACK(int client_sockfd, struct sockaddr_storage *client_addr, int seq, socklen_t address_len);

void handle_client(int sockfd, struct sockaddr_storage *addr, socklen_t addr_len);

#define UNKNOWN_OPTION_MESSAGE_LEN 24
#define LINE_LEN 1024
#define BASE_TEN 10
#define END_STRING ")))"

struct __attribute__((packed)) PACKET {
    int seq_num;
    char data [256];
} typedef Packet;

int main(int argc, char *argv[]) {
    char *address;
    char *port_str;
    char buffer[LINE_LEN + 1];
    in_port_t port;
    int sockfd;
    ssize_t bytes_received;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    struct sockaddr_storage addr;


    address = NULL;
    port_str = NULL;
    parse_arguments(argc, argv, &address, &port_str);
    handle_arguments(argv[0], address, port_str, &port);
    convert_address(address, &addr);
    sockfd = socket_create(addr.ss_family, SOCK_DGRAM, 0);
    socket_bind(sockfd, &addr, port);
    client_addr_len = sizeof(client_addr);
//    bytes_received = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *) &client_addr,
//                              &client_addr_len);
//
//    if (bytes_received == -1) {
//        perror("recvfrom");
//    }
//
//    buffer[(size_t) bytes_received] = '\0';
    handle_packet(sockfd, &client_addr);
//    printf("Client sent: %s", buffer);
//    sendto(sockfd, "helloback", 9 + 1, 0, (struct sockaddr*) &client_addr, client_addr_len);

//    bytes_received = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *) &client_addr,
//                              &client_addr_len);
//
//    if (bytes_received == -1) {
//        perror("recvfrom");
//    }
//
//    buffer[(size_t) bytes_received] = '\0';
//    handle_packet(sockfd, &client_addr, buffer, (size_t) bytes_received);
//
//    sendto(sockfd, "helloback", 9 + 1, 0, (struct sockaddr*) &client_addr, client_addr_len);
//    send(sockfd, buffer, (size_t) bytes_received, 0);
    socket_close(sockfd);

    return EXIT_SUCCESS;
}

static void parse_arguments(int argc, char *argv[], char **ip_address, char **port) {
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

    if (optind >= argc) {
        usage(argv[0], EXIT_FAILURE, "The ip address and port are required");
    }

    if (optind + 1 >= argc) {
        usage(argv[0], EXIT_FAILURE, "The port is required");
    }

    if (optind < argc - 2) {
        usage(argv[0], EXIT_FAILURE, "Error: Too many arguments.");
    }

    *ip_address = argv[optind];
    *port = argv[optind + 1];
}

static void handle_arguments(const char *binary_name, const char *ip_address, const char *port_str, in_port_t *port) {
    if (ip_address == NULL) {
        usage(binary_name, EXIT_FAILURE, "The ip address is required.");
    }

    if (port_str == NULL) {
        usage(binary_name, EXIT_FAILURE, "The port is required.");
    }

    *port = parse_in_port_t(binary_name, port_str);
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

    fprintf(stderr, "Usage: %s <ip address> <port> [-h]\n", program_name);
    fputs("Options:\n", stderr);
    fputs("  -h  Display this help message\n", stderr);
    exit(exit_code);
}

static void convert_address(const char *address, struct sockaddr_storage *addr) {
    memset(addr, 0, sizeof(*addr));

    if (inet_pton(AF_INET, address, &(((struct sockaddr_in *) addr)->sin_addr)) == 1) {
        addr->ss_family = AF_INET;
    } else if (inet_pton(AF_INET6, address, &(((struct sockaddr_in6 *) addr)->sin6_addr)) == 1) {
        addr->ss_family = AF_INET6;
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

Packet *make_packet(int seq_num, char* data) {
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    if (packet == NULL) {
        perror("Error allocating memory for Packet");
        exit(EXIT_FAILURE);
    }
    packet->seq_num = seq_num;
    strcpy(packet->data, data);
    return packet;
}

void handle_packet(int sockfd, struct sockaddr_storage *addr) {
    socklen_t addr_len = sizeof(&addr);
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    int last_ack = -1; // Last ACKed sequence number
    int expected_seq_num = 0; // Expected next sequence number
    while (1) {
        ssize_t bytes_received = recvfrom(sockfd, packet, sizeof(Packet), 0, (struct sockaddr *) addr, &addr_len);
        if (bytes_received == -1) {
            perror("recvfrom");
            exit(EXIT_FAILURE);
        }

        if (packet->seq_num == expected_seq_num) {
            // ACKs
            last_ack = packet->seq_num;
            printf("Received packet: %s, seq_num: %d\n", packet->data, packet->seq_num);
            printf("Sending ACK: %d\n", last_ack);
            Packet *ack_packet = make_packet(last_ack, "ACK");
            sendto(sockfd, ack_packet, sizeof(Packet) + 1, 0, (struct sockaddr *) addr, addr_len);
            free(ack_packet);
            expected_seq_num++;
        } else {
            printf("Got: Seq: %d, Expecting: Seq: %d\n", packet->seq_num, expected_seq_num);
            printf("Packet info: %s, %d\n", packet->data,packet->seq_num);
            printf("Sending ACK: %d\n", last_ack);
            Packet *ack_packet = make_packet(last_ack, "ACK");
            sendto(sockfd, ack_packet, sizeof(Packet) + 1, 0, (struct sockaddr *) addr, addr_len);
            free(ack_packet);
        }
//        free(packet);
    }
}

static void socket_close(int sockfd) {
    if (close(sockfd) == -1) {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}