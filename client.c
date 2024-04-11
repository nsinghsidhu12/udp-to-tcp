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

void handle_timeout(int signal);

struct __attribute__((packed)) PACKET {
    int seq_num;
    char data[256];
} typedef Packet;

Packet *make_packet(int seq_num, char* data);

char **word_maker(char *buffer);

void send_packets(int sockfd, struct sockaddr_storage *addr, char *message);

#define UNKNOWN_OPTION_MESSAGE_LEN 24
#define BASE_TEN 10
#define LINE_LEN 1024
#define WINDOW_SIZE 10

static volatile sig_atomic_t timeout_occurred = 0;

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
    struct sigaction myAction;

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
    send_packets(sockfd, &server_socket_addr, message);

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
    timeout_occurred = 1;
    printf("In Timeout\n");
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

char **word_maker(char *buffer) {
    size_t size = strlen(buffer);
    char **words = malloc(size * sizeof(char *));
    if (words == NULL) {
        perror("Words array memory allocation failed");
        exit(EXIT_FAILURE);
    }
    int word_count = 0;
    char *token = strtok(buffer, " \t\n");
    while (token != NULL) {
        words[word_count++] = token;
        token = strtok(NULL, " \t\n");
    }
    return words;
}

void send_window_packets(int sockfd, struct sockaddr_storage *addr, char **words, int word_count, Packet **packets, const int *base, int *next_seq, socklen_t addr_len) {
    while (*next_seq < (*base + WINDOW_SIZE) && *next_seq < word_count) {
        Packet *packet = make_packet(*next_seq, words[*next_seq]);
        packets[*next_seq % WINDOW_SIZE] = packet;
        ssize_t bytes_sent = sendto(sockfd, packet, sizeof(Packet) + 1, 0, (struct sockaddr *)addr, addr_len);
        printf("Packet sent Data: %s Seq: %d\n", packet->data, packet->seq_num);
        (*next_seq)++;
    }
}

void send_packets(int sockfd, struct sockaddr_storage *addr, char *message) {
    signal(SIGALRM, handle_timeout);
    char **words = word_maker(message);
    int word_count = 0;

    for (int i = 0; words[i] != NULL; i++) {
        word_count++;
    }

    Packet *packets[WINDOW_SIZE];
    int seq = 0;
    int base = 0;
    int next_seq = 0;
    socklen_t addr_len = sizeof(*addr);
    ssize_t bytes_sent;
    int ack = 0;

    while (base < word_count) {
        send_window_packets(sockfd, addr, words, word_count, packets, &base, &next_seq, addr_len);
        alarm(1);

        while (ack < WINDOW_SIZE) {
            Packet *ack_packet = (Packet *)malloc(sizeof(Packet));
            ssize_t bytes_received = recvfrom(sockfd, ack_packet, sizeof(Packet) + 1, 0, (struct sockaddr *)addr, &addr_len);

            if (bytes_received < 0) {
                perror("No ACKs received");
                close(sockfd);
                exit(EXIT_FAILURE);
            }

            if (bytes_received > 0) {
                printf("Received ACK: Seq: %d\n", ack_packet->seq_num);
                ack++;
                if (ack_packet->seq_num == base) {
                    while (base < next_seq) {
                        base++;
                    }

                    alarm(0);
                    break;
                }
            }
            free(ack_packet);
        }
        if (timeout_occurred) {
            printf("timeout\n");
            for (int i = base; i < next_seq; i++) {
                    Packet *packet = packets[i % WINDOW_SIZE];
                    bytes_sent = sendto(sockfd, packet, sizeof(Packet) + 1, 0, (struct sockaddr *)addr, addr_len);
                    printf("Retransmitted Packet Data: %s Seq: %d\n", packet->data, packet->seq_num);

                    if (bytes_sent < 0) {
                        break;
                    }
            }
        }
        ack = 0;
    }

    for (int i = 0; i < WINDOW_SIZE; i++) {
        printf("%s %d\n", packets[i]->data, packets[i]->seq_num);
        free(packets[i]);
    }

    free(*words);
}












