#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

struct __attribute__((packed)) PACKET {
    int seq_num;
    char data[256];
} typedef Packet;

static void parse_arguments(int argc, char *argv[], char **ip_address, char **port);

static void handle_arguments(const char *program_name, const char *ip_address, const char *port_str, in_port_t *port);

static in_port_t parse_in_port_t(const char *program_name, const char *port_str);

_Noreturn static void usage(const char *program_name, int exit_code, const char *message);

static void handle_exit_failure(int socket_fd);

static void initialize_address(char *ip_address, in_port_t port, struct sockaddr_storage *socket_addr,
                               socklen_t *socket_addr_len, int *socket_fd);

static void convert_address(const char *ip_address, struct sockaddr_storage *socket_addr, socklen_t *socket_addr_len);

static int create_socket(int domain);

static void bind_socket(int socket_fd, struct sockaddr_storage *socket_addr, in_port_t port);

static void setup_signal_handler();

static void sigint_handler(int signum);

static void handle_server(int socket_fd, struct sockaddr_storage *socket_addr);

static void handle_transmission(int socket_fd, int last_ack, struct sockaddr_storage dest_socket_addr,
                                socklen_t dest_socket_addr_len);

static void send_packet(int socket_fd, Packet *buffer, struct sockaddr_storage dest_socket_addr,
                        socklen_t dest_socket_addr_len);

static void close_socket(int socket_fd);



#define LINE_LEN 1024
#define UNKNOWN_OPTION_MESSAGE_LEN 24
#define BASE_TEN 10
#define END_STRING "FIN"
#define START_STRING "SYN"

static volatile sig_atomic_t exit_flag = 0;

int main(int argc, char *argv[]) {
    char *server_ip_address;
    char *server_port_str;
    in_port_t server_port;
    int socket_fd;
    struct sockaddr_storage server_socket_addr;
    socklen_t server_socket_addr_len;
    struct sockaddr_storage sender_socket_addr;

    parse_arguments(argc, argv, &server_ip_address, &server_port_str);
    handle_arguments(argv[0], server_ip_address, server_port_str, &server_port);

    initialize_address(server_ip_address, server_port, &server_socket_addr,
                       &server_socket_addr_len, &socket_fd);

    setup_signal_handler();

    handle_server(socket_fd, &sender_socket_addr);

    close_socket(socket_fd);

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

static void handle_arguments(const char *program_name, const char *ip_address, const char *port_str, in_port_t *port) {
    if (ip_address == NULL) {
        usage(program_name, EXIT_FAILURE, "The ip address is required.");
    }

    if (port_str == NULL) {
        usage(program_name, EXIT_FAILURE, "The port is required.");
    }

    *port = parse_in_port_t(program_name, port_str);
}

in_port_t parse_in_port_t(const char *program_name, const char *str) {
    char *end_ptr;
    uintmax_t parsed_value;

    errno = 0;
    parsed_value = strtoumax(str, &end_ptr, BASE_TEN);

    if (errno != 0) {
        perror("Error parsing in_port_t");
        exit(EXIT_FAILURE);
    }

    if (*end_ptr != '\0') {
        usage(program_name, EXIT_FAILURE, "Invalid characters in input.");
    }

    if (parsed_value > UINT16_MAX) {
        usage(program_name, EXIT_FAILURE, "in_port_t value out of range.");
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

static void handle_exit_failure(int socket_fd) {
    if (socket_fd != -1) {
        close_socket(socket_fd);
    }

    exit(EXIT_FAILURE);
}

static void initialize_address(char *ip_address, in_port_t port, struct sockaddr_storage *socket_addr,
                               socklen_t *socket_addr_len, int *socket_fd) {
    convert_address(ip_address, socket_addr, socket_addr_len);
    *socket_fd = create_socket(socket_addr->ss_family);
    bind_socket(*socket_fd, socket_addr, port);
}

static void convert_address(const char *ip_address, struct sockaddr_storage *socket_addr, socklen_t *socket_addr_len) {
    memset(socket_addr, 0, sizeof(*socket_addr));

    if (inet_pton(AF_INET, ip_address, &(((struct sockaddr_in *) socket_addr)->sin_addr)) == 1) {
        socket_addr->ss_family = AF_INET;
        *socket_addr_len = sizeof(struct sockaddr_in);
    } else if (inet_pton(AF_INET6, ip_address, &(((struct sockaddr_in6 *) socket_addr)->sin6_addr)) == 1) {
        socket_addr->ss_family = AF_INET6;
        *socket_addr_len = sizeof(struct sockaddr_in6);
    } else {
        fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", ip_address);
        handle_exit_failure(-1);
    }
}

static int create_socket(int domain) {
    int socket_fd;

    socket_fd = socket(domain, SOCK_DGRAM, 0);

    if (socket_fd == -1) {
        perror("Socket creation failed");
        handle_exit_failure(-1);
    }

    return socket_fd;
}

static void bind_socket(int socket_fd, struct sockaddr_storage *socket_addr, in_port_t port) {
    char addr_str[INET6_ADDRSTRLEN];
    socklen_t addr_len = 0;
    void *v_addr;
    in_port_t net_port;

    net_port = htons(port);

    if (socket_addr->ss_family == AF_INET) {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr = (struct sockaddr_in *) socket_addr;
        addr_len = sizeof(*ipv4_addr);
        ipv4_addr->sin_port = net_port;
        v_addr = (void *) &(((struct sockaddr_in *) socket_addr)->sin_addr);
    } else if (socket_addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr = (struct sockaddr_in6 *) socket_addr;
        addr_len = sizeof(*ipv6_addr);
        ipv6_addr->sin6_port = net_port;
        v_addr = (void *) &(((struct sockaddr_in6 *) socket_addr)->sin6_addr);
    } else {
        fprintf(stderr, "Internal error: addr->ss_family must be AF_INET or AF_INET6, was: %d\n",
                socket_addr->ss_family);
        handle_exit_failure(socket_fd);
    }

    if (inet_ntop(socket_addr->ss_family, v_addr, addr_str, sizeof(addr_str)) == NULL) {
        perror("inet_ntop");
        handle_exit_failure(socket_fd);
    }

    printf("Binding to: %s:%u\n", addr_str, port);

    if (bind(socket_fd, (struct sockaddr *) socket_addr, addr_len) == -1) {
        perror("Binding failed");
        fprintf(stderr, "Error code: %d\n", errno);
        handle_exit_failure(socket_fd);
    }

    printf("Bound to socket: %s:%u\n", addr_str, port);
}

static void setup_signal_handler(void) {
    struct sigaction sig_action;

    memset(&sig_action, 0, sizeof(sig_action));

    sig_action.sa_handler = sigint_handler;

    sigemptyset(&sig_action.sa_mask);
    sig_action.sa_flags = 0;

    if (sigaction(SIGINT, &sig_action, NULL) == -1) {
        perror("sigaction");
        handle_exit_failure(-1);
    }
}

static void sigint_handler(int signum) {
    exit_flag = 1;
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

void handle_server(int socket_fd, struct sockaddr_storage *socket_addr) {
    static struct timespec start_time = {0, 0};
    if (start_time.tv_sec == 0 && start_time.tv_nsec == 0) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
    }

    while (!exit_flag) {
        socklen_t addr_len = sizeof(&socket_addr);
        Packet *packet = (Packet *) malloc(sizeof(Packet));
        int last_ack = -1; // Last ACKed sequence number
        int expected_seq_num = 0; // Expected next sequence number
        int continue_flag = 0;
        ssize_t bytes_received = recvfrom(socket_fd, packet, sizeof(Packet), 0, (struct sockaddr *) socket_addr, &addr_len);

        if (bytes_received == -1) {
            perror("recvfrom");
            handle_exit_failure(socket_fd);
        }

        if (packet->seq_num > 0 || strcmp(packet->data, END_STRING) == 0) {
            last_ack = packet->seq_num;
            printf("Received packet from last time: data: %s, seq_num: %d\n", packet->data, packet->seq_num);
            printf("Sending ACK: %d\n", last_ack);

            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            double elapsed_time = (now.tv_sec - start_time.tv_sec) + (now.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("Elapsed time: %f seconds\n", elapsed_time);
            handle_transmission(socket_fd, last_ack, *socket_addr, addr_len);
            continue;
        }

        if (packet->seq_num == expected_seq_num) {
            continue_flag = 1;
            last_ack = packet->seq_num;
            printf("Received packet, data: %s, seq_num: %d\n", packet->data, packet->seq_num);
            printf("Sending ACK: %d\n", last_ack);
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            double elapsed_time = (now.tv_sec - start_time.tv_sec) + (now.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("Elapsed time: %f seconds\n", elapsed_time);

            handle_transmission(socket_fd, last_ack, *socket_addr, addr_len);
            expected_seq_num++;
        } else {
            printf("Received packet out of order, duplicate, or corrupted: seq_num: %d\n", packet->seq_num);
            printf("Packet info: %s, %d\n", packet->data,packet->seq_num);
            printf("Sending ACK: %d\n", last_ack);

            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            double elapsed_time = (now.tv_sec - start_time.tv_sec) + (now.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("Elapsed time: %f seconds\n", elapsed_time);
            handle_transmission(socket_fd, last_ack, *socket_addr, addr_len);
        }

        while (continue_flag) {
            bytes_received = recvfrom(socket_fd, packet, sizeof(Packet), 0, (struct sockaddr *) socket_addr, &addr_len);

            if (bytes_received == -1) {
                perror("recvfrom");
                handle_exit_failure(socket_fd);
            }

            if (strcmp(packet->data, START_STRING) == 0) {
                printf("==============================\n");
                printf("       New Connection\n         ");
                printf("==============================\n");
                handle_transmission(socket_fd, 0, *socket_addr, addr_len);
                expected_seq_num = 1;
                continue;
            }

            if (packet->seq_num == expected_seq_num) {
                if (strcmp(packet->data, END_STRING) == 0) {
                    continue_flag = 0;
                    last_ack = packet->seq_num;
                    printf("Received packet, data: %s, seq_num: %d\n", packet->data, packet->seq_num);
                    printf("Sending ACK: %d\n", last_ack);
                    struct timespec now;
                    clock_gettime(CLOCK_MONOTONIC, &now);
                    double elapsed_time = (now.tv_sec - start_time.tv_sec) + (now.tv_nsec - start_time.tv_nsec) / 1e9;
                    printf("Elapsed time: %f seconds\n", elapsed_time);
                    handle_transmission(socket_fd, last_ack, *socket_addr, addr_len);
                    expected_seq_num++;
                } else {
                    last_ack = packet->seq_num;
                    printf("Received packet, data: %s, seq_num: %d\n", packet->data, packet->seq_num);
                    printf("Sending ACK: %d\n", last_ack);
                    struct timespec now;
                    clock_gettime(CLOCK_MONOTONIC, &now);
                    double elapsed_time = (now.tv_sec - start_time.tv_sec) + (now.tv_nsec - start_time.tv_nsec) / 1e9;
                    printf("Elapsed time: %f seconds\n", elapsed_time);
                    handle_transmission(socket_fd, last_ack, *socket_addr, addr_len);
                    expected_seq_num++;
                }

            } else {
                printf("Received packet out of order, duplicate, or corrupted: seq_num: %d\n", packet->seq_num);
                printf("Packet info, data: %s, seq_num: %d\n", packet->data,packet->seq_num);
                printf("Sending ACK: %d\n", last_ack);
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                double elapsed_time = (now.tv_sec - start_time.tv_sec) + (now.tv_nsec - start_time.tv_nsec) / 1e9;
                printf("Elapsed time: %f seconds\n", elapsed_time);
                handle_transmission(socket_fd, last_ack, *socket_addr, addr_len);
            }
        }
    }
}

static void handle_transmission(int socket_fd, int last_ack, struct sockaddr_storage dest_socket_addr, socklen_t dest_socket_addr_len) {
    Packet *ack_packet = make_packet(last_ack, "ACK");
    send_packet(socket_fd, ack_packet, dest_socket_addr, dest_socket_addr_len);
    free(ack_packet);
}


static void send_packet(int socket_fd, Packet *buffer, struct sockaddr_storage dest_socket_addr,
                        socklen_t dest_socket_addr_len) {
    ssize_t bytes_sent = sendto(socket_fd, buffer, sizeof(Packet), 0,
                                (struct sockaddr *) &dest_socket_addr, dest_socket_addr_len);

    if (bytes_sent == -1) {
        perror("sendto");
        handle_exit_failure(socket_fd);
    }
}

static void close_socket(int socket_fd) {
    if (close(socket_fd) == -1) {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}