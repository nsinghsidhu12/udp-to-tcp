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

struct __attribute__((packed)) PACKET {
    int seq_num;
    int ack_num;
    char data[256];
} typedef Packet;

static void parse_arguments(int argc, char *argv[], char **client_ip_address, char **client_port_str,
                            char **dest_ip_address, char **dest_port_str, char **file_path);

static void handle_arguments(char *program_name, const char *client_ip_address, const char *client_port_str,
                             const char *dest_ip_address, const char *dest_port_str, const char *file_path,
                             in_port_t *client_port, in_port_t *dest_port);

static void verify_file(char *file_path);

static void check_file_exists(FILE *file);

static void check_file_size(FILE *file);

static in_port_t parse_in_port_t(const char *program_name, const char *port_str);

_Noreturn static void usage(const char *program_name, int exit_code, const char *message);

static void handle_exit_failure(int socket_fd, FILE *file);

static void initialize_address(char *ip_address, in_port_t port, struct sockaddr_storage *socket_addr,
                               socklen_t *socket_addr_len, int *socket_fd);

static void convert_address(char *ip_address, struct sockaddr_storage *socket_addr, socklen_t *socket_addr_len);

static void get_destination_address(struct sockaddr_storage *socket_addr, in_port_t port);

static int create_socket(int domain);

static void bind_socket(int socket_fd, struct sockaddr_storage *socket_addr, in_port_t port);

static void read_file(char *file_path, int socket_fd, struct sockaddr_storage socket_addr);

static void timeout_handler(int signum);

static void handle_transmission(int socket_fd, char *data, struct sockaddr_storage dest_socket_addr, int *seq_num,
                                int *ack_num);

static void validate_word(int socket_fd, char *word);

static Packet *make_packet(int seq_num, int ack_num, char *data);

static void send_packet(int socket_fd, Packet *buffer, struct sockaddr_storage dest_socket_addr,
                        socklen_t dest_socket_addr_len);

static void close_socket(int socket_fd);

static void close_file(FILE *file);

#define LINE_LEN 1024
#define UNKNOWN_OPTION_MESSAGE_LEN 24
#define BASE_TEN 10

static volatile sig_atomic_t timeout_flag = 0;

int main(int argc, char *argv[]) {
    char *client_ip_address;
    char *client_port_str;
    in_port_t client_port;
    char *dest_ip_address;
    char *dest_port_str;
    in_port_t dest_port;
    char *file_path;
    int socket_fd;
    struct sockaddr_storage client_socket_addr;
    socklen_t client_socket_addr_len;
    struct sockaddr_storage dest_socket_addr;
    socklen_t dest_socket_addr_len;

    parse_arguments(argc, argv, &client_ip_address, &client_port_str, &dest_ip_address, &dest_port_str,
                    &file_path);
    handle_arguments(argv[0], client_ip_address, client_port_str, dest_ip_address, dest_port_str,
                     file_path, &client_port, &dest_port);

    verify_file(file_path);

    initialize_address(client_ip_address, client_port, &client_socket_addr,
                       &client_socket_addr_len, &socket_fd);

    convert_address(dest_ip_address, &dest_socket_addr, &dest_socket_addr_len);
    get_destination_address(&dest_socket_addr, dest_port);

    read_file(file_path, socket_fd, dest_socket_addr);
    close_socket(socket_fd);

    return EXIT_SUCCESS;
}

static void parse_arguments(int argc, char *argv[], char **client_ip_address, char **client_port_str,
                            char **dest_ip_address, char **dest_port_str, char **file_path) {
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
    *dest_ip_address = argv[optind + 2];
    *dest_port_str = argv[optind + 3];
    *file_path = argv[optind + 4];
}

static void handle_arguments(char *program_name, const char *client_ip_address, const char *client_port_str,
                             const char *dest_ip_address, const char *dest_port_str, const char *file_path,
                             in_port_t *client_port, in_port_t *dest_port) {
    if (client_ip_address == NULL) {
        usage(program_name, EXIT_FAILURE, "The client ip address is required.");
    }

    if (client_port_str == NULL) {
        usage(program_name, EXIT_FAILURE, "The client port is required.");
    }

    if (dest_ip_address == NULL) {
        usage(program_name, EXIT_FAILURE, "The destination ip address is required.");
    }

    if (dest_port_str == NULL) {
        usage(program_name, EXIT_FAILURE, "The destination port is required.");
    }

    if (file_path == NULL) {
        usage(program_name, EXIT_FAILURE, "The file path is required.");
    }

    *client_port = parse_in_port_t(program_name, client_port_str);
    *dest_port = parse_in_port_t(program_name, dest_port_str);
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

static void handle_exit_failure(int socket_fd, FILE *file) {
    if (socket_fd != -1) {
        close_socket(socket_fd);
    }

    if (file != NULL) {
        close_file(file);
    }

    exit(EXIT_FAILURE);
}

static void verify_file(char *file_path) {
    FILE *file = fopen(file_path, "r");

    check_file_exists(file);
    check_file_size(file);
    close_file(file);
}

static void check_file_size(FILE *file) {
    fseek(file, 0, SEEK_END);

    if (ftell(file) == 0) {
        fprintf(stderr, "The file is empty\n");
        handle_exit_failure(-1, file);
    }
}

static void check_file_exists(FILE *file) {
    if (file == NULL) {
        fprintf(stderr, "The file does not exist");
        handle_exit_failure(-1, file);
    }
}

in_port_t parse_in_port_t(const char *program_name, const char *str) {
    char *end_ptr;
    uintmax_t parsed_value;

    errno = 0;
    parsed_value = strtoumax(str, &end_ptr, BASE_TEN);

    if (errno != 0) {
        perror("Error parsing in_port_t");
        handle_exit_failure(-1, NULL);
    }

    if (*end_ptr != '\0') {
        usage(program_name, EXIT_FAILURE, "Invalid characters in input.");
    }

    if (parsed_value > UINT16_MAX) {
        usage(program_name, EXIT_FAILURE, "in_port_t value out of range.");
    }

    return (in_port_t) parsed_value;
}

static void initialize_address(char *ip_address, in_port_t port, struct sockaddr_storage *socket_addr,
                               socklen_t *socket_addr_len, int *socket_fd) {
    convert_address(ip_address, socket_addr, socket_addr_len);
    *socket_fd = create_socket(socket_addr->ss_family);
    bind_socket(*socket_fd, socket_addr, port);
}

static void convert_address(char *ip_address, struct sockaddr_storage *socket_addr, socklen_t *socket_addr_len) {
    memset(socket_addr, 0, sizeof(*socket_addr));

    if (inet_pton(AF_INET, ip_address, &(((struct sockaddr_in *) socket_addr)->sin_addr)) == 1) {
        socket_addr->ss_family = AF_INET;
        *socket_addr_len = sizeof(struct sockaddr_in);
    } else if (inet_pton(AF_INET6, ip_address, &(((struct sockaddr_in6 *) socket_addr)->sin6_addr)) == 1) {
        socket_addr->ss_family = AF_INET6;
        *socket_addr_len = sizeof(struct sockaddr_in6);
    } else {
        fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", ip_address);
        handle_exit_failure(-1, NULL);
    }
}

static void get_destination_address(struct sockaddr_storage *socket_addr, in_port_t port) {
    if (socket_addr->ss_family == AF_INET) {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr = (struct sockaddr_in *) socket_addr;
        ipv4_addr->sin_family = AF_INET;
        ipv4_addr->sin_port = htons(port);
    } else if (socket_addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr = (struct sockaddr_in6 *) socket_addr;
        ipv6_addr->sin6_family = AF_INET6;
        ipv6_addr->sin6_port = htons(port);
    }
}

static int create_socket(int domain) {
    int socket_fd;

    socket_fd = socket(domain, SOCK_DGRAM, 0);

    if (socket_fd == -1) {
        perror("Socket creation failed");
        handle_exit_failure(-1, NULL);
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
        handle_exit_failure(socket_fd, NULL);
    }

    if (inet_ntop(socket_addr->ss_family, v_addr, addr_str, sizeof(addr_str)) == NULL) {
        perror("inet_ntop");
        handle_exit_failure(socket_fd, NULL);
    }

    printf("Binding to: %s:%u\n", addr_str, port);

    if (bind(socket_fd, (struct sockaddr *) socket_addr, addr_len) == -1) {
        fprintf(stderr, "Error code: %d\n", errno);
        handle_exit_failure(socket_fd, NULL);
    }

    printf("Bound to socket: %s:%u\n", addr_str, port);
}

static void read_file(char *file_path, int socket_fd, struct sockaddr_storage socket_addr) {
    signal(SIGALRM, timeout_handler);
    FILE *file = fopen(file_path, "r");
    char line[LINE_LEN];
    char *word_ptr;
    int seq_num = 0;
    int ack_num = 0;

    handle_transmission(socket_fd, "end_conn", socket_addr, &seq_num, &ack_num);

    while (fgets(line, sizeof(line), file) != NULL) {
        char *word;
        word = strtok_r(line, " \t\n", &word_ptr);

        while (word != NULL) {
            validate_word(socket_fd, word);
            handle_transmission(socket_fd, word, socket_addr, &seq_num, &ack_num);
            word = strtok_r(NULL, " \t\n", &word_ptr);
        }
    }

    handle_transmission(socket_fd, "end_conn", socket_addr, &seq_num, &ack_num);
}

static void timeout_handler(int signum) {
    timeout_flag = 1;
}

static void handle_transmission(int socket_fd, char *data, struct sockaddr_storage dest_socket_addr, int *seq_num,
        int *ack_num) {
    socklen_t dest_socket_addr_len = sizeof(dest_socket_addr);
    Packet *packet = make_packet(*seq_num, *ack_num, data);
    send_packet(socket_fd, packet, dest_socket_addr, dest_socket_addr_len);
    *seq_num = *seq_num + 1;
    alarm(3);
    Packet ack;

    int continue_flag = 1;

    while (continue_flag) {
        ssize_t bytes_received = recvfrom(socket_fd, &ack, sizeof(Packet), MSG_DONTWAIT, (struct sockaddr *) &dest_socket_addr,
                                          &dest_socket_addr_len);
        if (bytes_received == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (timeout_flag == 1) {
                printf("Packet retransmitting: %s, %d\n", packet->data, packet->seq_num);
                send_packet(socket_fd, packet, dest_socket_addr, dest_socket_addr_len);
                alarm(3);
                timeout_flag = 0;
            }
        } else if (bytes_received >= 0) {
            if (ack.seq_num + 1 == *seq_num) {
                alarm(3);
                continue_flag = 0;
            }
            timeout_flag = 0;
            printf("Received ACK: %d\n", ack.seq_num);
        }
    }

    free(packet);
}

static void validate_word(int socket_fd, char *word) {
    size_t word_len = strlen(word);

    if (word_len > UINT8_MAX) {
        fprintf(stderr, "Word exceeds maximum length of 256");
        handle_exit_failure(socket_fd, NULL);
    }
}

static Packet *make_packet(int seq_num, int ack_num, char *data) {
    Packet *packet = (Packet *) malloc(sizeof(Packet));

    if (packet == NULL) {
        perror("Error allocating memory for Packet");
        exit(EXIT_FAILURE);
    }

    packet->seq_num = seq_num;
    packet->ack_num = ack_num;
    strcpy(packet->data, data);

    printf("Packet Created: %s, %d\n", packet->data, packet->seq_num);

    return packet;
}

static void send_packet(int socket_fd, Packet *buffer, struct sockaddr_storage dest_socket_addr,
                        socklen_t dest_socket_addr_len) {
    ssize_t bytes_sent = sendto(socket_fd, buffer, sizeof(Packet), 0,
                                (struct sockaddr *) &dest_socket_addr, dest_socket_addr_len);

    if (bytes_sent == -1) {
        perror("sendto");
        handle_exit_failure(socket_fd, NULL);
    }
}

static void close_file(FILE *file) {
    if (fclose(file) != 0) {
        fprintf(stderr, "Error in closing file");
        exit(EXIT_FAILURE);
    }
}

static void close_socket(int socket_fd) {
    if (close(socket_fd) == -1) {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}