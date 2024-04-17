#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

struct entity {
    char *ip_address;
    char *port_str;
    in_port_t port;
};

struct entity_opt {
    double drop_pkt_chance;
    double drop_delay_chance;
    double min_delay;
    double max_delay;
};

struct __attribute__((packed)) PACKET {
    int seq_num;
    char data[256];
} typedef Packet;

static void parse_arguments(int argc, char *argv[], struct entity *proxy, struct entity *client, struct entity *server,
                            struct entity_opt *client_opt, struct entity_opt *server_opt);

static void handle_arguments(char *program_name, struct entity *proxy, struct entity *client, struct entity *server,
                             struct entity_opt client_opt, struct entity_opt server_opt);

_Noreturn static void usage(char *program_name, int exit_code, char *message);

static void handle_exit_failure(int socket_fd);

static double parse_percent(char *program_name, char *input);

static double parse_milliseconds(char *program_name, char *input);

static in_port_t parse_in_port_t(char *program_name, char *input);

static void initialize_address(char *ip_address, in_port_t port, struct sockaddr_storage *socket_addr,
                               socklen_t *socket_addr_len, int *socket_fd);

static void convert_address(char *ip_address, struct sockaddr_storage *socket_addr, socklen_t *socket_addr_len);

static int create_socket(int domain);

static void bind_socket(int socket_fd, struct sockaddr_storage *socket_addr, in_port_t port);

static void setup_signal_handler();

static void sigint_handler(int signum);

static int handle_proxy(int socket_fd, struct entity client, struct entity server, struct entity_opt client_opt,
                        struct entity_opt server_opt);

static char *set_destination(struct sockaddr_storage *dest_socket_addr, socklen_t *dest_socket_addr_len,
                             struct sockaddr_storage inc_socket_addr, struct entity client, struct entity server);

static void get_destination_address(struct sockaddr_storage *socket_addr, in_port_t port);

static void set_drop_flags(char* dest_entity, int *drop_flag, int *drop_delay_flag, struct entity_opt client_opt,
                           struct entity_opt server_opt);

static void set_delay(char* dest_entity, struct timespec *delay, struct entity_opt client_opt,
                      struct entity_opt server_opt);

static void forward_packet(int socket_fd, Packet *buffer, struct sockaddr_storage dest_socket_addr,
                           socklen_t dest_socket_addr_len);

static void close_socket(int socket_fd);

#define NO_ARG_MESSAGE_LEN 128
#define UNKNOWN_OPTION_MESSAGE_LEN 64
#define BASE_TEN 10
#define SERVER "server"
#define CLIENT "client"

static volatile sig_atomic_t exit_flag = 0;

int main(int argc, char *argv[]) {
    struct entity proxy;
    struct entity client;
    struct entity server;
    struct entity_opt client_opt = {50, 50, 1000, 2000};
    struct entity_opt server_opt = {50, 50, 1000, 2000};
    struct sockaddr_storage proxy_socket_addr;
    socklen_t proxy_socket_addr_len;
    int socket_fd;

    parse_arguments(argc, argv, &proxy, &client, &server, &client_opt, &server_opt);
    handle_arguments(argv[0], &proxy, &client, &server, client_opt, server_opt);
    initialize_address(proxy.ip_address, proxy.port, &proxy_socket_addr,&proxy_socket_addr_len,
                       &socket_fd);
    setup_signal_handler();
    handle_proxy(socket_fd, client, server, client_opt, server_opt);

    return EXIT_SUCCESS;
}

static void parse_arguments(int argc, char *argv[], struct entity *proxy, struct entity *client, struct entity *server,
                            struct entity_opt *client_opt, struct entity_opt *server_opt) {
    static struct option long_options[] = {
            {"cdrop",      required_argument, NULL, 1},
            {"sdrop",      required_argument, NULL, 2},
            {"cdropdelay", required_argument, NULL, 3},
            {"sdropdelay", required_argument, NULL, 4},
            {"cmindelay",  required_argument, NULL, 5},
            {"cmaxdelay",  required_argument, NULL, 6},
            {"smindelay",  required_argument, NULL, 7},
            {"smaxdelay",  required_argument, NULL, 8},
            {"help",       no_argument,       NULL, 'h'},
            {NULL, 0,                         NULL, 0}
    };

    int opt;

    opterr = 0;

    while ((opt = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
        switch (opt) {
            case 1: {
                client_opt->drop_pkt_chance = parse_percent(argv[0], optarg);
                break;
            }
            case 2: {
                server_opt->drop_pkt_chance = parse_percent(argv[0], optarg);
                break;
            }
            case 3: {
                client_opt->drop_delay_chance = parse_percent(argv[0], optarg);
                break;
            }
            case 4: {
                server_opt->drop_delay_chance = parse_percent(argv[0], optarg);
                break;
            }
            case 5: {
                client_opt->min_delay = parse_milliseconds(argv[0], optarg);
                break;
            }
            case 6: {
                client_opt->max_delay = parse_milliseconds(argv[0], optarg);
                break;
            }
            case 7: {
                server_opt->min_delay = parse_milliseconds(argv[0], optarg);
                break;
            }
            case 8: {
                server_opt->max_delay = parse_milliseconds(argv[0], optarg);
                break;
            }
            case 'h': {
                usage(argv[0], EXIT_SUCCESS, NULL);
            }
            case '?': {
                if (optopt >= 1 && optopt <= 8) {
                    char message[NO_ARG_MESSAGE_LEN];

                    sprintf(message, "Option '--%s' requires a value", long_options[optopt - 1].name);
                    usage(argv[0], EXIT_FAILURE, message);
                } else {
                    char message[UNKNOWN_OPTION_MESSAGE_LEN];

                    snprintf(message, sizeof(message), "Unknown option '-%c'", optopt);
                    usage(argv[0], EXIT_FAILURE, message);
                }
            }
            default: {
                usage(argv[0], EXIT_FAILURE, NULL);
            }
        }
    }

    if (optind + 5 >= argc) {
        usage(argv[0], EXIT_FAILURE, "Too few arguments");
    }

    if (optind < argc - 6) {
        usage(argv[0], EXIT_FAILURE, "Too many arguments");
    }

    proxy->ip_address = argv[optind];
    proxy->port_str = argv[optind + 1];
    client->ip_address = argv[optind + 2];
    client->port_str = argv[optind + 3];
    server->ip_address = argv[optind + 4];
    server->port_str = argv[optind + 5];
}

static void handle_arguments(char *program_name, struct entity *proxy, struct entity *client, struct entity *server,
                             struct entity_opt client_opt, struct entity_opt server_opt) {
    if (proxy->ip_address == NULL) {
        usage(program_name, EXIT_FAILURE, "The proxy ip address is required");
    }

    if (proxy->port_str == NULL) {
        usage(program_name, EXIT_FAILURE, "The proxy port is required");
    }

    if (client->ip_address == NULL) {
        usage(program_name, EXIT_FAILURE, "The client ip address is required");
    }

    if (client->port_str == NULL) {
        usage(program_name, EXIT_FAILURE, "The client port is required");
    }

    if (server->ip_address == NULL) {
        usage(program_name, EXIT_FAILURE, "The server ip address is required");
    }

    if (server->port_str == NULL) {
        usage(program_name, EXIT_FAILURE, "The server port is required");
    }

    if (client_opt.min_delay > client_opt.max_delay) {
        usage(program_name, EXIT_FAILURE, "The client's min delay is greater than its max delay");
    }

    if (server_opt.min_delay > server_opt.max_delay) {
        usage(program_name, EXIT_FAILURE, "The server's min delay is greater than its max delay");
    }

    proxy->port = parse_in_port_t(program_name, proxy->port_str);
    client->port = parse_in_port_t(program_name, client->port_str);
    server->port = parse_in_port_t(program_name, server->port_str);
}

static double parse_percent(char *program_name, char *input) {
    char *end_ptr;
    double percent;

    errno = 0;
    percent = strtod(input, &end_ptr);

    if (errno != 0) {
        perror("Error parsing convert_to_percent");
        handle_exit_failure(-1);
    }

    if (*end_ptr != '\0') {
        usage(program_name, EXIT_FAILURE, "Invalid characters in input");
    }

    if (percent < 0 || percent > 100) {
        usage(program_name, EXIT_FAILURE, "convert_to_percent value out of range");
    }

    return percent;
}

static double parse_milliseconds(char *program_name, char *input) {
    char *end_ptr;
    double milliseconds;

    errno = 0;
    milliseconds = strtod(input, &end_ptr);

    if (errno != 0) {
        perror("Error parsing milliseconds");
        handle_exit_failure(-1);
    }

    if (*end_ptr != '\0') {
        usage(program_name, EXIT_FAILURE, "Invalid characters in input");
    }

    if (milliseconds < 0 || milliseconds > 10000) {
        usage(program_name, EXIT_FAILURE, "parse_milliseconds value out of range");
    }

    return milliseconds;
}

static in_port_t parse_in_port_t(char *program_name, char *input) {
    char *end_ptr;
    uintmax_t parsed_value;

    errno = 0;
    parsed_value = strtoumax(input, &end_ptr, BASE_TEN);

    if (errno != 0) {
        perror("Error parsing in_port_t");
        handle_exit_failure(-1);
    }

    if (*end_ptr != '\0') {
        usage(program_name, EXIT_FAILURE, "Invalid characters in input.");
    }

    if (parsed_value > UINT16_MAX) {
        usage(program_name, EXIT_FAILURE, "in_port_t value out of range.");
    }

    return (in_port_t) parsed_value;
}

_Noreturn static void usage(char *program_name, int exit_code, char *message) {
    if (message) {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr, "Usage: %s <ip address> <port> <client ip address> <client port> <server ip address> "
                    "<server port> [-h] --cdrop <value> --sdrop <value> --cdropdelay <value> --sdropdelay <value> "
                    "--cmindelay <value> --cmaxdelay <value> --smindelay <value> --smaxdelay <value>\n", program_name);
    fputs("Options:\n", stderr);
    fputs("  --help, -h            Display this help message\n", stderr);
    fputs("  --cdrop <value>       Drop chance of packets from client, <value> between 0-100\n", stderr);
    fputs("  --sdrop <value>       Drop chance of packets from server, <value> between 0-100\n", stderr);
    fputs("  --cdropdelay <value>  Drop delay chance of packets from client, <value> between 0-100\n", stderr);
    fputs("  --sdropdelay <value>  Drop delay chance of packets from server, <value> between 0-100\n", stderr);
    fputs("  --cmindelay <value>   Minimum delay of packets from client, <value> between 0-10000\n", stderr);
    fputs("  --cmaxndelay <value>  Maximum delay of packets from client, <value> between 0-10000\n", stderr);
    fputs("  --smindelay <value>   Minimum delay of packets from server, <value> between 0-10000\n", stderr);
    fputs("  --cmaxdelay <value>   Maximum delay of packets from server, <value> between 0-10000\n", stderr);

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

static int handle_proxy(int socket_fd, struct entity client, struct entity server, struct entity_opt client_opt,
                        struct entity_opt server_opt) {
    while (!exit_flag) {
        struct sockaddr_storage inc_socket_addr;
        socklen_t inc_socket_addr_len = sizeof(inc_socket_addr);
        struct sockaddr_storage dest_socket_addr;
        socklen_t dest_socket_addr_len;
        char buffer[sizeof(Packet)];
        char *dest_entity;
        int drop_flag = 0;
        int drop_delay_flag = 0;
        Packet *packet = malloc(sizeof(Packet));

        ssize_t bytes_received = recvfrom(socket_fd, packet, sizeof(Packet), 0,
                                          (struct sockaddr *) &inc_socket_addr, &inc_socket_addr_len);

        if (bytes_received == -1) {
            perror("recvfrom");
            free(packet);
            handle_exit_failure(socket_fd);
        }

        memcpy(buffer, &packet, sizeof(Packet));
        buffer[(size_t) bytes_received] = '\0';

        dest_entity = set_destination(&dest_socket_addr, &dest_socket_addr_len, inc_socket_addr, client, server);
        set_drop_flags(dest_entity, &drop_flag, &drop_delay_flag, client_opt, server_opt);

        if (drop_flag == 0) {
            if (drop_delay_flag == 0) {
                printf("Packet sent with delay - Data: %s, Seq %d\n", packet->data, packet->seq_num);
                struct timespec delay;
                set_delay(dest_entity, &delay, client_opt, server_opt);
                nanosleep(&delay, NULL);
            } else if (drop_delay_flag == 1) {
                printf("Packet sent with no delay - Data: %s, Seq %d\n", packet->data, packet->seq_num);
            }
            forward_packet(socket_fd, packet, dest_socket_addr, dest_socket_addr_len);
        } else if (drop_flag == 1){
            printf("Packet dropped - Data: %s, Seq %d\n", packet->data, packet->seq_num);
        }
        free(packet);
    }

    close_socket(socket_fd);

    return EXIT_SUCCESS;
}

static char *set_destination(struct sockaddr_storage *dest_socket_addr, socklen_t *dest_socket_addr_len,
                             struct sockaddr_storage inc_socket_addr, struct entity client, struct entity server) {
    char ip_address[INET6_ADDRSTRLEN];
    uint16_t port;

    if (inc_socket_addr.ss_family == AF_INET) {
        struct sockaddr_in *ipv4_addr = (struct sockaddr_in *) &inc_socket_addr;
        inet_ntop(AF_INET, &(ipv4_addr->sin_addr), ip_address, sizeof(ip_address));
        port = ntohs(ipv4_addr->sin_port);
    } else if (inc_socket_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *ipv6_addr = (struct sockaddr_in6 *) &inc_socket_addr;
        inet_ntop(AF_INET6, &(ipv6_addr->sin6_addr), ip_address, sizeof(ip_address));
        port = ntohs(ipv6_addr->sin6_port);
    } else {
        fprintf(stderr, "inc_socket_addr->ss_family must be AF_INET or AF_INET6, was: %d\n",
                inc_socket_addr.ss_family);
        handle_exit_failure(-1);
    }

    if (strcmp(ip_address, client.ip_address) == 0 && (port == client.port)) {
        convert_address(server.ip_address, dest_socket_addr, dest_socket_addr_len);
        get_destination_address(dest_socket_addr, server.port);
        return SERVER;
    } else if (strcmp(ip_address, server.ip_address) == 0 && (port == server.port)) {
        convert_address(client.ip_address, dest_socket_addr, dest_socket_addr_len);
        get_destination_address(dest_socket_addr, client.port);
        return CLIENT;
    } else {
        fprintf(stderr, "Destination is not the client or server");
        handle_exit_failure(-1);
    }

    return NULL;
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
    } else {
        fprintf(stderr, "socket_addr->ss_family must be AF_INET or AF_INET6, was: %d\n",
                socket_addr->ss_family);
        handle_exit_failure(-1);
    }
}

static void forward_packet(int socket_fd, Packet *buffer, struct sockaddr_storage dest_socket_addr, socklen_t dest_socket_addr_len) {
    ssize_t bytes_sent = sendto(socket_fd, buffer, sizeof(Packet), 0,
                                (struct sockaddr *) &dest_socket_addr, dest_socket_addr_len);

    if (bytes_sent == -1) {
        perror("sendto");
        handle_exit_failure(socket_fd);
    }
}

static void set_drop_flags(char* dest_entity, int *drop_flag, int *drop_delay_flag, struct entity_opt client_opt,
                           struct entity_opt server_opt) {
    float random_num = ((float) rand() / RAND_MAX) * 99 + 1;

    if (strcmp(dest_entity, CLIENT) == 0) {
        if (random_num <= server_opt.drop_pkt_chance) {
            *drop_flag = 1;
        } else if (random_num <= server_opt.drop_delay_chance) {
            *drop_delay_flag = 1;
        }
    } else if (strcmp(dest_entity, SERVER) == 0) {
        if (random_num <= client_opt.drop_pkt_chance) {
            *drop_flag = 1;
        } else if (random_num <= client_opt.drop_delay_chance) {
            *drop_delay_flag = 1;
        }
    } else {
        fprintf(stderr, "Destination is not set as the client or server");
        handle_exit_failure(-1);
    }
}

static void set_delay(char* dest_entity, struct timespec *delay, struct entity_opt client_opt,
                      struct entity_opt server_opt) {
    srand(time(NULL));

    if (strcmp(dest_entity, CLIENT) == 0) {
        double random_delay = server_opt.min_delay + (double) rand() / RAND_MAX * (server_opt.max_delay - server_opt.min_delay);
        delay->tv_sec = (time_t) random_delay / 1000;
        delay->tv_nsec = (long)((random_delay - (double) delay->tv_sec * 1000) * 1000000);
    } else if (strcmp(dest_entity, SERVER) == 0) {
        double random_delay = client_opt.min_delay + (double) rand() / RAND_MAX * (client_opt.max_delay - client_opt.min_delay);
        delay->tv_sec = (time_t) random_delay / 1000;
        delay->tv_nsec = (long)((random_delay - (double) delay->tv_sec * 1000) * 1000000);
    } else {
        fprintf(stderr, "Destination is not set as the client or server");
        handle_exit_failure(-1);
    }
}

static void close_socket(int socket_fd) {
    if (close(socket_fd) == -1) {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}

