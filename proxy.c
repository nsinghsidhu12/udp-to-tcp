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

static void parse_arguments(int argc, char *argv[], char **proxy_ip_address, char **proxy_port_str,
                            char **client_ip_address, char **client_port_str, char **server_ip_address,
                            char **server_port_str, double *client_drop_pkt_chance, double *server_drop_pkt_chance,
                            double *client_drop_delay_chance, double *server_drop_delay_chance,
                            double *client_min_delay, double *client_max_delay, double *server_min_delay,
                            double *server_max_delay);

static void handle_arguments(char *program_name, const char *proxy_ip_address, char *proxy_port_str,
                             in_port_t *proxy_port, const char *client_ip_address, char *client_port_str,
                             in_port_t *client_port, const char *server_ip_address, char *server_port_str,
                             in_port_t *server_port, double client_min_delay, double client_max_delay,
                             double server_min_delay, double server_max_delay);

static void convert_address(char *ip_address, struct sockaddr_storage *socket_addr, socklen_t *socket_addr_len);

static int create_socket(int domain);

static void bind_socket(int socket_fd, struct sockaddr_storage *socket_addr, in_port_t port);

static void setup_signal_handler();

static void sigint_handler(int signum);

static int handle_proxy(int socket_fd, char *client_ip_address, in_port_t client_port, char *server_ip_address,
                        in_port_t server_port, double client_drop_pkt_chance, double server_drop_pkt_chance,
                        double client_drop_delay_chance, double server_drop_delay_chance, double client_min_delay,
                        double client_max_delay, double server_min_delay, double server_max_delay);

static char* set_destination(struct sockaddr_storage *dest_socket_addr, socklen_t *dest_socket_addr_len,
                            struct sockaddr_storage inc_socket_addr, char *client_ip_address, in_port_t client_port,
                            char *server_ip_address, in_port_t server_port);

static void get_destination_address(struct sockaddr_storage *socket_addr, in_port_t port);

static void calculate_drops(int *drop_flag, int *drop_delay_flag, double *min_delay, double *max_delay,
                            double client_drop_pkt_chance, double server_drop_pkt_chance, char *dest_entity,
                            double client_drop_delay_chance, double server_drop_delay_chance, double client_min_delay,
                            double client_max_delay, double server_min_delay, double server_max_delay);

static void forward_packet(int socket_fd, char *buffer, struct sockaddr_storage dest_socket_addr,
                            socklen_t dest_socket_addr_len);

_Noreturn static void usage(char *program_name, int exit_code, char *message);

static double parse_percent(char *program_name, char *input);

static double parse_milliseconds(char *program_name, char *input);

static in_port_t parse_in_port_t(char *program_name, char *input);

static void socket_close(int socket_fd);

#define WORD_LEN 256
#define NO_ARG_MESSAGE_LEN 128
#define UNKNOWN_OPTION_MESSAGE_LEN 64
#define BASE_TEN 10
#define ENTITY_OPTION_LEN 4
#define SERVER "server"
#define CLIENT "client"

#define MILLISECONDS_IN_NANOSECONDS 1000000
#define MIN_DELAY_MILLISECONDS 500
#define MAX_ADDITIONAL_NANOSECONDS 1000000000

static volatile sig_atomic_t exit_flag = 0;

int main(int argc, char *argv[]) {
    char *proxy_ip_address = NULL;
    char *proxy_port_str = NULL;
    in_port_t proxy_port = 0;
    char *client_ip_address = NULL;
    char *client_port_str = NULL;
    in_port_t client_port = 0;
    char *server_ip_address = NULL;
    char *server_port_str = NULL;
    in_port_t server_port = 0;

    double client_options[ENTITY_OPTION_LEN];
    double server_options[ENTITY_OPTION_LEN];
    double client_drop_pkt_chance = 50;
    double server_drop_pkt_chance = 50;
    double client_drop_delay_chance = 50;
    double server_drop_delay_chance = 50;
    double client_min_delay = 1000;
    double client_max_delay = 2000;
    double server_min_delay = 1000;
    double server_max_delay = 2000;
    struct sockaddr_storage proxy_socket_addr;
    socklen_t proxy_socket_addr_len;
    int socket_fd;

    parse_arguments(argc, argv, &proxy_ip_address, &proxy_port_str, &client_ip_address, &client_port_str,
                    &server_ip_address, &server_port_str, &client_drop_pkt_chance, &server_drop_pkt_chance,
                    &client_drop_delay_chance, &server_drop_delay_chance, &client_min_delay, &client_max_delay,
                    &server_min_delay, &server_max_delay);

    handle_arguments(argv[0], proxy_ip_address, proxy_port_str, &proxy_port, client_ip_address,
                     client_port_str, &client_port, server_ip_address, server_port_str, &server_port,
                     client_min_delay, client_max_delay, server_min_delay, server_max_delay);

    convert_address(proxy_ip_address, &proxy_socket_addr, &proxy_socket_addr_len);

    socket_fd = create_socket(proxy_socket_addr.ss_family);

    bind_socket(socket_fd, &proxy_socket_addr, proxy_port);

    setup_signal_handler();

    handle_proxy(socket_fd, client_ip_address, client_port, server_ip_address, server_port, client_drop_pkt_chance,
                 server_drop_pkt_chance, client_drop_delay_chance, server_drop_delay_chance, client_min_delay,
                 client_max_delay, server_min_delay, server_max_delay);

    return 0;
}

static void parse_arguments(int argc, char *argv[], char **proxy_ip_address, char **proxy_port_str,
                            char **client_ip_address, char **client_port_str, char **server_ip_address,
                            char **server_port_str, double *client_drop_pkt_chance, double *server_drop_pkt_chance,
                            double *client_drop_delay_chance, double *server_drop_delay_chance,
                            double *client_min_delay, double *client_max_delay, double *server_min_delay,
                            double *server_max_delay) {
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
                *client_drop_pkt_chance = parse_percent(argv[0], optarg);
                break;
            }
            case 2: {
                *server_drop_pkt_chance = parse_percent(argv[0], optarg);
                break;
            }
            case 3: {
                *client_drop_delay_chance = parse_percent(argv[0], optarg);
                break;
            }
            case 4: {
                *server_drop_delay_chance = parse_percent(argv[0], optarg);
                break;
            }
            case 5: {
                *client_min_delay = parse_milliseconds(argv[0], optarg);
                break;
            }
            case 6: {
                *client_max_delay = parse_milliseconds(argv[0], optarg);
                break;
            }
            case 7: {
                *server_min_delay = parse_milliseconds(argv[0], optarg);
                break;
            }
            case 8: {
                *server_max_delay = parse_milliseconds(argv[0], optarg);
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

    *proxy_ip_address = argv[optind];
    *proxy_port_str = argv[optind + 1];
    *client_ip_address = argv[optind + 2];
    *client_port_str = argv[optind + 3];
    *server_ip_address = argv[optind + 4];
    *server_port_str = argv[optind + 5];
}

static void handle_arguments(char *program_name, const char *proxy_ip_address, char *proxy_port_str,
                             in_port_t *proxy_port, const char *client_ip_address, char *client_port_str,
                             in_port_t *client_port, const char *server_ip_address, char *server_port_str,
                             in_port_t *server_port, double client_min_delay, double client_max_delay,
                             double server_min_delay, double server_max_delay) {
    if (proxy_ip_address == NULL) {
        usage(program_name, EXIT_FAILURE, "The proxy ip address is required");
    }

    if (proxy_port_str == NULL) {
        usage(program_name, EXIT_FAILURE, "The proxy port is required");
    }

    if (client_ip_address == NULL) {
        usage(program_name, EXIT_FAILURE, "The client ip address is required");
    }

    if (client_port_str == NULL) {
        usage(program_name, EXIT_FAILURE, "The client port is required");
    }

    if (server_ip_address == NULL) {
        usage(program_name, EXIT_FAILURE, "The server ip address is required");
    }

    if (server_port_str == NULL) {
        usage(program_name, EXIT_FAILURE, "The server port is required");
    }

    if (client_min_delay > client_max_delay) {
        usage(program_name, EXIT_FAILURE, "The client's min delay is greater than its max delay");
    }

    if (server_min_delay > server_max_delay) {
        usage(program_name, EXIT_FAILURE, "The server's min delay is greater than its max delay");
    }

    *proxy_port = parse_in_port_t(program_name, proxy_port_str);
    *client_port = parse_in_port_t(program_name, client_port_str);
    *server_port = parse_in_port_t(program_name, server_port_str);
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
        exit(EXIT_FAILURE);
    }
}

static int create_socket(int domain) {
    int socket_fd;

    socket_fd = socket(domain, SOCK_DGRAM, 0);

    if (socket_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    return socket_fd;
}

static void bind_socket(int socket_fd, struct sockaddr_storage *socket_addr, in_port_t port) {
    char addr_str[INET6_ADDRSTRLEN];
    socklen_t addr_len;
    void *vaddr;
    in_port_t net_port;

    net_port = htons(port);

    if (socket_addr->ss_family == AF_INET) {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr = (struct sockaddr_in *) socket_addr;
        addr_len = sizeof(*ipv4_addr);
        ipv4_addr->sin_port = net_port;
        vaddr = (void *) &(((struct sockaddr_in *) socket_addr)->sin_addr);
    } else if (socket_addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr = (struct sockaddr_in6 *) socket_addr;
        addr_len = sizeof(*ipv6_addr);
        ipv6_addr->sin6_port = net_port;
        vaddr = (void *) &(((struct sockaddr_in6 *) socket_addr)->sin6_addr);
    } else {
        fprintf(stderr, "Internal error: addr->ss_family must be AF_INET or AF_INET6, was: %d\n",
                socket_addr->ss_family);
        exit(EXIT_FAILURE);
    }

    if (inet_ntop(socket_addr->ss_family, vaddr, addr_str, sizeof(addr_str)) == NULL) {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    printf("Binding to: %s:%u\n", addr_str, port);

    if (bind(socket_fd, (struct sockaddr *) socket_addr, addr_len) == -1) {
        perror("Binding failed");
        fprintf(stderr, "Error code: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    printf("Bound to socket: %s:%u\n", addr_str, port);
}

static void sigint_handler(int signum) {
    exit_flag = 1;
}

static void setup_signal_handler(void) {
    struct sigaction sig_action;

    memset(&sig_action, 0, sizeof(sig_action));

    sig_action.sa_handler = sigint_handler;

    sigemptyset(&sig_action.sa_mask);
    sig_action.sa_flags = 0;

    if (sigaction(SIGINT, &sig_action, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

static int handle_proxy(int socket_fd, char *client_ip_address, in_port_t client_port, char *server_ip_address,
                        in_port_t server_port, double client_drop_pkt_chance, double server_drop_pkt_chance,
                        double client_drop_delay_chance, double server_drop_delay_chance, double client_min_delay,
                        double client_max_delay, double server_min_delay, double server_max_delay) {
    while (!exit_flag) {
        struct sockaddr_storage inc_socket_addr;
        socklen_t inc_socket_addr_len = sizeof(inc_socket_addr);
        struct sockaddr_storage dest_socket_addr;
        socklen_t dest_socket_addr_len;
        char buffer[WORD_LEN + 1];
        char *dest_entity;
        int drop_flag = 0;
        int drop_delay_flag = 0;
        double min_delay = 0;
        double max_delay = 0;

        ssize_t bytes_received = recvfrom(socket_fd, buffer, sizeof(buffer) - 1, 0,
                                          (struct sockaddr *) &inc_socket_addr, &inc_socket_addr_len);

        if (bytes_received == -1) {
            perror("recvfrom");
        }

        buffer[(size_t) bytes_received] = '\0';
        printf("read %zu characters: \"%s\" from\n", (size_t) bytes_received, buffer);

        dest_entity = set_destination(&dest_socket_addr, &dest_socket_addr_len, inc_socket_addr, client_ip_address,
                                      client_port, server_ip_address, server_port);

        calculate_drops(&drop_flag, &drop_delay_flag, &min_delay, &max_delay, client_drop_pkt_chance,
                        server_drop_pkt_chance, dest_entity, client_drop_delay_chance, server_drop_delay_chance,
                        client_min_delay, client_max_delay, server_min_delay, server_max_delay);

        if (drop_flag == 0) {
            if (drop_delay_flag == 0) {
                struct timespec delay;
                delay.tv_sec  = 10;
                delay.tv_nsec = 0;
                nanosleep(&delay, NULL);
            }

            forward_packet(socket_fd, buffer, dest_socket_addr, dest_socket_addr_len);
        }
    }

    socket_close(socket_fd);

    return EXIT_SUCCESS;
}

static char* set_destination(struct sockaddr_storage *dest_socket_addr, socklen_t *dest_socket_addr_len,
                            struct sockaddr_storage inc_socket_addr, char *client_ip_address, in_port_t client_port,
                            char *server_ip_address, in_port_t server_port) {
    char ip_address[INET6_ADDRSTRLEN];
    uint16_t port = 0;

    if (inc_socket_addr.ss_family == AF_INET) {
        struct sockaddr_in *ipv4_addr = (struct sockaddr_in *) &inc_socket_addr;
        inet_ntop(AF_INET, &(ipv4_addr->sin_addr), ip_address, sizeof(ip_address));
        port = ntohs(ipv4_addr->sin_port);
    } else if (inc_socket_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *ipv6_addr = (struct sockaddr_in6 *) &inc_socket_addr;
        inet_ntop(AF_INET6, &(ipv6_addr->sin6_addr), ip_address, sizeof(ip_address));
        port = ntohs(ipv6_addr->sin6_port);
    }

    if (strcmp(ip_address, client_ip_address) == 0 && (port == client_port)) {
        convert_address(server_ip_address, dest_socket_addr, dest_socket_addr_len);
        get_destination_address(dest_socket_addr, server_port);
        return CLIENT;
    } else if (strcmp(ip_address, server_ip_address) == 0 && (port == server_port)) {
        convert_address(client_ip_address, dest_socket_addr, dest_socket_addr_len);
        get_destination_address(dest_socket_addr, client_port);
        return SERVER;
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
    }
}

static void forward_packet(int socket_fd, char *buffer, struct sockaddr_storage dest_socket_addr, socklen_t dest_socket_addr_len) {
    ssize_t bytes_sent = sendto(socket_fd, buffer, strlen(buffer) + 1, 0,
                                (struct sockaddr *) &dest_socket_addr, dest_socket_addr_len);

    if (bytes_sent == -1) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }
}

static void calculate_drops(int *drop_flag, int *drop_delay_flag, double *min_delay, double *max_delay,
                            double client_drop_pkt_chance, double server_drop_pkt_chance, char *dest_entity,
                            double client_drop_delay_chance, double server_drop_delay_chance, double client_min_delay,
                            double client_max_delay, double server_min_delay, double server_max_delay) {
    srand(time(NULL));
    float random_float = ((float) rand() / RAND_MAX) * 99 + 1;

    if (strcmp(dest_entity, CLIENT) == 0) {
        *min_delay = client_min_delay;
        *max_delay = client_max_delay;
        if (random_float <= client_drop_pkt_chance) {
            *drop_flag = 1;
        } else if (random_float <= client_drop_delay_chance) {
            *drop_delay_flag = 1;
        }
    } else if (strcmp(dest_entity, SERVER) == 0) {
        *min_delay = server_min_delay;
        *max_delay = server_max_delay;
        if (random_float <= server_drop_pkt_chance) {
            *drop_flag = 1;
        } else if (random_float <= server_drop_delay_chance) {
            *drop_delay_flag = 1;
        }
    }
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

static double parse_percent(char *program_name, char *input) {
    char *end_ptr;
    double percent;

    errno = 0;
    percent = strtod(input, &end_ptr);

    if (errno != 0) {
        perror("Error parsing convert_to_percent");
        exit(EXIT_FAILURE);
    }

    // Check if there are any non-numeric characters in the input string
    if (*end_ptr != '\0') {
        usage(program_name, EXIT_FAILURE, "Invalid characters in input");
    }

    // Check if the percent is within the valid range for convert_to_percent
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
        exit(EXIT_FAILURE);
    }

    // Check if there are any non-numeric characters in the input string
    if (*end_ptr != '\0') {
        usage(program_name, EXIT_FAILURE, "Invalid characters in input");
    }

    // Check if the percent is within the valid range for parse_milliseconds
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
        exit(EXIT_FAILURE);
    }

    // Check if there are any non-numeric characters in the input string
    if (*end_ptr != '\0') {
        usage(program_name, EXIT_FAILURE, "Invalid characters in input.");
    }

    // Check if the parsed value is within the valid range for in_port_t
    if (parsed_value > UINT16_MAX) {
        usage(program_name, EXIT_FAILURE, "in_port_t value out of range.");
    }

    return (in_port_t) parsed_value;
}

static void socket_close(int socket_fd) {
    if (close(socket_fd) == -1) {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}