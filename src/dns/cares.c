#include <ares.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#define DNS_TIMEOUT_MS           40000
int resolved = 0;

static void
state_cb(void *data, int s, int read, int write)
{
    printf("Change state fd %d read:%d write:%d\n", s, read, write);
}


static void
callback(void *arg, int status, int timeouts, struct ares_addrinfo *host)
{
    struct ares_addrinfo_node   *p_node;

    if(!host || status != ARES_SUCCESS){
        printf("Failed to lookup %s\n", ares_strerror(status));
        return;
    }

    char ip[INET6_ADDRSTRLEN];

    for (p_node = host->nodes; p_node != NULL; p_node = p_node->ai_next) {
        if (p_node->ai_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)p_node->ai_addr;
            inet_ntop(p_node->ai_family, &(sin->sin_addr), ip, sizeof(ip));
        } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)p_node->ai_addr;
            inet_ntop(p_node->ai_family, &(sin6->sin6_addr), ip, sizeof(ip));
        }
        printf("Address: %s\n", ip);
    }

    resolved = 1;
}

static void
wait_ares(ares_channel channel)
{
    printf("ares wait\n");
    for(;;){
        struct timeval *tvp, tv;
        fd_set read_fds, write_fds;
        int nfds;

        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);
        printf("nfds %d r_fd: %d w_fd: %d\n", nfds, read_fds, write_fds);
        if(nfds == 0){
            break;
        }
        tvp = ares_timeout(channel, NULL, &tv);
        printf("select on the fds\n");
        select(nfds, &read_fds, &write_fds, NULL, tvp);
        printf("ares_process\n");
        ares_process(channel, &read_fds, &write_fds);
        printf("ares_process done\n");
    }

    printf("ares wait done.\n");
}

int
main(void)
{
    ares_channel channel;
    int status;
    struct ares_options options;
    struct ares_addrinfo_hints hints;
    struct ares_addrinfo_hints* hint;
    int optmask = 0;

    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS){
        printf("ares_library_init: %s\n", ares_strerror(status));
        return 1;
    }

    hints.ai_family     = AF_UNSPEC;
    hints.ai_socktype   = SOCK_DGRAM;
    hints.ai_protocol   = IPPROTO_UDP;
    hints.ai_flags      = ARES_AI_CANONNAME;
    hint                = &hints;
    
    options.timeout = DNS_TIMEOUT_MS;
    options.tries = 1;
    options.sock_state_cb = state_cb;

    optmask |= ARES_OPT_TIMEOUTMS;
    optmask |= ARES_OPT_TRIES;
    optmask |= ARES_OPT_SOCK_STATE_CB;

    status = ares_init_options(&channel, &options, optmask);
    if(status != ARES_SUCCESS) {
        printf("ares_init_options: %s\n", ares_strerror(status));
        return 1;
    }

    //ares_gethostbyname(channel, "vbond.cisco.com", AF_INET, callback, NULL);
    //ares_getaddrinfo(channel, "vbond.cisco.com", NULL, hint , callback, NULL);
    ares_getaddrinfo(channel, "centos.com", NULL, hint , callback, NULL);
    wait_ares(channel);
    ares_destroy(channel);
    ares_library_cleanup();
    printf("fin\n");
    return 0;
}
