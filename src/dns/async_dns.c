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
#include <event2/event.h>

#define DNS_TIMEOUT_MS              4000
#define MAX_NAMESERVERS             16
#define USE_BITMASK					0

typedef struct dns_ctx
{
	struct event_base 				*base;
	ares_channel					channel;
	struct ares_addrinfo_hints* 	hint;
} t_dns_ctx;

static t_dns_ctx		dns_ctx;

t_dns_ctx *
get_dns_ctx(void)
{
	return &dns_ctx;
}

static void
ares_ev_cb (evutil_socket_t  sockfd, short event, void *args)
{
	printf("ares_ev_cb\n");
	t_dns_ctx *dns_ctx_p = get_dns_ctx();

    if (event & EV_TIMEOUT) {
		printf("EV_TIMEOUT\n");
        ares_process_fd(dns_ctx_p->channel, sockfd, ARES_SOCKET_BAD);

    } else if (event & EV_READ) {
		printf("EV_READ\n");
        ares_process_fd(dns_ctx_p->channel, sockfd, ARES_SOCKET_BAD);
    }
}

static void
ares_state_cb(void *data, int fd, int read, int write)
{
    printf("Change state fd %d read:%d write:%d\n", fd, read, write);
	t_dns_ctx *dns_ctx_p = get_dns_ctx();

	if(USE_BITMASK) {
		return;
	}

	struct timeval			tv, *timeout;
    struct event 			*read_evt;

	timeout = ares_timeout(dns_ctx_p->channel, NULL, &tv);

	if (read) {
		printf("Adding event for FD: %d\n", fd);
		read_evt = event_new(dns_ctx_p->base, fd, EV_PERSIST | EV_READ | EV_TIMEOUT, ares_ev_cb, dns_ctx_p->channel);
		event_add(read_evt, timeout);
	}
}

static void
ares_res_cb(void *arg, int status, int timeouts, struct ares_addrinfo *host)
{
	printf("ares_res_cb\n");
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
}

/*
void
ares_create_event(ares_channel channel)
{
	int						bitmask, socks[MAX_NAMESERVERS];
	struct timeval			tv, *timeout;
    struct event 			*read_evt[MAX_NAMESERVERS];

	timeout = ares_timeout(channel, NULL, &tv);
    bitmask = ares_getsock(channel, socks, MAX_NAMESERVERS);

    for (int i = 0, j = 0; i < MAX_NAMESERVERS; i++) {
		printf("Current socket: %d\n", i);
        if (ARES_GETSOCK_READABLE(bitmask, i)) {
			printf("%d is readable.\n", i);
            read_evt[j] = event_new(base, socks[i], 
                                    EV_PERSIST | EV_READ | EV_TIMEOUT,
                                    ares_ev_cb, channel);
			printf("Adding event %d.\n", i);
			event_add(read_evt[j++], timeout);
        }
    }
}
*/

void
ares_init2()
{
	int status;

    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS){
        printf("ares_library_init: %s\n", ares_strerror(status));
    }
}

int
main(void)
{
	t_dns_ctx *dns_ctx_p = get_dns_ctx();
    dns_ctx_p->base = event_base_new();

	ares_init2();

    struct ares_options				options;
    struct ares_addrinfo_hints 		hints;
    int 							status, optmask = 0;

    hints.ai_family     = AF_UNSPEC;
    hints.ai_socktype   = SOCK_DGRAM;
    hints.ai_protocol   = IPPROTO_UDP;
    hints.ai_flags      = EVUTIL_AI_CANONNAME;
    dns_ctx_p->hint     = &hints;
    
    options.timeout = DNS_TIMEOUT_MS;
    options.tries = 1;
    options.sock_state_cb = ares_state_cb;

    optmask |= ARES_OPT_TIMEOUTMS;
    optmask |= ARES_OPT_TRIES;
    optmask |= ARES_OPT_SOCK_STATE_CB;

    status = ares_init_options(&(dns_ctx_p->channel), &options, optmask);
    if(status != ARES_SUCCESS) {
        printf("ares_init_options: %s\n", ares_strerror(status));
        return 1;
    }

    //ares_gethostbyname(channel, "vbond.cisco.com", AF_INET, callback, NULL);
    ares_getaddrinfo(dns_ctx_p->channel, "centos.com", NULL, dns_ctx_p->hint , ares_res_cb, NULL);

	if (USE_BITMASK) {
		//ares_create_event(channel); 
	}

    //wait_ares(channel);
	event_base_dispatch(dns_ctx_p->base);
    ares_destroy(dns_ctx_p->channel);
    ares_library_cleanup();
    printf("fin\n");
    return 0;
}
