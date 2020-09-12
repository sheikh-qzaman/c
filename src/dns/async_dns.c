#include <ares.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <event2/event.h>

#define DNS_TIMEOUT_MS              4000
#define MAX_NAMESERVERS             3
#define USE_BITMASK					0

static void
ares_state_cb(void *data, int fd, int read, int write);

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

int
ares_init2()
{
	struct ares_options				options;
    struct ares_addrinfo_hints 		hints;
    int 							status, optmask = 0;

	t_dns_ctx *dns_ctx_p = get_dns_ctx();

    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS){
        printf("%s: ares_library_init: %s\n", __func__, ares_strerror(status));
    }

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
		return -1;
    }
	return 0;
}

static void
ares_ev_cb (evutil_socket_t  sockfd, short event, void *args)
{
	printf("%s: socket %d Event: ", __func__, sockfd);
	t_dns_ctx *dns_ctx_p = get_dns_ctx();

    if (event & EV_TIMEOUT) {
		printf("TIMEOUT\n");
        //ares_process_fd(dns_ctx_p->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        ares_process_fd(dns_ctx_p->channel, sockfd, sockfd);

    } else if (event & EV_READ) {
		printf("READ\n");
        ares_process_fd(dns_ctx_p->channel, sockfd, ARES_SOCKET_BAD);
    }
}

static void
ares_state_cb(void *data, int fd, int read, int write)
{
	struct timeval			tv, *timeout;
    struct event 			*read_evt;

    printf("%s: State change fd %d read:%d write:%d\n", __func__, fd, read, write);

	t_dns_ctx *dns_ctx_p = get_dns_ctx();
	timeout = ares_timeout(dns_ctx_p->channel, NULL, &tv);

	if (read) {
		printf("%s: Adding event for FD: %d\n", __func__, fd);
		read_evt = event_new(dns_ctx_p->base, fd, EV_PERSIST | EV_READ | EV_TIMEOUT, ares_ev_cb, dns_ctx_p->channel);
		event_add(read_evt, timeout);
	}
}

static void
ares_res_cb(void *arg, int status, int timeouts, struct ares_addrinfo *host)
{
    struct ares_addrinfo_node   *p_node;

    if(!host || status != ARES_SUCCESS){
        printf("%s: Failed to lookup %s\n", __func__, ares_strerror(status));
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
        printf("%s: Address: %s\n", __func__, ip);
    }
}

int
main(void)
{
	int status;

	t_dns_ctx *dns_ctx_p = get_dns_ctx();
    dns_ctx_p->base = event_base_new();

	status = ares_init2();
	if (status != ARES_SUCCESS) {
		printf("%s: c-ares parameter initialization error.", __func__);
	}

    ares_getaddrinfo(dns_ctx_p->channel, "centos.com", NULL, dns_ctx_p->hint , ares_res_cb, NULL);

	event_base_dispatch(dns_ctx_p->base);
    ares_destroy(dns_ctx_p->channel);
    ares_library_cleanup();
    printf("%s: Finished!\n", __func__);
    return 0;
}
