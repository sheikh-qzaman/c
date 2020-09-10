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

struct event_base 				*base;
ares_channel					channel;
struct ares_addrinfo_hints* 	hint;

static void
ares_read_cb (evutil_socket_t  sockfd, short event, void *args)
{
	printf("ares_read_cb\n");
	ares_channel   channel = args;

    if (event & EV_TIMEOUT) {
		printf("EV_TIMEOUT\n");
        return ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

    } else if (event & EV_READ) {
		printf("EV_READ\n");
        return ares_process_fd(channel, sockfd, ARES_SOCKET_BAD);
    }
}



static void
state_cb(void *data, int fd, int read, int write)
{
    printf("Change state fd %d read:%d write:%d\n", fd, read, write);

	int						bitmask;
	struct timeval			tv, *timeout;
    struct event 			*read_evt;

	timeout = ares_timeout(channel, NULL, &tv);

	printf("Adding event for FD: %d\n", fd);
	
	if (read) {
		read_evt = event_new(base, fd, EV_PERSIST | EV_READ | EV_TIMEOUT, ares_read_cb, channel);
		event_add(read_evt, timeout);
	}
}

static void
callback(void *arg, int status, int timeouts, struct ares_addrinfo *host)
{
	printf("callback:\n");
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

void
event_init()
{
    base = event_base_new();
}

void ares_init_mine() { }

void
ares_create_event(ares_channel channel)
{
	int						socks[MAX_NAMESERVERS];
	int						bitmask;
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
                                    ares_read_cb, channel);
			printf("Adding event %d.\n", i);
			event_add(read_evt[j++], timeout);
        }
    }
}

int
main(void)
{
	event_init();

    struct ares_options				options;
    struct ares_addrinfo_hints 		hints;
    int 							status, optmask = 0;

    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS){
        printf("ares_library_init: %s\n", ares_strerror(status));
        return 1;
    }

    hints.ai_family     = AF_UNSPEC;
    hints.ai_socktype   = SOCK_DGRAM;
    hints.ai_protocol   = IPPROTO_UDP;
    hints.ai_flags      = EVUTIL_AI_CANONNAME;
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
    ares_getaddrinfo(channel, "centos.com", NULL, hint , callback, NULL);

   	//ares_create_event(channel); 

    //wait_ares(channel);
	event_base_dispatch(base);
    ares_destroy(channel);
    ares_library_cleanup();
    printf("fin\n");
    return 0;
}
