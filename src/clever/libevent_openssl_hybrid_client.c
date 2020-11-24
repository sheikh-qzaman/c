#include <sys/types.h>
#include <sys/socket.h>

#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <event.h>
#include <event2/event-config.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/util.h>

#include "peer.h"

extern int    errno;

#define LINELEN 128
#define MAX_SELECT_ATTEMPTS 50

struct event        *timer_ev;
struct timeval      tv;
struct bufferevent  *bev;

t_ssl_peer          *p_ssl_peer;

int errexit(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	exit(1);
}

int
connectsock(const char *host, int port)
{
    struct hostent      *phe; 	/* pointer to host information entry    */
    struct sockaddr_in  sin; 	/* an Internet endpoint address         */
    int                 sock; 	/* socket descriptor                    */
    int                 ret;
    int                 retry_attempts = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;

    /* Map port number (char string) to port number (int)*/
    if ((sin.sin_port = htons(port)) == 0) {
        errexit("can't get \"%d\" port number\n", port);
    }

    sin.sin_addr.s_addr = inet_addr(host);

    /* Allocate a socket */
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        errexit("can't create socket: %s\n", strerror(errno));
    }

    evutil_make_socket_nonblocking(sock);

    /* Connect the socket */
    ret = connect(sock, (struct sockaddr *)&sin, sizeof(sin));

    if (ret < 0) {
        if (errno == EINPROGRESS) {
			struct timeval l_connect_timeout;
            int l_fds, max_fd;
            fd_set filedes_set;
            l_connect_timeout.tv_sec=0;
            l_connect_timeout.tv_usec=10000;

            FD_ZERO(&filedes_set);
            max_fd = sock;
            FD_SET(sock, &filedes_set);

			while (retry_attempts < MAX_SELECT_ATTEMPTS) {
                l_fds = select(max_fd + 1, NULL, &filedes_set, NULL, &l_connect_timeout);
                if (l_fds == 0) { //timed out
                    printf("select timeout failure %d\n", errno);
                } else if(l_fds < 0) { //select failed
                    printf("select failure %d\n", errno);
                    return 1;
                } else {
                    int l_sock_optval = -1;
                    int l_sock_optval_len = sizeof(l_sock_optval);

                    if(getsockopt(sock, SOL_SOCKET, SO_ERROR, (int*)&l_sock_optval, (socklen_t*)&l_sock_optval_len) !=0) {
                        printf("connect failure %d\n", errno);
                        return 1;
                    }

                    if(l_sock_optval == 0) {
                        //connected to server
                        retry_attempts = 0;
                        break;
                    }
                }

                retry_attempts++;
            }
        }
	}

    return sock;
}

static int
cert_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    char buf[256];
    X509 *err_cert;
    int err, depth;

    printf("certify verify callback()\n");
    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);
    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

    if (err) {
        printf("Certificate ERROR: [ %s ] \nPlease check certificate [ %s ] depth : [ %d ] \n",
                    X509_verify_cert_error_string(err), buf, depth);
    }

    return preverify_ok;
}

static SSL_CTX*
create_ssl_ctx()
{
    SSL_CTX  *client_ctx;

    /* Initialize the OpenSSL library */
    SSL_library_init();
    SSL_load_error_strings();

    /* We MUST have entropy, or else there's no point to crypto. */
    if (!RAND_poll()) {
        return NULL;
    }

    client_ctx = SSL_CTX_new(SSLv23_client_method());

    SSL_CTX_set_verify_depth(client_ctx, 1);

    SSL_CTX_set_ecdh_auto(client_ctx, 1);

    // ca certificate
    if (!SSL_CTX_load_verify_locations(client_ctx, "rootCA.crt",NULL)) { 
        errexit("Could not load CA cert\n");
    }

    SSL_CTX_set_verify_depth(client_ctx, 1);

    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, cert_verify_callback);

    return client_ctx;
}

void
bev_ssl_readcb(struct bufferevent *bev, void *arg)
{
    printf("got message...\n");
}

void
bev_ssl_writecb(struct bufferevent *bev, void *arg)
{
}

void
bev_ssl_eventcb(struct bufferevent *bev, short event, void *arg)
{
}

static void
evbuffer_cleanup(const void *data, size_t len, void *arg) {
    if (arg != NULL) {
        printf("Freeing up...\n");
        free(arg);
    }
}

static void
timer_cb(int sock, short which, void *arg) {
    struct evbuffer     *p_outbuf;
    struct bufferevent  *p_buffer_ev;
    char *str = calloc(10, sizeof(char));

    strncpy(str, "hello", 6);

    if (!evtimer_pending(timer_ev, NULL)) {
        event_del(timer_ev);
        p_outbuf = bufferevent_get_output(bev);
        printf("Sending hello...\n");
        evbuffer_add_reference(p_outbuf, str, 6, evbuffer_cleanup, str);
        evtimer_add(timer_ev, &tv);
    }
}

void
create_client()
{
    t_ssl_peer *p_peer = calloc(1, sizeof(t_ssl_peer));
    p_peer->ctx = create_ssl_ctx();
}

int
main(int argc, char *argv[])
{
    char                *host = "15.0.0.2";
    int                 port = 4433;
    const SSL_METHOD    *method;
    SSL_CTX             *ctx;
    SSL                 *ssl;
    BIO                 *sbio; 
    evutil_socket_t                 fd = -1;
    struct event_base               *evbase;

    evbase = event_base_new();
    
    ctx = create_ssl_ctx();

    //ssl initialize
    ssl = SSL_new(ctx);
    
    int     s, n, ret, err;               // socket descriptor, read count
    
    //  tcp connection
    s = connectsock(host, port);

    printf("Connected to host %s on %d\n", host, s);
    
    // enable ssl communication
    sbio = BIO_new_socket(s, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);
    
    while ((ret = SSL_connect(ssl)) != 1) {
        err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ    ||
                   SSL_ERROR_WANT_WRITE   ||
                   SSL_ERROR_WANT_CONNECT) {
            printf("Trying SSL connect again.\n");
        } else {
            printf("SSL connect error.\n");
            return 1;
        }
    }

    printf("SSL connect successfull..\n");

    bev = bufferevent_openssl_socket_new(evbase, -1, ssl, BUFFEREVENT_SSL_OPEN, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_enable(bev, EV_READ | EV_WRITE);

    bufferevent_setcb(bev, bev_ssl_readcb, bev_ssl_writecb, bev_ssl_eventcb, NULL);

    //ret = bufferevent_socket_connect(bev, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));
    //printf("ret: %d\n", ret);

    printf("bufferevent\n");

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    timer_ev = evtimer_new(evbase, timer_cb, NULL);

    evtimer_add(timer_ev, &tv);
    
    event_base_loop(evbase, 0);

    SSL_CTX_free(ctx);
    bufferevent_free(bev);
    event_base_free(evbase);
    
    exit(0);
}
