#include <sys/types.h>
#include <sys/socket.h>

#include <sys/errno.h>
#include <sys/select.h>
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

#include <event.h>
#include <event2/event-config.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/util.h>

extern int    errno;

#define LINELEN 128
#define MAX_SELECT_ATTEMPTS 50  

int errexit(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	exit(1);
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

    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, cert_verify_callback);

    return client_ctx;
}

void
bev_ssl_readcb(struct bufferevent *bev, void *arg)
{
    //printf("++++++++++++++ (%s : %d : %d) +++++++++++\n", __FUNCTION__, __LINE__, print_cnt++);
    /* Drain the buffer no one is interested */
    evbuffer_drain(bufferevent_get_input(bev), EVBUFFER_LENGTH(bev->input));
}

void
bev_ssl_writecb(struct bufferevent *bev, void *arg)
{
    //printf("++++++++++++++ (%s : %d : %d) +++++++++++\n", __FUNCTION__, __LINE__, print_cnt++);
}

void
bev_ssl_eventcb(struct bufferevent *bev, short event, void *arg)
{
}

int
main(int argc, char *argv[])
{
    char                            *host = "15.0.0.2";
    int                             port = 4433;
    const SSL_METHOD                *method;
    SSL_CTX                         *ctx;
    SSL                             *ssl;
    BIO                             *sbio; 
    enum bufferevent_options        bev_opts = 0;
    struct bufferevent              *buf_ev;
    evutil_socket_t                 fd = -1;
    struct event_base               *evbase;
    struct sockaddr_in              sin; 	/* an Internet endpoint address         */
    char                            buf[LINELEN+1];     // buffer for one line of text
    int                             sock, n, ret, err;               // socket descriptor, read count
    int                             outchars, inchars;  // characters sent and received    
    
    // create ssl context
    ctx = create_ssl_ctx();    
    if (!ctx) {
        return 1;
    }

    //ssl initialize
    ssl = SSL_new(ctx);

    evbase = event_base_new();
    
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(host);

    bev_opts = BEV_OPT_CLOSE_ON_FREE;

    buf_ev = bufferevent_openssl_socket_new(evbase, fd, ssl, BUFFEREVENT_SSL_CONNECTING, bev_opts);
    if (buf_ev == NULL) {
        printf("Bufferevet creation failed for client: %d\n", fd);
        exit(0);
    }

    bufferevent_enable(buf_ev, EV_READ | EV_WRITE);

    bufferevent_setcb(buf_ev, bev_ssl_readcb, bev_ssl_writecb, bev_ssl_eventcb, NULL);
    
    ret = bufferevent_socket_connect(buf_ev, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));
    printf("ret: %d\n", ret);

    fd = bufferevent_getfd(buf_ev);

    printf("Connected to host %s on %d\n", host, fd);

    event_base_loop(evbase, 0);

    SSL_CTX_free(ctx);

    bufferevent_free(buf_ev);
    
    event_base_free(evbase);

    printf("Exiting...\n");
    exit(0);
}
