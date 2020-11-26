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

#define LINELEN                     12
#define MAX_SELECT_ATTEMPTS         50
#define CLIENT_ADD_INTERVAL_SEC     1
#define CLIENT_ADD_INTERVAL_MSEC    0 
#define CLIENT_DEL_INTERVAL_SEC     5
#define MSG_SEND_INTERVAL_SEC       1 
#define MSG_SEND_INTERVAL_MSEC      0
#define ERR_OK                      0
#define TCP_ERR                     1

void delete_ssl_peer();

struct event        *client_add_timer;
struct event        *client_del_timer;
struct timeval      tv;
struct timeval      del_tv;
char                *host = "15.0.0.2";
int                 port = 4433;
t_ssl_peer          *p_peer;
struct event_base   *evbase;
SSL_CTX             *ssl_client_ctx;
int                 count = 0;

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
    struct sockaddr_in  sin; 	/* an Internet endpoint address         */
    int                 sock; 	/* socket descriptor                    */
    int                 ret, retry_attempts = 0, flag = 1;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;

    /* Map port number (char string) to port number (int)*/
    if ((sin.sin_port = htons(port)) == 0) {
        errexit("can't get \"%d\" port number\n", port);
    }

    sin.sin_addr.s_addr = inet_addr(host);

    /* Allocate a socket */
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        errexit("can't create socket: %s\n", strerror(errno));
    }

    evutil_make_socket_nonblocking(sock);

    p_peer->listener_fd = sock;

    // TODO do we need it for client?
    /*
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        close(socket);
        return 1;
    }
    */

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

    return 0;
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
    /* Initialize the OpenSSL library */
    SSL_library_init();
    SSL_load_error_strings();

    /* We MUST have entropy, or else there's no point to crypto. */
    if (!RAND_poll()) {
        return NULL;
    }

    ssl_client_ctx = SSL_CTX_new(SSLv23_client_method());

    /*
     * This function sets the maximum allowable depth for peer certificates. In other words, it limits the number of certificates that we are
     * willing to verify in order to ensure the chain is trusted. For example, if the depth was set to four and six certificates are present
     * in the chain to reach the trusted certificate, the verification would fail because the required depth would be too great.
     */
    SSL_CTX_set_verify_depth(ssl_client_ctx, 1);

    SSL_CTX_set_ecdh_auto(ssl_client_ctx, 1);

    // ca certificate
    if (!SSL_CTX_load_verify_locations(ssl_client_ctx, "rootCA.crt",NULL)) { 
        errexit("Could not load CA cert\n");
    }

    /*
     * OpenSSL has internal callback to verify the client provided certificate. However this callback provide customization, i.e. accepting an
     * expired certificate for example. The second argument is flag which can be logical ORed. These are:
     * SSL_VERIFY_NONE: When the context is being used in server mode, no request for a certificate will be sent to the client, and the client
     * should not send a certificate. 
     * SSL_VERIFY_PEER: When the context is being used in server mode, a request for a certificate will be sent to the client. The client may opt
     * to ignore the request, but if a certificate is sent back, it will be verified. If the verification fails, the handshake will be terminated
     * immediately. When the context is being used in client mode, if the server sends a certificate, it will be verified. If the verification fails,
     * the handshake will be terminated immediately. The only time that a server would not send a certificate is when an anonymous cipher is in use.
     * Anonymous ciphers are disabled by default. Any other flags combined with this one in client mode are ignored.
     * SSL_VERIFY_FAIL_IF_NO_PEER_CERT: If the context is not being used in server mode or if SSL_VERIFY_PEER is not set, this flag is ignored.
     * Use of this flag will cause the handshake to terminate immediately if no certificate is provided by the client.
     * SSL_VERIFY_CLIENT_ONCE: If the context is not being used in server mode or if SSL_VERIFY_PEER is not set, this flag is ignored. Use of this flag
     * will prevent the server from requesting a certificate from the client in the case of a renegotiation. A certificate will still be requested during
     * the initial handshake.
     */
    SSL_CTX_set_verify(ssl_client_ctx, SSL_VERIFY_PEER, cert_verify_callback);

    return ssl_client_ctx;
}

void
bev_ssl_readcb(struct bufferevent *bev, void *arg)
{
    printf("got message...\n");
}

void
bev_ssl_writecb(struct bufferevent *bev, void *arg)
{
    printf("writing to buffer\n");
}

void
bev_ssl_eventcb(struct bufferevent *bev, short event, void *arg)
{
}

static void
evbuffer_cleanup(const void *data, size_t len, void *arg)
{
    if (arg != NULL) {
        printf("Freeing up...\n");
        free(arg);
    }
}

static void
msg_timer_cb(int sock, short which, void *arg)
{
    struct evbuffer     *p_outbuf;
    char *str = calloc(LINELEN, sizeof(char));
    char buf[LINELEN];

    snprintf(buf, sizeof(buf), "msg: %d", count);
    strncpy(str, buf, LINELEN);

    if (p_peer == NULL) {
        printf("No peer, not sending hello.\n");
        return;
    }

    if (!evtimer_pending(p_peer->timer_ev, NULL)) {
        event_del(p_peer->timer_ev);
        p_outbuf = bufferevent_get_output(p_peer->bev);
        evbuffer_add_reference(p_outbuf, str, LINELEN, evbuffer_cleanup, str);
        printf("Sending msg: %d\n", count++);
        if (count % 5 == 0) {
            delete_ssl_peer();
        } else {
            evtimer_add(p_peer->timer_ev, &p_peer->tv);
        }
    }
}

int
create_ssl_client()
{
    int         sock, ret, err;
    
    p_peer = calloc(1, sizeof(t_ssl_peer));
    // using default context
    //p_peer->ctx = client_ctx;
    p_peer->ssl = SSL_new(ssl_client_ctx);

    //  tcp connection
    if (connectsock(host, port) != ERR_OK) {
        printf("Error in tcp connection.\n");
        return TCP_ERR;
    }

    printf("Connected to host %s on %d\n", host, p_peer->listener_fd);

    if (!(ret = SSL_set_fd(p_peer->ssl, p_peer->listener_fd))) {
        printf("SSL error: %d setting fd.", SSL_get_error(p_peer->ssl, ret));
    }

    // enable ssl communication
    // TODO in viptela we don't use it but free it, probably being used only for dtls
    //p_peer->sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    //SSL_set_bio(p_peer->ssl, p_peer->sbio, p_peer->sbio);

    printf("Trying SSL connect again.\n");
    while (!(ret = SSL_connect(p_peer->ssl))) {
        err = SSL_get_error(p_peer->ssl, ret);
        if (err == SSL_ERROR_WANT_READ    ||
                   SSL_ERROR_WANT_WRITE   ||
                   SSL_ERROR_WANT_CONNECT) {
        } else {
            printf("SSL connect error.\n");
            return 1;
        }
    }

    printf("SSL connect successfull..\n");

    // we should probably put -1 as socket as the socket already present in p_peer->ssl
    // For socket-based bufferevent if the SSL object already has a socket set, you do not need to provide the socket: just pass -1.
    // TODO In viptela we're not using BEV_OPT_CLOSE_ON_FREE as option
    //p_peer->bev = bufferevent_openssl_socket_new(evbase, -1, p_peer->ssl, BUFFEREVENT_SSL_OPEN, BEV_OPT_CLOSE_ON_FREE);
    p_peer->bev = bufferevent_openssl_socket_new(evbase, -1, p_peer->ssl, BUFFEREVENT_SSL_OPEN, 0);

    // once we have bev we don't need the SSL pointer as bev will have the SSL
    p_peer->ssl = NULL;

    bufferevent_enable(p_peer->bev, EV_READ | EV_WRITE);

    bufferevent_setcb(p_peer->bev, bev_ssl_readcb, bev_ssl_writecb, bev_ssl_eventcb, NULL);

    p_peer->tv.tv_sec = MSG_SEND_INTERVAL_SEC;
    p_peer->tv.tv_usec = MSG_SEND_INTERVAL_MSEC;

    p_peer->timer_ev = evtimer_new(evbase, msg_timer_cb, NULL);

    evtimer_add(p_peer->timer_ev, &p_peer->tv);

    return 0;
}

void
delete_ssl_peer()
{
    SSL *ssl;
    evutil_socket_t fd = -1;

    if (p_peer->bev == NULL) {
        return;
    }

    ssl = bufferevent_openssl_get_ssl(p_peer->bev);

    //SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN);
    //SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
    //SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

    int ret;
    printf("SSL %p\n", ssl);
    ret = SSL_shutdown(ssl);
    printf("SSL %p\n", ssl);
    printf("SSL Err: %d\n", SSL_get_error(ssl, ret));
    if (ret == 0) {
        printf("Sending another ssl shutdown.\n");
        ret = SSL_shutdown(ssl);
        printf("SSL Err: %d\n", SSL_get_error(ssl, ret));
    }

    //SSL_free(ssl);
    p_peer->ssl = NULL;

    bufferevent_setcb(p_peer->bev, NULL, NULL, NULL, NULL);
    bufferevent_free(p_peer->bev);
    p_peer->bev = NULL;

    if (ssl) {
        printf("Freeing SSL\n");
        //SSL_free(ssl);
    }

    if (p_peer->listener_fd >= 0) {
        close(p_peer->listener_fd);
    }

    free(p_peer);
    p_peer = NULL;
}

static void
client_timer_cb(int sock, short which, void *arg)
{
    char *mode = (char*) arg;

    if (evtimer_pending(client_add_timer, NULL)) {
        return;
    }

    if (strcmp(mode, "add") == 0) {
        event_del(client_add_timer);
        create_ssl_client();
        //client_del_timer = evtimer_new(evbase, client_timer_cb, "del");
        //evtimer_add(client_del_timer, &del_tv);
        tv.tv_sec = 30;
        evtimer_add(client_add_timer, &tv);
    } else {
        event_del(client_del_timer);
        if (p_peer != NULL) {
            printf("Deleting ssl peer.\n");
            delete_ssl_peer();

            printf("Deleted peer.\n");
        }
        evtimer_add(client_del_timer, &del_tv);
    }

    //evtimer_add(timer_ev, &tv);
}

int
main(int argc, char *argv[])
{
    evbase = event_base_new();

    create_ssl_ctx();
    
    //ret = bufferevent_socket_connect(bev, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));
    //printf("ret: %d\n", ret);
    del_tv.tv_sec = CLIENT_DEL_INTERVAL_SEC;
    del_tv.tv_usec = CLIENT_ADD_INTERVAL_MSEC;

    tv.tv_sec = CLIENT_ADD_INTERVAL_SEC;
    tv.tv_usec = CLIENT_ADD_INTERVAL_MSEC;

    client_add_timer = evtimer_new(evbase, client_timer_cb, "add");

    evtimer_add(client_add_timer, &tv);

    event_base_loop(evbase, 0);

    printf("Exiting...\n");
    event_base_free(evbase);
    
    exit(0);
}
