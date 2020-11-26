/* Simple echo server using OpenSSL bufferevents */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <event.h>
#include <event2/listener.h>
#include <event2/bufferevent_ssl.h>

static void
ssl_readcb(struct bufferevent * bev, void * arg)
{
    printf("Reading from buffer\n");
    struct evbuffer *in = bufferevent_get_input(bev);

    printf("Received %zu bytes\n", evbuffer_get_length(in));
    printf("----- data ----\n");
    printf("%.*s\n", (int)evbuffer_get_length(in), evbuffer_pullup(in, -1));

    printf("Writing to buffer\n");
    bufferevent_write_buffer(bev, in);
    printf("Wrote to buffer\n");
}

static void
ssl_writecb(struct bufferevent *bev, void *ctx)
{
    printf("BEV_EVENT_WRITE\n");
}

static void
ssl_eventcb(struct bufferevent *bev, short event, void *ctx)
{
    if (event & BEV_EVENT_CONNECTED) {
        printf("BEV_EVENT_CONNECTED\n");
    }

    if (event & BEV_EVENT_READING) {
        printf("BEV_EVENT_READING\n");
        printf(evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        printf("\n");
    }

    if (event & BEV_EVENT_WRITING) {
        printf("BEV_EVENT_WRITING\n");
    }

    if (event & BEV_EVENT_ERROR) {
        printf("BEV_EVENT_ERROR\n");
    }

    if (event & BEV_EVENT_EOF) {
        printf("BEV_EVENT_EOF\n");
    }

    if (event & BEV_EVENT_TIMEOUT) {
        printf("BEV_EVENT_TIMEOUT\n");
    }
}

static void
ssl_acceptcb(struct evconnlistener *serv, int sock, struct sockaddr *sa, int sa_len, void *arg)
{
    struct event_base *evbase;
    struct bufferevent *bev;
    SSL_CTX *server_ctx;
    SSL *client_ctx;

    server_ctx = (SSL_CTX *)arg;
    client_ctx = SSL_new(server_ctx);
    evbase = evconnlistener_get_base(serv);

    printf("Client\n");

    bev = bufferevent_openssl_socket_new(evbase, sock, client_ctx,
                                         BUFFEREVENT_SSL_ACCEPTING,
                                         BEV_OPT_CLOSE_ON_FREE);

    bufferevent_enable(bev, EV_READ | EV_WRITE);
    bufferevent_setcb(bev, ssl_readcb, ssl_writecb, ssl_eventcb, NULL);
}

static SSL_CTX *
create_ssl_ctx(void)
{
    SSL_CTX  *server_ctx;

    /* Initialize the OpenSSL library */
    SSL_load_error_strings();
    SSL_library_init();
    /* We MUST have entropy, or else there's no point to crypto. */
    if (!RAND_poll())
        return NULL;

    server_ctx = SSL_CTX_new(SSLv23_server_method());

    SSL_CTX_set_ecdh_auto(server_ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(server_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        perror("Cant' open certificate.");
        //ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(server_ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) {
        perror("Cant' open private key.");
        //ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    //SSL_CTX_set_options(server_ctx, SSL_OP_NO_SSLv2);

    return server_ctx;
}

int
main(int argc, char **argv)
{
    SSL_CTX *ctx;
    struct evconnlistener *listener;
    struct event_base *evbase;
    struct sockaddr_in sin;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(4433);
    //sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    sin.sin_addr.s_addr = inet_addr("15.0.0.2"); 

    ctx = create_ssl_ctx();
    if (ctx == NULL) {
        return 1;
    }

    evbase = event_base_new();
    listener = evconnlistener_new_bind(
                         evbase, ssl_acceptcb, (void *)ctx,
                         LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 1024,
                         (struct sockaddr *)&sin, sizeof(sin));

    event_base_loop(evbase, 0);

    evconnlistener_free(listener);
    SSL_CTX_free(ctx);

    return 0;
}
