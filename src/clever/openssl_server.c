#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int errexit(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(1);
}

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("15.0.0.2"); 

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        errexit("Error setting socket option SO_REUSEADDR.");
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

void init_openssl()
{ 
    SSL_load_error_strings();    
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        //ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        perror("Cant' open certificate.");
        //ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) {
        perror("Cant' open private key.");
        //ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int
main(int argc, char **argv)
{
    int                 sock, client;
    SSL_CTX             *ctx;
    struct sockaddr_in  addr;
    uint                len = sizeof(addr);
    SSL                 *ssl;
    char                buf[128];

    init_openssl();
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(4433);

    while (1) {
        client = accept(sock, (struct sockaddr*)&addr, &    len);

        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        printf("Client %d connected.\n", client);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            errexit("ERROR");
        }

        /* Handle connections */
        while(1) {
            SSL_read(ssl, buf, sizeof(buf));
            printf("%s\n", buf);

            if (strncmp(buf, "exit", 4) == 0) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client);
                break;
            }

            SSL_write(ssl, buf, sizeof(buf));
        }
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
