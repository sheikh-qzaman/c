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

extern int    errno;

#define LINELEN 128

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

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;

    /* Map port number (char string) to port number (int)*/
    if ((sin.sin_port = htons(port)) == 0) {
        errexit("can't get \"%d\" port number\n", port);
    }

    /* Map host name to IP address, allowing for dotted decimal
    if ( phe = gethostbyname(host) ) {
        memcpy(&sin.sin_addr, phe->h_addr, phe->h_length);
    } else if ( (sin.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE ) {
        errexit("can't get \"%s\" host entry\n", host);
    } */

    sin.sin_addr.s_addr = inet_addr(host);

    /* Allocate a socket */
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        errexit("can't create socket: %s\n", strerror(errno));
    }

    /* Connect the socket */
    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        errexit("can't connect to %s.%d: %s\n", host, port, strerror(errno));
    }

    return sock;
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
    
    // load encryption & hash algorithms for SSL
    SSL_library_init();
    
    // load the error strings for good error reporting            
    SSL_load_error_strings();
    
    // create context
    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    
    // ca certificate
    if (!SSL_CTX_load_verify_locations(ctx, "rootCA.crt",NULL)) { 
        errexit("Could not load CA cert\n");
    }
    
    SSL_CTX_set_verify_depth(ctx, 1);
    
    //ssl initialize
    ssl = SSL_new(ctx);
    
    // talk to the server
    char    buf[LINELEN+1];     // buffer for one line of text
    int     s, n, r;               // socket descriptor, read count
    int     outchars, inchars;  // characters sent and received    
    
    //  tcp connection
    s = connectsock(host, port);

    printf("Connected to host %s on %d\n", host, s);
    
    // enable ssl communication
    sbio = BIO_new_socket(s, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);
    
    if((r = SSL_connect(ssl)) <= 0) {
        errexit("SSL connect failed\n%d\n",r);
    }
    
    if(SSL_get_peer_certificate(ssl) != NULL){
        if(SSL_get_verify_result(ssl) != X509_V_OK) {
            errexit("Could not verify peer certificate\n");    
        }
    } else {
        errexit("Could not get peer certificate\n");
    }

	while (fgets(buf, sizeof(buf), stdin)) {
        buf[LINELEN] = '\0';    /* ensure line null-terminated    */
        outchars = strlen(buf);
        (void) SSL_write(ssl, buf, outchars);

        if (strncmp(buf, "exit", 4) == 0) {
            break;
        }

        n = SSL_read(ssl, &buf, LINELEN);
        printf("%d: ", n);

        /*
        for (inchars = 0; inchars < outchars; inchars+=n ) {
            n = SSL_read(ssl, &buf[inchars], outchars - inchars);
            if (n < 0)  {
                errexit("socket read failed: %s\n", strerror(errno));
            }
        }
        */

        fputs(buf, stdout);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(s);
    
    exit(0);
}
