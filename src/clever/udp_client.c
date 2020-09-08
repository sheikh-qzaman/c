// Client side implementation of UDP client-server model 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <net/if.h>

#define PORT     8080 
#define MAXLINE 1024 

// Driver code 
int main() { 
    int sockfd; 
    char buffer[MAXLINE]; 
    char *hello = "Hello from client"; 
    struct sockaddr_in     servaddr; 

    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 

    memset(&servaddr, 0, sizeof(servaddr)); 
    
    // Filling server information 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(PORT); 
    //servaddr.sin_addr.s_addr = INADDR_ANY; 
    servaddr.sin_addr.s_addr = inet_addr("15.0.0.2"); 

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "ens3");

	if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
		printf("Error binding to %s\n", ifr);
	}
    
    int n, len; 
    
    sendto(sockfd, (const char *)hello, strlen(hello), MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr)); 
    printf("Hello message sent.\n"); 
        
    n = recvfrom(sockfd, (char *)buffer, MAXLINE, 
                MSG_WAITALL, (struct sockaddr *) &servaddr, 
                &len); 
    buffer[n] = '\0'; 
    printf("Server : %s\n", buffer); 

    close(sockfd); 
    return 0; 
} 
