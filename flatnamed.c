#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/types.h>
#include <err.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

// 512 is usually enough; but what the hell why not 64k? or more?
#define QMAX 64000





void hexdump(const void *d, size_t datalen) {
    const uint8_t *data = d;
    size_t i, j = 0;

    for (i = 0; i < datalen; i += j) {
	printf("%4zu: ", i);
	for (j = 0; j < 16 && i+j < datalen; j++)
	    printf("%02x ", data[i + j]);
	while (j++ < 16)
	    printf("   ");
	printf("|");
	for (j = 0; j < 16 && i+j < datalen; j++)
	    putchar(isprint(data[i + j]) ? data[i + j] : '.');
	printf("|\n");
    }
}


void msginfo(const struct sockaddr_storage *ss, socklen_t sslen, size_t len) {
    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV]; //XXX NI_MAX* not portable 
    int error;

    error = getnameinfo((const struct sockaddr *)ss, sslen,
	hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
	NI_NUMERICHOST | NI_NUMERICSERV);
    if (error != 0) {
	warnx("msginfo: %s", gai_strerror(error));
	return;
    }

    fprintf(stderr, "host %s port %s bytes %zu\n", hbuf, sbuf, len);
}

int main(int argc, char **argv) {
	
	int port = 53; // TODO take arg, argparse etc.

	// arg parsing
	int ch;
	while ((ch = getopt(argc, argv, "p:")) != -1) {
		if (ch == 'p') {
			port = atoi(optarg);
		}
	}

	struct sockaddr_in udp_sockaddr;
	memset(&udp_sockaddr, 0, sizeof(udp_sockaddr));
	

	udp_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY); //any incoming IP 
    udp_sockaddr.sin_port = htons(53);
    // udp_sockaddr.sin_family = AF_INET; //address family

	int s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);
	if (s == -1) {
		perror("socket error: ");
	    return -1;
	}
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
	    perror("setsockopt(SO_REUSEADDR) failed: ");
	    return -1;
	}


	if (bind(s, (struct sockaddr *) &udp_sockaddr, 
			sizeof(struct sockaddr_in)) < 0) {
		perror("udp bind error: ");
		return -1;
	}

#ifdef DEBUG
	fprintf(stderr, "started on port: %d\n", port);
#endif
	while (1) { // i guess udp doesn't need multi threads
		struct sockaddr from;
		memset(&from, 0, sizeof(from));   
		socklen_t fromLen = sizeof(struct sockaddr);
		unsigned char buf[QMAX];
		ssize_t rlen = recvfrom(s, buf, QMAX, 0, &from, &fromLen);
#ifdef DEBUG
		msginfo((struct sockaddr_storage *) &from, fromLen, rlen);
		hexdump(buf, rlen);
#endif
	}


	return 0;
}