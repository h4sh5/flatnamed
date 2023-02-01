#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
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

#include "qtypes.h"

// ut hash for hashmaps
#include "uthash.h"

struct name_hash_record {
    uint32_t key_type_hash; // this is a hash of name + "-" + type
    // uint16_t type; // probably dont need this
    char class[2]; // i mean do i really need to store this..?
    char *value;
    UT_hash_handle hh;         /* makes this structure hashable */
};

struct name_hash_record *records =  NULL;


uint32_t jenkins_one_at_a_time_hash(const uint8_t* key, size_t length) {
  size_t i = 0;
  uint32_t hash = 0;
  while (i != length) {
    hash += key[i++];
    hash += hash << 10;
    hash ^= hash >> 6;
  }
  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;
  return hash;
}

void add_name(char* name, char* type, char* class, char* value) {
    struct name_hash_record *r;

    r = malloc(sizeof *r);
    unsigned char name_dash_type[strlen(name)+1+strlen(type)+1];
    sprintf(name_dash_type, "%s-%s", name, type);
    r->key_type_hash = jenkins_one_at_a_time_hash(name_dash_type, sizeof name_dash_type);
    r->class[0] = class[0]; r->class[1] = class[1];
    r->value = value;
    HASH_ADD_INT(records, key_type_hash, r);  /* id: name of key field */
}

// 512 is usually enough; but why not more?
#define QMAX 10240
// max line size in zone record file
#define RECORD_LINE_MAX QMAX * 2

//packed, to make sure the size is consistent and no extra padding is applied
typedef struct {
	uint16_t tid; // tx id
	uint16_t flags;
	uint16_t num_questions;
	uint16_t answer_rrs; // Resource Records in answer
	uint16_t authority_rrs;
	uint16_t additional_rrs;
} __attribute__((packed)) DNSHeader; // Query headers and Response headers are the same! Difference only in the flag. (first bit 0 = qry, 1 = response)

typedef struct {
	uint16_t name_ptr; // pointer to the queried name (compression thingo)
	uint16_t type;
	uint16_t class;
	uint32_t ttl; // Resource Records in answer
	uint16_t dlen; // data length
} __attribute__((packed)) RRHeader; // Query headers and Response headers are the same! Difference only in the flag. (first bit 0 = qry, 1 = response)



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

/**
 * convert ipv4 string to 32 bit int
 **/
uint32_t ipv4_str_to_int(char *ip) {
	struct addrinfo *res;// getaddrinfo returns an array
	int error;
	if (error = getaddrinfo(ip, 0, NULL, &res) != 0) {
		warnx("getaddrinfo: %s", gai_strerror(error));
		freeaddrinfo(res);
		return 0;
	}
	uint32_t ip_int = ((struct sockaddr_in*) (res[0].ai_addr))->sin_addr.s_addr;
#ifdef DEBUG
	fprintf(stderr, "converted ipv4 addr to int: %08x %d\n", ip_int,ip_int);
#endif
	freeaddrinfo(res);

	return ip_int;

}

// parse and answer query
void process_query(unsigned char *pkt, size_t plen, struct sockaddr* sa, socklen_t sa_len,  int socket) {
	DNSHeader qh = {0,};
	memcpy(&qh, pkt, sizeof(qh));
#ifdef DEBUG
	fprintf(stderr, "txid:%04x flags:%04x questions:%04x answer_rrs:%04x additional_rrs:%04x\n", qh.tid, qh.flags, qh.answer_rrs, qh.authority_rrs,qh.additional_rrs);
#endif
	// use a while loop to parse names
	size_t name_max = QMAX - sizeof(DNSHeader); // it can only be so big anyway
	// avoiding malloc so there are no heap bugs, so we just use a big stack var
	unsigned char name[name_max]; // need to reserve one byte at the end for NULL
	memset(name, 0, name_max);
	size_t name_len = 0; // current len
	size_t name_index = 0;
	//process the length/string pairs until we get a NULL byte.  
	// e.g. domain example.com is encoded as these 13 bytes: 7example3com0
	// https://jvns.ca/blog/2022/09/12/why-do-domain-names-end-with-a-dot-/
	while (1) {
		size_t next_len = pkt[sizeof(qh) + name_index];
		// the end
		if (next_len == 0) {
			break;
		}
		if (name_len >= name_max -1) { // let's be safe
			name[name_len] = 0;
#ifdef DEBUG
			fprintf(stderr, "early exit since name too long. name:%s", name);
#endif
			break;
		}
		strncat(name, pkt + (sizeof(qh) + name_index + 1), next_len);
		name_index += next_len;
#ifdef DEBUG
		fprintf(stderr, "name_index:%d name:%s\n", name_index, name);
#endif
		name[name_index] = '.'; // add dot; 
		//this current implementation means that dots are always added to the end of queried names, which isn't necessarily a bad thing
		name_index ++;
#ifdef DEBUG
		fprintf(stderr, "name_index:%d name:%s\n", name_index, name);
#endif
		name_len = name_index + 1;

	}

	uint16_t type = (uint16_t) pkt[sizeof(qh) + name_len + 1];
	uint16_t class = (uint16_t) pkt[sizeof(qh) + name_len + 3];

#ifdef DEBUG
	fprintf(stderr, "name:%s type:%04x class:%04x\n", name, type, class);
	if (type == type_A) {
		fprintf(stderr, "type A query\n");
	}
#endif
	// question needs to be included in answer
	unsigned char *question = pkt+sizeof(qh); // the query data past the query header is the question
	size_t qlen = plen - sizeof(qh);

	/***************** RESPONSE **********************/
	// XXX give dummy response 
	DNSHeader ah = {0,};
	RRHeader rrh = {0,};

	ah.tid = qh.tid;
	ah.flags = htons(1 << 15); //  0x8000 (right most bit set, for indicating response)
	ah.num_questions = qh.num_questions;
	ah.answer_rrs = htons(1); // 1 (need to call htons on all these fields to conver them to little endian)

	// the weird compression scheme thing, where it points to the offset of the name, and starting with 0b11 (11 in binary)

	// 00 11 is because of small endian
	rrh.name_ptr = htons(0xc000 | sizeof(qh)); // happens to usually be at the end of the query header size (12 bytes)
	rrh.type = htons(type); // the queried type
	rrh.class = htons(class);
	rrh.ttl = htonl(300); // 300 seconds left?

	unsigned char data[4] = {0x7f, 0x00, 0x00, 0x01}; // 127.0.0.1 + NULL NULL

	// HANDLE A RECORD
	if (type == type_A) {
		rrh.dlen = htons(4); // an ipv4 address is 4 bytes long
		// do a lookup
		struct name_hash_record *r;
		char key[strlen(name) + 2 + 1];
		sprintf(key, "%s-A", name);
		key[sizeof(key) - 1] = 0; // NULL term
#ifdef DEBUG
		fprintf(stderr,"looking up key %s\n", key);
#endif
		uint32_t khash = jenkins_one_at_a_time_hash(key, sizeof(key));
		HASH_FIND_INT(records, &khash,r);
		if (r) {
			uint32_t ip_int = ipv4_str_to_int(r->value);
			fprintf(stderr, "found value:%s ip:%08x\n", r->value, ip_int);
			memcpy(data, &ip_int, sizeof(ip_int));
		}
	} else { // refuse - record not supported
		rrh.dlen = 0;
		size_t qlen = plen - sizeof(qh); // packet length - the header size = size of question

		unsigned char rpkt[sizeof(qh) + qlen];
		// set answer header to the same as qh, then modify it
		memcpy(&ah, &qh, sizeof(qh));
		// set qh flag to refuse (reply code 5)
		ah.flags = htons(0x8005); // REFUSE response 
		memcpy(rpkt, 										(unsigned char*) &ah, sizeof(qh)); // copy in answer header
		memcpy(rpkt + sizeof(ah), 							question, qlen); // copy in question
#ifdef DEBUG
		fprintf(stderr, "sending REFUSE\n");
#endif
		if (sendto(socket, rpkt, sizeof(rpkt), 0, sa, sa_len) == -1) {
			warnx("sendto error: %s", strerror(errno));
		}
		return;
	}

	// actual answer data
	

	

	unsigned char rpkt[sizeof(ah) + qlen + sizeof(rrh) + sizeof(data)];
	memcpy(rpkt, 										(unsigned char*) &ah, sizeof(ah)); // copy in answer header
	memcpy(rpkt + sizeof(ah), 							question, qlen); // copy in question
	memcpy(rpkt + sizeof(ah) + qlen,				 	(unsigned char*) &rrh, sizeof(rrh)); // copy in resource record header
	memcpy(rpkt + sizeof(ah) + qlen + sizeof(rrh),	 	data, sizeof(data)); // actual answer data
#ifdef DEBUG
	puts("------ answer ------");
	// hexdump(rpkt, sizeof(rpkt));
#endif
	if (sendto(socket, rpkt, sizeof(rpkt), 0, sa, sa_len) == -1) {
		warnx("sendto error: %s", strerror(errno));
	}



}

// 1 indexed, and double quotes only
// TODO: add single quote?
char* get_nth_whitespace_quoted_token(char *s, size_t slen, int nth) {
	int n = 0;
	// TODO handle quotes (double quotes)
	int in_quote = 0;  
	int prev_whitespace = 0;

	// scan past consecutive separators
	size_t end, prev_end;
	prev_end = 0;
	for (end = 0; end < slen; ++end) {
		if (s[end] == '"') {
			if (!in_quote) { // start quote
				in_quote = 1;
			} else { // end quote
				in_quote = 0;
			}
		}
		if ((s[end] == ' ' || s[end] == '\t' || s[end] == '\r') && !in_quote) { //whitespace

			if (!prev_whitespace) {
				n++;
				if (n == nth - 1) {
					prev_end = end + 1; // skip past the space
				}
			}
			prev_whitespace = 1;

		} else {
			// hit a non-whitespace token
			prev_whitespace = 0;
			
		}
		
		if (n == nth) { // scan til the token *after?
			break;
		}
	}
	// end would be the end of the token, prev_end would be the end of the prev token which is the start
// #ifdef DEBUG
// 	fprintf(stderr, "length of token:%d\n", end - prev_end);
// #endif
	char *token = malloc(end-prev_end+1);

	// get rid of quotes if they exist
	if (s[prev_end] == '"') {
		strncpy(token, s+prev_end+1, end-prev_end);
	} else {
		strncpy(token, s+prev_end, end-prev_end);
	}
	
	if (token[strlen(token)-2] == '"') {
		token[strlen(token)-2] = 0;
	}

	token[end-prev_end] = 0; // NULL term, and get rid of new line


	
// #ifdef DEBUG
// 	fprintf(stderr, "token in func:%s\n", token);
// #endif

	return token;

}

/**
 * parse zone file and add all zones into records
 * each line of the file is these values separated by space:
 * name class type value
 * e.g.
 * example.com IN A 1.2.3.4
 * version.bind CH TXT 6.9
 */
void parse_zone_file(char* filename) {
	FILE *fp = fopen(filename, "r");
	if (!fp) {
		perror(filename);
	}

	while (!feof(fp)) {
		char line[RECORD_LINE_MAX] = {0,};
		fgets(line, RECORD_LINE_MAX, fp);
		if (line[0]=='#') { //skip comments
			continue;
		}
		if (strlen(line) <= 1) {
			break;
		}
		// get tokens (quoted = double quotes only)
		char* name = get_nth_whitespace_quoted_token(line, strlen(line)-1, 1); // strlen - 1 to get rid of \n
		char* class = get_nth_whitespace_quoted_token(line, strlen(line)-1, 2);
		char* type = get_nth_whitespace_quoted_token(line, strlen(line)-1, 3);
		char* value = get_nth_whitespace_quoted_token(line, strlen(line)-1, 4);
#ifdef DEBUG

		fprintf(stderr,"parsed name:%s class:%s type:%s value:%s\n", name,class,type, value);
		// char name_type[strlen(name)+strlen(type) +2];
		// sprintf(name_type, "%s-%s", name, type);
		// name_type[strlen(name)+strlen(type) +2 - 1] = 0; //NULL term
		// fprintf(stderr, "key:%s\n", name_type);
		add_name(name, type, class,value);
#endif
	}


}

int main(int argc, char **argv) {
	
	int port = 53; // TODO take arg, argparse etc.

	// arg parsing
	int ch;
	int debug_count  = 0;
	char* zonefile = "flatzone.txt";
	// zonefile; = "flatzone.txt";
	while ((ch = getopt(argc, argv, "f:p:D:")) != -1) {
		if (ch == 'p') {
			port = atoi(optarg);
		} 
		if (ch == 'D') {
			debug_count = atoi(optarg);
			fprintf(stderr, "debug_count: %d\n", debug_count);
		} 
		if (ch == 'f') {
			// fprintf(stderr,"option -f\n");
			if (optarg) {
				zonefile = optarg;
			}
		} 
		if (ch == ':') {
			// missing argument
			return -1;
		}
	}

	fprintf(stderr, "using zone file %s\n", zonefile);

	parse_zone_file(zonefile);

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

	size_t count = 0;

#ifdef DEBUG
	fprintf(stderr, "started on port: %d\n", port);
#endif
	while (1) { // i guess udp doesn't need multi threads
		struct sockaddr from;
		memset(&from, 0, sizeof(from));
		socklen_t fromLen = sizeof(struct sockaddr);
		unsigned char buf[QMAX] = {0,};
		ssize_t rlen = recvfrom(s, buf, QMAX, 0, &from, &fromLen);
#ifdef DEBUG
		// msginfo((struct sockaddr_storage *) &from, fromLen, rlen);
		// hexdump(buf, rlen);
#endif
		// if (!fork()) { //child?
		process_query(buf, rlen, &from, fromLen, s);
			// return 0;
		// }
		
		count ++;
#ifdef DEBUG
		fprintf(stderr, "count:%d\n", count);
#endif
		if (debug_count != 0 && count == debug_count) {
			fprintf(stderr, "finishing up in debug mode..\n");
			return 0;
		}
	}


	return 0;
}