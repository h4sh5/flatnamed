#ifndef QTYPES_H
#define QTYPES_H

// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
// https://en.wikipedia.org/wiki/List_of_DNS_record_types
enum qtype { 
	type_A  = 1,
	type_NS  = 2,
	type_CNAME  = 5,
	type_SOA  = 6,
	type_PTR  = 12,
	type_HINFO  = 13,
	type_MX  = 15,
	type_TXT  = 16,
	type_RP  = 17,
	type_AFSDB  = 18,
	type_SIG  = 24,
	type_KEY  = 25,
	type_AAAA  = 28,
	type_LOC  = 29,
	type_SRV  = 33,
	type_NAPTR  = 35,
	type_KX  = 36,
	type_CERT  = 37,
	type_DNAME  = 39,
	type_OPT	= 41,
	type_APL  = 42,
	type_DS  = 43,
	type_SSHFP  = 44,
	type_IPSECKEY  = 45,
	type_RRSIG  = 46,
	type_NSEC  = 47,
	type_DNSKEY  = 48,
	type_DHCID  = 49,
	type_NSEC3  = 50,
	type_NSEC3PARAM  = 51,
	type_TLSA  = 52,
	type_SMIMEA  = 53,
	type_HIP  = 55,
	type_CDS  = 59,
	type_CDNSKEY  = 60,
	type_OPENPGPKEY  = 61,
	type_CSYNC  = 62,
	type_ZONEMD  = 63,
	type_SVCB  = 64,
	type_HTTPS  = 65,
	type_EUI48  = 108,
	type_EUI64  = 109,
	type_TKEY  = 249,
	type_TSIG  = 250,
	type_IXFR = 251,
	type_AXFR = 252,
	type_ANY = 255, // *
	type_URI  = 256,
	type_CAA  = 257,
	type_TA  = 32768,
	type_DLV  = 32769 
};

enum qclass {
	IN = 1, // internet
	CS = 2, // CSNET
	CH = 3, // CHAOS
	HS = 4, // Hesiod

};

#endif