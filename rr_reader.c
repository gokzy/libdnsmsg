#include <stdlib.h>
#include <arpa/inet.h>

#include "dnsmsg.h"

static dm_err dns_type_a_rr_reader(struct dns_msg_buff *dmb, u_int16_t len, 
				u_char *from, void **to);
static dm_err dns_type_cname_rr_reader(struct dns_msg_buff *dmb, u_int16_t len,
				u_char *from, void **to);
static dm_err dns_type_unsupported_reader(struct dns_msg_buff *dmd, u_int16_t len,
				u_char *from, void **to);

dm_err (*resource_record_reader[]) 
(struct dns_msg_buff *dmb, u_int16_t len, u_char *from, void **to) = {
	NULL, /* not define type number 0 */
	&dns_type_a_rr_reader,
	&dns_type_cname_rr_reader,
	NULL,
	NULL,
	&dns_type_cname_rr_reader
};

/*
 * struct dns_msg_buuf *dmb
 * u_char *from
 * void **rdata
 * u_int16_t rlen
 */
static dm_err dns_type_a_rr_reader(struct dns_msg_buff *dmb, u_int16_t len, 
				u_char *from,  void **to)
{
	struct in_addr *ipv4addr;

	ipv4addr = (struct in_addr *)malloc(sizeof(struct in_addr));
	if (!ipv4addr)
		return ENOMEM;

	ipv4addr = (struct in_addr *)from;

	*to = ipv4addr;

	return SUCCESS;
}

static dm_err dns_type_cname_rr_reader(struct dns_msg_buff *dmb, u_int16_t len,
				u_char *from, void **to)
{
	int l;

	l = decode_qname2string(from, (u_char **)to, dmb);

	/* if (l != len) */
	/* 	fprintf(stdout, "l != len erro\n"); */

	return l;
}

static int dns_type_unsupported_reader(struct dns_msg_buff *dmd, u_int16_t len, 
				u_char *from, void **to)
{
	return -1;
}
