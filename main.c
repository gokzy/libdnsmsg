#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "dnsmsg.h"

#define DNS_OPCODE
#define DNS_AA
#define DNS_TC
#define DNS_RD
#define DNS_RA
#define DNS_Z
#define DNS_RCODE

int decode_qname2string(u_char *from, u_char **decoded, struct dns_msg_buff *dmb);

int main(void);

// function name ...
u_char *get_ptr(struct dns_msg_buff *dmb, u_int16_t offset)
{

	if (offset > MAX_MSG_PTR_LEN)
		return NULL;

	if ((dmb->data + offset) > dmb->end)
		return NULL;

	return (dmb->data + offset);
}

#define MAX_DNAME_LEN 256

// return length of real data
int decode_qname2string(u_char *from, u_char **decoded, struct dns_msg_buff *dmb)
{
	u_char tmp[MAX_DNAME_LEN];
	int label_len, domain_len = 0, real_domain_len = 0;
	
	while (*from) {
		label_len = *from;
		from++;

		if (COMPRESSION(label_len)) {
			u_int16_t *offset = (u_int16_t* )(from -1);

			from = get_ptr(dmb, ntohs(*offset) & ~0xc000);

			if (real_domain_len == 0) {
				real_domain_len = domain_len + 2;
			}

			if (!from)
				return 0;
		} else {
			memcpy(tmp + domain_len, from, label_len);
			from += label_len;
			domain_len += label_len;
			
			tmp[domain_len] = '.';
			domain_len++;
		}
		
	}

	*decoded = malloc(domain_len);
	if (!*decoded)
		return 0;

	memcpy(*decoded, tmp, domain_len);
	(*decoded)[domain_len] = '\0';
	
	return (real_domain_len == 0) ? domain_len : real_domain_len;
}


/*
 * return pase result in dns_info->hdr_info
 */
int main(void)
{
	struct dns_msg_buff *dmb;
	struct dns_info *dinfo = NULL;
	dinfu_char dns_msg[509];
	FILE *f;
	
	/* struct dns_query q = {  */
	/* 	.qname = "setup.icloud.com", */
	/* 	.qtype = RR_TYPE_A, */
	/* 	.qclass = RR_CLASS_IN */
	/* }; */

	dmb = dmb_alloc();
	if (!dmb)
		exit(1);

	assemble_header(dmb, 0x0100);
	assemble_question_section(dmb, "setup.icloud.com", RR_TYPE_A);

	msg_dump_hex_ascii(dmb);

	/* dinfo = dns_mesg_perse_from_bin(dmb->data, dmb->len); */
	/* show_dns_info(dinfo); */

	f = fopen("test_bin/setup.iclou.com.bin","rb");
	fread(dns_msg, sizeof(u_char), 509, f);
	fclose(f);

	dinfo = dns_mesg_perse_from_bin(dns_msg, 509);
	if (dinfo == NULL) {
			printf("null complete\n");
	}
	show_dns_info(dinfo);

	return 0;
}
