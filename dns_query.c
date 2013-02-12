#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include "dnsmsg.h"

static int assemble_header(struct dns_msg_buff *dmb, u_int16_t flags);
static int assemble_question_section(struct dns_msg_buff *dmb, char *domaine, enum RR_TYPE qtype);

u_char *convert_qname(char *domain) {
	int domain_len;
	u_int16_t label_len;
	u_char *qname, *tmp, *head;

	domain_len = strlen(domain);

	qname = (u_char *)malloc(domain_len + 1);
	if (!qname)
		return NULL;

	label_len = 0;
	head = tmp = qname;
	qname++;

	while (*domain) {
		if (*domain == '.') {
			*tmp = label_len;
			tmp = qname;
			label_len = 0;
		} else {
			*qname = *domain;
			label_len++;
		}
		qname++;
		domain++;
	}
	*tmp = label_len;
	qname++;
	*qname = '\0';

	return head;
}

static u_int16_t generate_query_id(void) {
	return 0x1143;
};

static int assemble_header(struct dns_msg_buff *dmb, u_int16_t flags) {
	//u_int16_t id;
	struct dns_header *hdr;

	assert(dmb != NULL);

	hdr = (struct dns_header *)dmb->data;
	
	hdr->id = htons(generate_query_id());
	hdr->flags = htons(flags);
	hdr->qdcount = htons(1);
	hdr->ancount = htons(0);
	hdr->nscount = htons(0);
	hdr->arcount = htons(0);

	dmb->dns_hdr_tail = dmb->data + sizeof(struct dns_header);

	dmb->end += sizeof(struct dns_header);

	return SUCCESS;
}

static int assemble_question_section(struct dns_msg_buff *dmb, char *domaine, enum RR_TYPE qtype)
{
	u_char *qname;

	qname = convert_qname(domaine);

	push_qname(dmb, qname);
	push_qtype(dmb, qtype);
	push_qclass(dmb, RR_CLASS_IN);

	return SUCCESS;
}
