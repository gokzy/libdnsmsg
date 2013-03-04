#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "ngx-queue.h"

enum RR_CLASS {
	RR_CLASS_IN = 1
};

enum RR_TYPE {
	RR_TYPE_A = 1,
	RR_TYPE_AAAA = 28
};

struct dns_msg_buff {
	u_char *msg; /* */

	u_char *head;
	u_char *data;
	u_char *end;
	u_char *tail;

	u_char *dns_hdr_head, *dns_hdr_tail;
	u_char *dns_ques_sec_head, *dns_ques_sec_tail;
	u_char *dns_ans_sec_head, *dns_ans_sec_tail;
	u_char *dns_auth_sec_head, *dns_auth_sec_tail;
	u_char *dns_add_sec_head, *dns_add_sec_tail;

	int len;
};

#define DNS_QR 
#define DNS_OPCODE
#define DNS_AA
#define DNS_TC
#define DNS_RD
#define DNS_RA
#define DNS_Z
#define DNS_RCODE

struct dns_header {
	u_int16_t id;
	u_int16_t flags;
	u_int16_t qdcount;
	u_int16_t ancount;
	u_int16_t nscount;
	u_int16_t arcount;
};

struct dns_query {
	char *qname;
	enum RR_TYPE qtype;
	enum RR_CLASS qclass;
};

struct resource_record {
	char *name;
	enum RR_TYPE type;
	enum RR_CLASS class;
	u_int32_t ttl;
	u_int16_t rdlength;
	char *rdata;

	ngx_queue_t queue;
};

struct dns_question_info {
	char *qname;
	enum RR_TYPE qtype;
	enum RR_CLASS qclass;

	ngx_queue_t queue;
};

struct dns_info {
	struct dns_header *hdr_info;
	ngx_queue_t ques_info;
	ngx_queue_t ans_info;
	ngx_queue_t auth_info;
	ngx_queue_t add_info;
	/* struct dns_question_info *ques_info; */
	/* struct dns_answer_info *ans_info; */
	/* struct dns_authority_info *auth_info; */
	/* struct dns_addtitional_info *add_info; */

	struct dns_msg_buff *dmb;
};

typedef struct dns_question_info dns_question_info_t;

void msg_dump_hex_ascii(struct dns_msg_buff *dmb);
struct dns_msg_buff *dmb_alloc(void);
int dmb_free(struct dns_msg_buff *dmb);
int receive_queue(struct dns_msg_buff *dmb);
int send_query(struct dns_msg_buff *dmb);
u_int16_t generate_query_id(void);
int assemble_header(struct dns_msg_buff *dmb, u_int16_t flags);
u_char *convert_qname(char *domain);
int dmb_push_data(struct dns_msg_buff *dmb, u_char *data, int len);
int dmb_push_16(struct dns_msg_buff *dmb, u_int16_t data);
int push_qname(struct dns_msg_buff *dmb, u_char *data);
int push_qtype(struct dns_msg_buff *dmb, enum RR_TYPE type);
int push_qclass(struct dns_msg_buff *dmb, enum RR_CLASS class);
int assemble_question_section(struct dns_msg_buff *dmb, char *domaine, enum RR_TYPE qtype);
int main(void);


#define MAX_MESSAGE_LEN 65536
#define COMPRESSION(c) (c & 0xc0)

static ngx_queue_t domains;

struct domain {
	u_char *dname;
	u_char *ptr;
	
	ngx_queue_t queue;
};

void dump_hex(u_char *msg, int len) {
	
}

void msg_dump_hex_ascii(struct dns_msg_buff *dmb) {
	int i, row = 0;
	u_char *data;
	u_char ascii[17];

	if (!dmb) {
		fprintf(stdout, "dmb null\n");
		return;
	}

	data = dmb->head;

	while (data != dmb->end) {
		if (row == 16) {
			for (i = 0; i < 16; i++) {
				if ( i == 8 )
					fprintf(stdout ," ");
				fprintf(stdout, "%02x ", ascii[i]);
			}

			fprintf(stdout, " | ");

			for (i = 0; i < 16; i++) {
				if ( 33 <= ascii[i]  && ascii[i] <= 126)
					fprintf(stdout, "%c", ascii[i]);
				else
					fprintf(stdout, ".", ascii[i]);
			}
			fprintf(stdout, " |\n");
			row = 0;
		}

		ascii[row] = *data;
		data++;
		row++;
	}

	for (i = 0; i < row; i++) {
		if ( i == 7 )
			fprintf(stdout ," ");
		fprintf(stdout, "%02x ", ascii[i]);
	}
	
	fprintf(stdout, " | ");
	
	for (i = 0; i < row; i++) {
		if ( 33 <= ascii[i]  && ascii[i] <= 126)
			fprintf(stdout, "%c", ascii[i]);
		else
			fprintf(stdout, ".", ascii[i]);
	}
	fprintf(stdout, " |\n");

}


struct dns_msg_buff *dmb_alloc(void) {
	struct dns_msg_buff *dmb;

	dmb = malloc(sizeof(struct dns_msg_buff));
	if (!dmb)
		return NULL;

	dmb->msg = malloc(MAX_MESSAGE_LEN);
	if (!dmb->msg)
		return NULL;

	dmb->head = dmb->msg + 2;
	dmb->data = dmb->msg + 2;
	dmb->end = dmb->data;
	dmb->tail = dmb->msg + MAX_MESSAGE_LEN;
	dmb->len = 0;

	return dmb;
}

struct dns_msg_buff *dmb_alloc_header(void) {
	struct dns_msg_buff *dmb;

	dmb = malloc(sizeof(struct dns_msg_buff));
	if (!dmb)
		return NULL;

	dmb->head = NULL;
	dmb->data = NULL;
	dmb->end = NULL;
	dmb->tail = NULL;
	dmb->len = 0;

	return dmb;
}

#define MAX_MSG_PTR_LEN (0x4000 -1)

// function name ...
u_char *get_ptr(struct dns_msg_buff *dmb, u_int16_t offset)
{

	if (offset > MAX_MSG_PTR_LEN)
		return NULL;

	if ((dmb->data + offset) > dmb->end) 
		return NULL;

	return (dmb->data + offset);
}

int dmb_free(struct dns_msg_buff *dmb) {
	
}

int receive_queue(struct dns_msg_buff *dmb) {

}

int send_query(struct dns_msg_buff *dmb) {
	
}

u_int16_t generate_query_id(void) {
	return 0x1143;
};

int assemble_header(struct dns_msg_buff *dmb, u_int16_t flags) {
	u_int16_t id;
	struct dns_header *hdr;

	hdr = (struct dns_header *)dmb->data;
	
	hdr->id = htons(generate_query_id());
	hdr->flags = htons(flags);
	hdr->qdcount = htons(1);
	hdr->ancount = htons(0);
	hdr->nscount = htons(0);
	hdr->arcount = htons(0);

	dmb->dns_hdr_tail = dmb->data + sizeof(struct dns_header);

	dmb->end += sizeof(struct dns_header);

	return 0;
}

#define MAX_DNAME_LEN 256

int decode_qname2string(u_char *from, u_char *decoded, struct dns_msg_buff *dmb)
{
	u_char tmp[MAX_DNAME_LEN];
	int label_len, domain_len = 0;
	u_char *tttt = NULL;
	
	while (*from) {
		label_len = *from;
		from++;

		if (COMPRESSION(label_len)) {
			from = get_ptr(dmb, label_len);
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

	tttt = malloc(domain_len);
	if (!tttt)
		return 0;

	memcpy(decoded, tmp, domain_len);
	decoded[domain_len] = '\0';
	
	return domain_len;
}

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

int dmb_push_data(struct dns_msg_buff *dmb, u_char *data, int len)
{
	if (dmb->end + len < dmb->tail)
		memcpy(dmb->end, data, len);
	else
		return 1;

	dmb->end += len;

	return 0;
}

int dmb_push_16(struct dns_msg_buff *dmb, u_int16_t data)
{
	u_int16_t ndata = htons(data);
	if (dmb->end + sizeof(u_int16_t) < dmb->tail)
		memcpy(dmb->end, (u_char *)&ndata, sizeof(u_int16_t));
	else
		return 1;

	dmb->end += sizeof(u_int16_t);

	return 0;
}

int push_qname(struct dns_msg_buff *dmb, u_char *data)
{
	// replace strnlen()
	return dmb_push_data(dmb, data, (strlen(data) + 1));
}

int push_qtype(struct dns_msg_buff *dmb, enum RR_TYPE type)
{
	return dmb_push_16(dmb, (u_int16_t)type);
}

int push_qclass(struct dns_msg_buff *dmb, enum RR_CLASS class)
{
	return dmb_push_16(dmb, (u_int16_t)class);
}

int assemble_question_section(struct dns_msg_buff *dmb, char *domaine, enum RR_TYPE qtype)
{
	char *qname;

	qname = convert_qname(domaine);

	push_qname(dmb, qname);
	push_qtype(dmb, qtype);
	push_qclass(dmb, RR_CLASS_IN);

	return 0;
}

int dmb_put_bin_msg(struct dns_msg_buff *dmb, u_char *msg, int len)
{
	if (!msg)
		return 1;

	dmb->msg = msg;
	dmb->head = msg;
	dmb->data = msg;
	dmb->end = msg + len;
	dmb->tail = msg + len;

	return 0;
}


/*
 * return pase result in dns_info->hdr_info
 */
int dns_header_parse(struct dns_info *dinfo)
{
	struct dns_header *hdr_info;
	struct dns_header *hdr;
	struct dns_msg_buff *dmb;

	if (!dinfo->dmb)
		return 1;
	else
		dmb = dinfo->dmb;

	hdr_info = malloc(sizeof(struct dns_header));
	if (!hdr_info)
		return 1; 

	hdr = (struct dns_header *)dmb->head;

	hdr_info->id = ntohs(hdr->id);
	hdr_info->flags = ntohs(hdr->flags);
	hdr_info->qdcount = ntohs(hdr->qdcount);
	hdr_info->ancount = ntohs(hdr->ancount);
	hdr_info->nscount = ntohs(hdr->nscount);
	hdr_info->arcount = ntohs(hdr->arcount);

	dmb->dns_hdr_tail = dmb->head + sizeof(struct dns_header);

	if (hdr_info->qdcount != 0)
		dmb->dns_ques_sec_head = dmb->dns_hdr_tail;
	else if (hdr_info->ancount != 0)
		dmb->dns_ans_sec_head = dmb->dns_hdr_tail;
	else if (hdr_info->nscount != 0)
		dmb->dns_auth_sec_head = dmb->dns_hdr_tail;
	else if (hdr_info->arcount != 0)
		dmb->dns_add_sec_head = dmb->dns_hdr_tail;

	dinfo->hdr_info = hdr_info;

	return 0;
}

int dns_question_section_parse(struct dns_info *dinfo)
{
	struct dns_question_info *qinfo, *head = NULL;
	struct dns_msg_buff *dmb;
	struct dns_header *hdr;
	u_char *qsec_head, *work_ptr;
	u_char *qname = NULL;
	int len,i;

	if (!dinfo->dmb)
		return 1;
	else
		dmb = dinfo->dmb;
	
	if (!dinfo->hdr_info)
		if (dns_header_parse(dinfo))
			return 1;

	hdr = dinfo->hdr_info;
	qsec_head = dmb->dns_ques_sec_head;
	ngx_queue_init(&dinfo->ques_info);

	for (i = 0; i < hdr->qdcount; i++) {
		enum RR_CLASS *qclass;
		enum RR_TYPE *qtype;

		qinfo = malloc(sizeof(struct dns_question_info));

		/* date free...*/
		if (!qinfo)
			return 1;

		ngx_queue_init(&qinfo->queue);

		len += decode_qname2string(qsec_head, qname, dmb);
		printf("|%c|\n",qname[1]);
		qtype = (enum RR_TYPE *)(qsec_head + len);
		len += sizeof(u_int16_t);

		qclass = (enum RR_CLASS *)(qsec_head + len);
		len += sizeof(u_int16_t);

		qinfo->qname = qname;
		qinfo->qtype = ntohs(qtype);
		qinfo->qclass = ntohs(qclass);

		fprintf(stdout, "%s\n", qname);
		ngx_queue_insert_tail(&dinfo->ques_info, &qinfo->queue);
	}

	return 0;
}

int dns_answer_parse(struct dns_info *dinfo)
{

	return 0;
}

struct dns_info *dns_mesg_perse_from_bin(u_char *msg, int len)
{
	struct dns_info *info;
	struct dns_msg_buff *dmb;

	info = malloc(sizeof(struct dns_info));
	if (!info)
		return NULL;

	dmb = dmb_alloc_header();
	if (!dmb)
		return NULL;

	dmb_put_bin_msg(dmb, msg, len);

	info->dmb = dmb;
	
	dns_header_parse(info);
	dns_question_section_parse(info);
	dns_answer_parse(info);

	return info;
}


void show_dns_info(struct dns_info *dinfo)
{
	ngx_queue_t *q;

	struct dns_question_info *qinfo;
	struct dns_header *hdr = dinfo->hdr_info;

	if (!hdr)
		return;

	if (ngx_queue_empty(&dinfo->ques_info))
		return;

	ngx_queue_foreach(q, &dinfo->ques_info) {
		qinfo = ngx_queue_data(q, dns_question_info_t, queue);
		fprintf(stdout, "domain : %s\n", qinfo->qname);
	}
	
}

int main(void)
{
	struct dns_msg_buff *dmb;
	struct dns_info *dinfo;
	struct dns_query q = { 
		.qname = "setup.icloud.com",
		.qtype = RR_TYPE_A,
		.qclass = RR_CLASS_IN
	};

	dmb = dmb_alloc();
	if (!dmb)
		exit(1);

	assemble_header(dmb, 0x0100);
	assemble_question_section(dmb, "setup.icloud.com", RR_TYPE_A);

	msg_dump_hex_ascii(dmb);

	dinfo = dns_mesg_perse_from_bin(dmb->data, dmb->len);

	show_dns_info(dinfo);

	return 0;
}
