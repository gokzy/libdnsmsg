#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include "dnsmsg.h"

static dm_err dns_header_parse(struct dns_info *dinfo);
static dm_err dns_question_section_parse(struct dns_info *dinfo);

#define ngx_queue_free(ngx_queue, type)			\
do {							\
	ngx_queue_t *q;					\
	type *info;					\
							\
	ngx_queue_foreach (q, &ngx_queue) {		\
		info = ngx_queue_data(q, type, queue);	\
		ngx_queue_remove(&info->queue);		\
		free(info);				\
	}						\
} while(0)


static dm_err dns_header_parse(struct dns_info *dinfo)
{
	struct dns_header *hdr_info;
	struct dns_header *hdr;
	struct dns_msg_buff *dmb;

	assert(dinfo != NULL);

	if (!dinfo->dmb)
		return ENODMB;
	else
		dmb = dinfo->dmb;

	hdr_info = malloc(sizeof(struct dns_header));
	if (!hdr_info)
		return ENOMEM; 

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

	return SUCCESS;
}

/*
 * 
 *
 * Arguments:
 *
 * Return:
 *
 */
static dm_err dns_question_section_parse(struct dns_info *dinfo)
{
	struct dns_msg_buff *dmb;
	struct dns_header *hdr;
	dns_question_info_t *qinfo;
	u_char *qsec_head;
	u_char *qname = NULL;
	int len = 0;
	int i;

	if (!dinfo->dmb)
		return ENODMB;
	else
		dmb = dinfo->dmb;
	
	if (!dinfo->hdr_info) {
		int errno;

		if((errno = dns_header_parse(dinfo)) != SUCCESS)
			return errno;
	}

	hdr = dinfo->hdr_info;
	qsec_head = dmb->dns_ques_sec_head;
	ngx_queue_init(&dinfo->ques_info);

	for (i = 0; i < hdr->qdcount; i++) {
		enum RR_CLASS *qclass;
		enum RR_TYPE *qtype;

		qinfo = malloc(sizeof(dns_question_info_t));

		if (!qinfo) {
			ngx_queue_free(dinfo->ques_info, dns_question_info_t);
			return ENOMEM;
		}

		ngx_queue_init(&qinfo->queue);

		len += decode_qname2string(qsec_head, &qname, dmb);

		qtype = (enum RR_TYPE *)(qsec_head + len);
		len += sizeof(u_int16_t);
		
		qclass = (enum RR_CLASS *)(qsec_head + len);
		len += sizeof(u_int16_t);

		qinfo->qname = qname;
		qinfo->qtype = ntohs(*qtype);
		qinfo->qclass = ntohs(*qclass);

		ngx_queue_insert_tail(&dinfo->ques_info, &qinfo->queue);
	}

	dmb->dns_ques_sec_tail = qsec_head + len;
	
	if (hdr->ancount != 0)
		dmb->dns_ans_sec_head = dmb->dns_ques_sec_tail + 1;
	else if (hdr->nscount != 0)
		dmb->dns_auth_sec_head = dmb->dns_ques_sec_tail + 1;
	else if (hdr->arcount != 0)
		dmb->dns_add_sec_head = dmb->dns_ques_sec_tail + 1;

	return SUCCESS;
}

int dns_answer_section_parse(struct dns_info *dinfo)
{
	struct dns_header *hdr;
	struct dns_msg_buff *dmb;
	dns_answer_info_t *ainfo;
	u_char *asec_head, *ansname;
	int i, len = 0;

	if (!dinfo->dmb)
		return ENODMB;
	else
		dmb = dinfo->dmb;

	/*
	 * 
	 */
	if (!dinfo->hdr_info) {
		int errno;

		if ((errno = dns_header_parse(dinfo)) != SUCCESS)
			return errno;
	}

	hdr = dinfo->hdr_info;
	asec_head = dmb->dns_ans_sec_head;
	ngx_queue_init(&dinfo->ans_info);

	for (i = 0; i < hdr->ancount; i++) {
		enum RR_CLASS *class;
		enum RR_TYPE *type;
		u_int32_t *ttl;
		u_int16_t *rdlength;
		void *rdata;

		ainfo = malloc(sizeof(dns_answer_info_t));

		/* date free...*/
		if (!ainfo) {
			ngx_queue_free(dinfo->ans_info, dns_answer_info_t);
			return ENOMEM;
		}

		ngx_queue_init(&ainfo->queue);

		len += decode_qname2string(asec_head + len, &ansname, dmb);
		type = (enum RR_TYPE *)(asec_head + len);
		len += sizeof(u_int16_t);

		class = (enum RR_CLASS *)(asec_head + len);
		len += sizeof(u_int16_t);
		
		ttl = (u_int32_t *)(asec_head + len);
		len += sizeof(u_int32_t);

		rdlength = (u_int16_t *)(asec_head + len);
		len += sizeof(u_int16_t);

		resource_record_reader[ntohs(*type)](dmb, 0, asec_head + len, &rdata);
		len += ntohs(*rdlength);

		ainfo->name = ansname;
		ainfo->type = ntohs(*type);
		ainfo->class = ntohs(*class);
		ainfo->ttl = ntohl(*ttl);
		ainfo->rdlength = ntohs(*rdlength);
		ainfo->rdata = rdata;

		ngx_queue_insert_tail(&dinfo->ans_info, &ainfo->queue);
	}
	
	return 0;
}

static dm_err dmb_put_bin_msg(struct dns_msg_buff *dmb, u_char *msg, int len)
{
	assert(dmb != NULL);
	assert(msg != NULL);

	dmb->msg = msg;
	dmb->head = msg;
	dmb->data = msg;
	dmb->end = msg + len;
	dmb->tail = msg + len;

	return SUCCESS;
}


/*
 * Free
 *  
 * Arguments:
 *  dns_info 
 *
 * Return:
 *
 *
 *
 */
dm_err free_dns_info(struct dns_info *dinfo)
{
	
	free(dinfo->hdr_info);

	if (!ngx_queue_empty(&dinfo->ques_info))
		ngx_queue_free(dinfo->ques_info, dns_question_info_t);

	if (!ngx_queue_empty(&dinfo->ans_info))
		ngx_queue_free(dinfo->ans_info, dns_answer_info_t);

	if (!ngx_queue_empty(&dinfo->auth_info))
		ngx_queue_free(dinfo->ans_info, dns_authority_info_t);

	if (!ngx_queue_empty(&dinfo->add_info))
		ngx_queue_free(dinfo->ans_info, dns_additional_info_t);

	return SUCCESS;
}

/*
 * 
 *
 */
dm_err dns_mesg_perse_from_bin(u_char *msg, int len, struct dns_info **dinfo)
{
	struct dns_info *info;
	struct dns_msg_buff *dmb;
	int err;

	if (!msg)
		return EINVALIDARG;

	info = malloc(sizeof(struct dns_info));
	if (!info)
		return ENOMEM;

	dmb = dmb_alloc_header();
	if (!dmb) {
		free(info);
		return ENOMEM;
	}

	dmb_put_bin_msg(dmb, msg, len);

	info->dmb = dmb;
	ngx_queue_init(&info->ques_info);
	ngx_queue_init(&info->ans_info);

	err = dns_header_parse(info);
	err = dns_question_section_parse(info);
	err = dns_answer_section_parse(info);

	*dinfo = info;

	return SUCCESS;
}


