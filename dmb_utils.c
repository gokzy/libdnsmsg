#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include "dnsmsg.h"

struct dns_msg_buff *dmb_alloc_header(void) 
{
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

struct dns_msg_buff *dmb_alloc(void) 
{
	struct dns_msg_buff *dmb;

	dmb = dmb_alloc_header();
	if (!dmb)
		return NULL;

	dmb->msg = malloc(MAX_STREAM_MESSAGE_LEN);
	if (!dmb->msg) {
		free(dmb);
		return NULL;
	}

	dmb->head = dmb->msg + 2;
	dmb->data = dmb->msg + 2;
	dmb->end = dmb->data;
	dmb->tail = dmb->msg + MAX_STREAM_MESSAGE_LEN;
	dmb->len = 0;

	return dmb;
}

void dmb_free(struct dns_msg_buff *dmb)
{
	if (!dmb->msg)
		free(dmb->msg);

	free(dmb);
}

dm_err dmb_push_data(struct dns_msg_buff *dmb, u_char *data, int len)
{
	assert(dmb->msg != NULL);

	if (dmb->end + len < dmb->tail)
		memcpy(dmb->end, data, len);
	else
		return ENOMSGBUF;

	dmb->end += len;

	return SUCCESS;
}

dm_err dmb_push_short(struct dns_msg_buff *dmb, u_int16_t data)
{
	u_int16_t ndata = htons(data);

	if (dmb->end + sizeof(u_int16_t) < dmb->tail)
		memcpy(dmb->end, (u_char *)&ndata, sizeof(u_int16_t));
	else
		return ENOMSGBUF;

	dmb->end += sizeof(u_int16_t);

	return SUCCESS;
}

dm_err dmb_push_long(struct dns_msg_buff *dmb, u_int32_t data)
{
	u_int32_t ndata = htonl(data);

	if (dmb->end + sizeof(u_int32_t) < dmb->tail)
		memcpy(dmb->end, (u_char *)&ndata, sizeof(u_int32_t));
	else
		return ENOMSGBUF;

	dmb->end += sizeof(u_int32_t);

	return SUCCESS;
}
