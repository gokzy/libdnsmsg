#include <sys/types.h>

#include "ngx-queue.h"

enum RR_CLASS {
	RR_CLASS_IN = 1
};

enum RR_TYPE {
	RR_TYPE_A = 1,
	RR_TYPE_NS = 2,
	RR_TYPE_MD = 3,
	RR_TYPE_CNAME = 5,
	RR_TYPE_AAAA = 28
};

/*
 * DNS Message Structure 
 *
 * ^  +----------------+ <= head
 * |  |  alighment     |
 * |  +----------------+ <= dns_hdr_head / data
 * |  |     header     |
 *    |                |
 * m  +----------------+ <= dmb_hdr_tail / dmb_ques_sec_head
 * s  |  question      |
 * g  |      section   |
 *    +----------------+ <= dmb_ques_sec_tail / dmb_ans_sec_head
 * |  |  answer        |
 * |  |      section   |
 * |  +----------------+ <= dmb_ans_sec_tail / dmb_auth_sec_head
 * |  |  authority     |
 * |  |      section   |
 * |  +----------------+ <= dmb_auth_sec_head / dmb_auth_sec_tail
 * |  |  additional    |
 * |  |      section   |
 * ^  +----------------+ <= dmb_auth_sec_tail / end
 *    | alighment      | 
 *    +----------------+ <= tail
 */
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

/*
 * DNS Header
 */
struct dns_header {
	u_int16_t id;
	u_int16_t flags;
	u_int16_t qdcount;
	u_int16_t ancount;
	u_int16_t nscount;
	u_int16_t arcount;
};

/*
 * 
 */
struct dns_question_info {
	u_char *qname;
	enum RR_TYPE qtype;
	enum RR_CLASS qclass;

	ngx_queue_t queue;
};

/*
 * Resource Record Data Structure.
 */
struct resource_record {
	u_char *name;
	enum RR_TYPE type;
	enum RR_CLASS class;
	u_int32_t ttl;
	u_int16_t rdlength;
	void *rdata;

	ngx_queue_t queue;
};

typedef struct dns_question_info dns_question_info_t;
typedef struct resource_record dns_answer_info_t;
typedef struct resource_record dns_authority_info_t;
typedef struct resource_record dns_additional_info_t;

/*
 * hdr_info
 * ques_info : question section 
 * ans_info  : answer section
 * auth_info : authentication section
 * add_info  : additional section
 */
struct dns_info {
	struct dns_header *hdr_info;
	ngx_queue_t ques_info;
	ngx_queue_t ans_info;
	ngx_queue_t auth_info;
	ngx_queue_t add_info;

	struct dns_msg_buff *dmb;
	int err_code;
};

struct dns_query {
	char *qname;
	enum RR_TYPE qtype;
	enum RR_CLASS qclass;
};

/*
 * Error code
 */
enum DM_ERRNO {
	EUNKNOWN 	= -1,
	SUCCESS 	=  0,
	ENOMEM 		=  1,
	EINVALIDARG 	=  2,
	ENODMB 		=  3,
	ENOMSGBUF	=  4
};

/*
 * Error Nomber
 */

typedef int dm_err;

#define MAX_DATAGRAM_MESSAGE_LEN 512
#define MAX_STREAM_MESSAGE_LEN 65536

#define COMPRESSION(c) ((c & 0xc0) == 0xc0)

#define MAX_MSG_PTR_LEN (0x4000 -1)

/*
 *
 */
#define push_qname(dmb, data) (dmb_push_data(dmb, data, (strlen((char *)data) + 1)))
#define push_qtype(dmb, type) (dmb_push_short(dmb, (u_int16_t)type))
#define push_qclass(dmb, class) (dmb_push_short(dmb, (u_int16_t)class))
#define push_ttl(dmb, ttl) (dmb_push_long(dmb, ttl))

extern dm_err (*resource_record_reader[]) 
(struct dns_msg_buff *dmb, u_int16_t len, u_char *from, void **to);

/*
 * 
 *
 * Arguments:
 *
 * Return:
 *
 */

/*
 * Parse DNS message from binary
 *
 * Arguments:
 *  msg
 *  len
 *
 * Return:
 *  
 */
dm_err dns_mesg_parse_from_bin(u_char *msg, int lne, struct dns_info **dinfo);

/****************************************************
 * DNS Message Buffer Utils
 ****************************************************/

/*
 * Arguments:
 *  
 * Return:
 *  
 */
struct dns_msg_buff *dmb_alloc_header(void);

/*
 * Arguments:
 *  
 * Return:
 *  return NULL if 
 *  
 */
struct dns_msg_buff *dmb_alloc(void);

/*
 * Arguments:
 *  
 * Return:
 *  
 */
void dmb_free(struct dns_msg_buff *dmb);

/*
 *
 */
dm_err dmb_push_data(struct dns_msg_buff *dmb, u_char *data, int len);

/*
 *
 */
dm_err dmb_push_short(struct dns_msg_buff *dmb, u_int16_t data);
dm_err dmb_push_long(struct dns_msg_buff *dmb, u_int16_t data);


/***********************************
 * Debug Message
 ***********************************/
void show_dns_info(struct dns_info *dinfo);
void msg_dump_hex_ascii(struct dns_msg_buff *dmb);
