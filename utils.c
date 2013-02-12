#include "dnsmsg.h"

void msg_dump_hex_ascii(struct dns_msg_buff *dmb)
{
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
					fprintf(stdout, ".");
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
o			fprintf(stdout ," ");
		fprintf(stdout, "%02x ", ascii[i]);
	}
	
	fprintf(stdout, " | ");
	
	for (i = 0; i < row; i++) {
		if ( 33 <= ascii[i]  && ascii[i] <= 126)
			fprintf(stdout, "%c", ascii[i]);
		else
			fprintf(stdout, ".");
	}
	fprintf(stdout, " |\n");
}

void show_dns_info(struct dns_info *dinfo)
{
	ngx_queue_t *q;

	struct dns_question_info *qinfo;
	struct dns_answer_info *ainfo;
	struct dns_header *hdr = dinfo->hdr_info;

	if (!hdr)
		return;

	if (ngx_queue_empty(&dinfo->ques_info))
		return;

	ngx_queue_foreach(q, &dinfo->ques_info) {
		qinfo = ngx_queue_data(q, dns_question_info_t, queue);
		fprintf(stdout, "========= question ========\n");
		fprintf(stdout, "domain : %s\n", qinfo->qname);
	}

	if (ngx_queue_empty(&dinfo->ans_info))
		return;

	ngx_queue_foreach(q, &dinfo->ans_info) {
		ainfo = ngx_queue_data(q, dns_answer_info_t, queue);
		fprintf(stdout, "========= answer rr_type %d========\n", ainfo->type);
		fprintf(stdout, "domain : %s\n", ainfo->name);
		if (ainfo->type == RR_TYPE_CNAME || ainfo->type == RR_TYPE_NS)
			fprintf(stdout, "cname : %s\n", ainfo->rdata);
		else if(ainfo->type == RR_TYPE_A)
			fprintf(stdout, "addr : %s\n", 
				inet_ntoa(*(struct in_addr *)ainfo->rdata));
		else
			fprintf(stdout, "unknowk resouce recorde type %x\n",ainfo->type);
	}
	
}
