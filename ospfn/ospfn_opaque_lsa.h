#ifndef _OSPFN_OPAQUE_LSA_H_
#define _OSPFN_OPAQUE_LSA_H_

// LSA related Header 

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_opaque.h"
#include "tables.h"


#define ASYNCPORT 4000
#define NAME_OPAQUE_LSA 236
#define ADJ_OPAQUE_LSA 234


struct name_opaque_body
{
	u_int32_t name_length;
	u_int8_t name_type;
	u_char name_data[1];
};

struct name_opaque_lsa
{
	struct lsa_header header;
	struct name_opaque_body body;
};



struct ndnx_opaque_lsa
{
	struct lsa_header lsah;
	char name[1];
};

struct ndnx_adjacent_opaque_lsa
{
	struct lsa_header lsah;
	char adj_list[1];
};

#endif
//extern struct ndn_neighbors *neighbors=NULL;

// function protoype

void ndnx_opaque_lsa_print (struct ndnx_opaque_lsa  *col);
void ndnx_name_opaque_lsa_print (struct ndnx_opaque_lsa  *ol);

void ospf_router_lsa_print (struct router_lsa  *rl, u_int16_t length);
void ndnx_lsa_header_dump (struct lsa_header *lsah);


void update_opaque_lsa(struct ndnx_opaque_lsa *col);
void update_name_opaque_lsa(struct ndnx_opaque_lsa *col);

void delete_opaque_lsa(struct ndnx_opaque_lsa * lsa);
void delete_name_opaque_lsa(struct ndnx_opaque_lsa * col);

