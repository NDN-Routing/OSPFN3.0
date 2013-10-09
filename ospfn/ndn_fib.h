
#ifndef _NDN_FIB_H_
#define _NDN_FIB_H_

#define NDN_FIB_LIFETIME ((~0U) >> 1)
#define NDN_FIB_MCASTTTL (-1)
#define OP_REG  0
#define OP_UNREG 1

extern void init_data(struct ndn_charbuf *local_scope_template);
extern int get_ndndid(struct ndn *h, struct ndn_charbuf *local_scope_template,unsigned char *ndndid);
extern int add_ndn_face(struct ndn *h, const char *uri, const char *address, const unsigned int p);
extern int delete_ndn_face(struct ndn *h, const char *uri, const char *address, const unsigned int p);
#endif
