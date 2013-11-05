/**
* @file ndn_fib.c 
*
* Manipulate ndnd fib for ospfn
*
* @author Cheng Yi,  AKM Hoque
*
*/


#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>

#include <ndn/ndn.h>
#include <ndn/uri.h>
#include <ndn/face_mgmt.h>
#include <ndn/reg_mgmt.h>
#include <ndn/charbuf.h>

#include "ndn_fib.h"
#include "ospfn.h"

static void 
ndn_fib_warn(int lineno, const char *format, ...)
{
	struct timeval t;
	va_list ap;
	va_start(ap, format);
	gettimeofday(&t, NULL);
	fprintf(stderr, "%d.%06d ndn_fib[%d]:%d: ", (int)t.tv_sec, (unsigned)t.tv_usec, (int)getpid(), lineno);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

static void 
ndn_fib_fatal(int lineno, const char *format, ...)
{
	struct timeval t;
	va_list ap;
	va_start(ap, format);
	gettimeofday(&t, NULL);
	fprintf(stderr, "%d.%06d ndn_fib[%d]:%d: ", (int)t.tv_sec, (unsigned)t.tv_usec, (int)getpid(), lineno);
	vfprintf(stderr, format, ap);
	va_end(ap);
	//exit(1);
}

#define ON_ERROR_EXIT(resval, msg) on_error_exit((resval), __LINE__, msg)

static void 
on_error_exit(int res, int lineno, const char *msg)
{
	if (res >= 0)
		return;
	ndn_fib_fatal(lineno, "fatal error, res = %d, %s\n", res, msg);
}

#define ON_ERROR_CLEANUP(resval) \
{           \
    if ((resval) < 0) { \
        ndn_fib_warn (__LINE__, "OnError cleanup\n"); \
        goto cleanup; \
    } \
}

#define ON_NULL_CLEANUP(resval) \
{           \
    if ((resval) == NULL) { \
        ndn_fib_warn(__LINE__, "OnNull cleanup\n"); \
        goto cleanup; \
    } \
}


/**
 * 
 * Bind a prefix to a face
 *
 */
static int 
register_unregister_prefix(struct ndn *h, struct ndn_charbuf *local_scope_template,
        struct ndn_charbuf *no_name, struct ndn_charbuf *name_prefix,
        struct ndn_face_instance *face_instance, int operation)
{
	struct ndn_charbuf *temp = NULL;
	struct ndn_charbuf *resultbuf = NULL;
	struct ndn_charbuf *signed_info = NULL;
	struct ndn_charbuf *name = NULL;
	struct ndn_charbuf *prefixreg = NULL;
	//struct ndn_parsed_ContentObject pcobuf = {0};
	//struct ndn_forwarding_entry forwarding_entry_storage = {0};
	struct ndn_parsed_ContentObject pcobuf;
	struct ndn_forwarding_entry forwarding_entry_storage;
	struct ndn_forwarding_entry *forwarding_entry = &forwarding_entry_storage;
	struct ndn_forwarding_entry *new_forwarding_entry;
	const unsigned char *ptr = NULL;
	size_t length = 0;
	int res;

	/* Register or unregister the prefix */
	forwarding_entry->action = (operation == OP_REG) ? "prefixreg" : "unreg";
	forwarding_entry->name_prefix = name_prefix;
	forwarding_entry->ndnd_id = face_instance->ndnd_id;
	forwarding_entry->ndnd_id_size = face_instance->ndnd_id_size;
	forwarding_entry->faceid = face_instance->faceid;
	forwarding_entry->flags = -1;
	forwarding_entry->lifetime = 2100;

	prefixreg = ndn_charbuf_create();
	ndnb_append_forwarding_entry(prefixreg, forwarding_entry);
	temp = ndn_charbuf_create();
	res = ndn_sign_content(h, temp, no_name, NULL, prefixreg->buf, prefixreg->length);
	resultbuf = ndn_charbuf_create();

	/* construct Interest containing prefixreg request */
	name = ndn_charbuf_create();
	ndn_name_init(name);
	ndn_name_append_str(name, "ndnx"); // change from ndn to ndnx
	ndn_name_append(name, face_instance->ndnd_id, face_instance->ndnd_id_size);
	ndn_name_append_str(name, (operation == OP_REG) ? "prefixreg" : "unreg");
	ndn_name_append(name, temp->buf, temp->length);

	/* send Interest, get Data */
	res = ndn_get(h, name, local_scope_template, 1000, resultbuf, &pcobuf, NULL, 0);
	ON_ERROR_CLEANUP(res);

	res = ndn_content_get_value(resultbuf->buf, resultbuf->length, &pcobuf, &ptr, &length);
	ON_ERROR_CLEANUP(res);
    
	/* extract new forwarding entry from Data */
	new_forwarding_entry = ndn_forwarding_entry_parse(ptr, length);
	ON_NULL_CLEANUP(new_forwarding_entry);

	res = new_forwarding_entry->faceid;

	ndn_forwarding_entry_destroy(&new_forwarding_entry);
	ndn_charbuf_destroy(&signed_info);
	ndn_charbuf_destroy(&temp);
	ndn_charbuf_destroy(&resultbuf);
	ndn_charbuf_destroy(&name);
	ndn_charbuf_destroy(&prefixreg);

	return res;

	cleanup:
		//ndn_forwarding_entry_destroy(&new_forwarding_entry);
		//ndn_charbuf_destroy(&signed_info);
		//ndn_charbuf_destroy(&temp);
		//ndn_charbuf_destroy(&resultbuf);
		//ndn_charbuf_destroy(&name);
		//ndn_charbuf_destroy(&prefixreg);

		if ( (new_forwarding_entry) !=NULL ){ 
			ndn_forwarding_entry_destroy(&new_forwarding_entry);
		}
		if ( (signed_info) != NULL ){
			ndn_charbuf_destroy(&signed_info);
		}
		if ( (temp) != NULL ){
			ndn_charbuf_destroy(&temp);
		}
		if ( (resultbuf) != NULL ){
			ndn_charbuf_destroy(&resultbuf);
		}
		if ( (name)!=NULL ){
			ndn_charbuf_destroy(&name);
		}
		if ( (prefixreg) != NULL ){
			ndn_charbuf_destroy(&prefixreg);
		}

	return -1;
}

/**
 *
 * Create new face by sending out a request Interest
 * The actual new face instance is returned
 * 
 */
static 
struct ndn_face_instance *create_face(struct ndn *h, struct ndn_charbuf *local_scope_template,
        struct ndn_charbuf *no_name, struct ndn_face_instance *face_instance)
{
	struct ndn_charbuf *newface = NULL;
	struct ndn_charbuf *signed_info = NULL;
	struct ndn_charbuf *temp = NULL;
	struct ndn_charbuf *name = NULL;
	struct ndn_charbuf *resultbuf = NULL;
	//struct ndn_parsed_ContentObject pcobuf = {0};
	struct ndn_parsed_ContentObject pcobuf;
	struct ndn_face_instance *new_face_instance = NULL;
	const unsigned char *ptr = NULL;
	size_t length = 0;
	int res = 0;

	/* Encode the given face instance */
	newface = ndn_charbuf_create();
	ndnb_append_face_instance(newface, face_instance);

	temp = ndn_charbuf_create();
	res = ndn_sign_content(h, temp, no_name, NULL, newface->buf, newface->length);
	resultbuf = ndn_charbuf_create();

	/* Construct the Interest name that will create the face */
	name = ndn_charbuf_create();
	ndn_name_init(name);
	ndn_name_append_str(name, "ndnx");
	ndn_name_append(name, face_instance->ndnd_id, face_instance->ndnd_id_size);
	ndn_name_append_str(name, face_instance->action);
	ndn_name_append(name, temp->buf, temp->length);

	/* send Interest to retrieve Data that contains the newly created face */
	res = ndn_get(h, name, local_scope_template, 1000, resultbuf, &pcobuf, NULL, 0);
	ON_ERROR_CLEANUP(res);

	/* decode Data to get the actual face instance */
	res = ndn_content_get_value(resultbuf->buf, resultbuf->length, &pcobuf, &ptr, &length);
	ON_ERROR_CLEANUP(res);

	new_face_instance = ndn_face_instance_parse(ptr, length);

	ndn_charbuf_destroy(&newface);
	ndn_charbuf_destroy(&signed_info);
	ndn_charbuf_destroy(&temp);
	ndn_charbuf_destroy(&resultbuf);
	ndn_charbuf_destroy(&name);

	return new_face_instance;

	cleanup:
		//ndn_charbuf_destroy(&newface);
		//ndn_charbuf_destroy(&signed_info);
		//ndn_charbuf_destroy(&temp);
		//ndn_charbuf_destroy(&resultbuf);
		//ndn_charbuf_destroy(&name);

		if ( (newface) != NULL ){
			ndn_charbuf_destroy(&newface);
		}
		if ( (signed_info) != NULL ){
			ndn_charbuf_destroy(&signed_info);
		}
		if ( (temp) != NULL ){
			ndn_charbuf_destroy(&temp);
		}
		if ( (resultbuf) != NULL ){
			ndn_charbuf_destroy(&resultbuf);
		}
		if ( (name) != NULL ){
			ndn_charbuf_destroy(&name);
		}

	return NULL;
}

/**
 *
 * Get ndnd id
 *
 */
int 
get_ndndid(struct ndn *h, struct ndn_charbuf *local_scope_template,
        unsigned char *ndndid)
{
	struct ndn_charbuf *name = NULL;
	struct ndn_charbuf *resultbuf = NULL;
	//struct ndn_parsed_ContentObject pcobuf = {0};
	struct ndn_parsed_ContentObject pcobuf;
	char ndndid_uri[] = "ndn:/%C1.M.S.localhost/%C1.M.SRV/ndnd/KEY";
	const unsigned char *ndndid_result;
	static size_t ndndid_result_size;
	int res;

	name = ndn_charbuf_create();
	resultbuf = ndn_charbuf_create();

	res = ndn_name_from_uri(name, ndndid_uri);
	ON_ERROR_EXIT(res, "Unable to parse service locator URI for ndnd key\n");

	/* get Data */
	res = ndn_get(h, name, local_scope_template, 4500, resultbuf, &pcobuf, NULL, 0);
	ON_ERROR_EXIT(res, "Unable to get key from ndnd\n");

	/* extract from Data */
	res = ndn_ref_tagged_BLOB(NDN_DTAG_PublisherPublicKeyDigest,
            resultbuf->buf,
            pcobuf.offset[NDN_PCO_B_PublisherPublicKeyDigest],
            pcobuf.offset[NDN_PCO_E_PublisherPublicKeyDigest],
            &ndndid_result, &ndndid_result_size);
	ON_ERROR_EXIT(res, "Unable to parse ndnd response for ndnd id\n");

	memcpy((void *)ndndid, ndndid_result, ndndid_result_size);

	ndn_charbuf_destroy(&name);
	ndn_charbuf_destroy(&resultbuf);

	return (ndndid_result_size);
}

/**
 * Construct a new face instance based on the given address and port
 * This face instance is only used to send new face request
 */
static struct 
ndn_face_instance *construct_face(const unsigned char *ndndid, size_t ndndid_size,
        const char *address, const char *port)
{
	struct ndn_face_instance *fi = calloc(1, sizeof(*fi));
	char rhostnamebuf[NI_MAXHOST];
	char rhostportbuf[NI_MAXSERV];
	struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_flags = (AI_ADDRCONFIG),
        .ai_socktype = SOCK_DGRAM};
	struct addrinfo *raddrinfo = NULL;
	struct ndn_charbuf *store = ndn_charbuf_create();
	int host_off = -1;
	int port_off = -1;
	int res;

	res = getaddrinfo(address, port, &hints, &raddrinfo);
	if (res != 0 || raddrinfo == NULL) 
	{
		fprintf(stderr, "Error: getaddrinfo\n");
		return NULL;
	}

	res = getnameinfo(raddrinfo->ai_addr, raddrinfo->ai_addrlen,
            rhostnamebuf, sizeof(rhostnamebuf),
            rhostportbuf, sizeof(rhostportbuf),
            NI_NUMERICHOST | NI_NUMERICSERV);
	freeaddrinfo(raddrinfo);	
	if (res != 0) 
	{
		fprintf(stderr, "Error: getnameinfo\n");
		return NULL;
	}

	fi->store = store;
	fi->descr.ipproto = IPPROTO_UDP;
	fi->descr.mcast_ttl = NDN_FIB_MCASTTTL;
	fi->lifetime = NDN_FIB_LIFETIME;

	ndn_charbuf_append(store, "newface", strlen("newface") + 1);
	host_off = store->length;
	ndn_charbuf_append(store, rhostnamebuf, strlen(rhostnamebuf) + 1);
	port_off = store->length;
	ndn_charbuf_append(store, rhostportbuf, strlen(rhostportbuf) + 1);

	char *b = (char *)store->buf;
	fi->action = b;
	fi->descr.address = b + host_off;
	fi->descr.port = b + port_off;
	fi->descr.source_address = NULL;
	fi->ndnd_id = ndndid;
	fi->ndnd_id_size = ndndid_size;

	return fi;
}

/**
 * initialize local data
 */
void 
init_data(struct ndn_charbuf *local_scope_template)
        //struct ndn_charbuf *no_name)
{
	ndn_charbuf_append_tt(local_scope_template, NDN_DTAG_Interest, NDN_DTAG);
	ndn_charbuf_append_tt(local_scope_template, NDN_DTAG_Name, NDN_DTAG);
	ndn_charbuf_append_closer(local_scope_template);    /* </Name> */
	ndnb_tagged_putf(local_scope_template, NDN_DTAG_Scope, "1");
	ndn_charbuf_append_closer(local_scope_template);    /* </Interest> */

	//ndn_name_init(no_name);
}

static int 
add_delete_ndn_face(struct ndn *h, const char *uri, const char *address, const unsigned int p, int operation)
{
	struct ndn_charbuf *prefix;
	char port[6];
	//struct ndn_charbuf *local_scope_template = ndn_charbuf_create();
	struct ndn_charbuf *no_name = ndn_charbuf_create();
	//unsigned char ndndid_storage[32] = {0};
	//unsigned char *ndndid = ndndid_storage;
	//size_t ndndid_size = 0;
	struct ndn_face_instance *fi;
	struct ndn_face_instance *nfi;
	int res;

	prefix = ndn_charbuf_create();
	res = ndn_name_from_uri(prefix, uri);
	ON_ERROR_CLEANUP(res);
	memset(port, 0, 6);
	sprintf(port, "%d", p);

	//init_data(local_scope_template);//, no_name);
	ndn_name_init(no_name);

	/*
	ndndid_size = get_ndndid(h, local_scope_template, ndndid);
	if (ndndid_size != sizeof(ndndid_storage))
 	{
		fprintf(stderr, "Incorrect size for ndnd id in response\n");
		ON_ERROR_CLEANUP(-1);
	}
	*/

		

	/* construct a face instance for new face request */
	//fi = construct_face(ndndid, ndndid_size, address, port);
	fi = construct_face(ospfn->ndndid, ospfn->ndndid_size, address, port);
	ON_NULL_CLEANUP(fi);

	/* send new face request to actually create a new face */
	
	nfi = create_face(h, ospfn->local_scope_template, no_name, fi);
	ON_NULL_CLEANUP(nfi);

	res = register_unregister_prefix(h, ospfn->local_scope_template, no_name, prefix, nfi, operation);
	ON_ERROR_CLEANUP(res);

	//ndn_charbuf_destroy(&local_scope_template);
	ndn_charbuf_destroy(&no_name);
	ndn_face_instance_destroy(&fi);
	ndn_face_instance_destroy(&nfi);
	ndn_charbuf_destroy(&prefix);

	return 0;

	cleanup:
		//ndn_charbuf_destroy(&prefix);
		//ndn_charbuf_destroy(&local_scope_template);
		//ndn_charbuf_destroy(&no_name);
		//ndn_face_instance_destroy(&fi);
		//ndn_face_instance_destroy(&nfi);

		if ( (prefix) != NULL ){
			ndn_charbuf_destroy(&prefix);
		}
		if ( (no_name) != NULL ){
			ndn_charbuf_destroy(&no_name);
		}
		if ( (fi) != NULL ){
			ndn_face_instance_destroy(&fi);
		}
		if ( (nfi) != NULL ){
			ndn_face_instance_destroy(&nfi);
		}

	return -1;
}

/**
 * Add a ndn face for a name prefix
 *
 */

int 
add_ndn_face(struct ndn *h, const char *uri, const char *address, const unsigned int p)
{
	return add_delete_ndn_face(h, uri, address, p, OP_REG);
}


/**
 * Delete a ndn face for a name prefix
 *
 */

int 
delete_ndn_face(struct ndn *h, const char *uri, const char *address, const unsigned int p)
{
	return add_delete_ndn_face(h, uri, address, p, OP_UNREG);
}
