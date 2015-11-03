#ifndef COUCHBASE_H_
#define COUCHBASE_H_

#include <libcouchbase/couchbase.h>
#include <libcouchbase/api3.h>
#include <libcouchbase/views.h>
#include <libcouchbase/n1ql.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <php.h>
#include <zend_exceptions.h>
#include "php_couchbase.h"

enum pcbc_constants {
	PERSISTTO_ONE = 1,
	PERSISTTO_TWO = 2,
	PERSISTTO_THREE = 4,
	PERSISTTO_MASTER = PERSISTTO_ONE,
	REPLICATETO_ONE = 1 << 4,
	REPLICATETO_TWO = 2 << 4,
	REPLICATETO_THREE = 4 << 4
};

typedef struct pcbc_lcb {
	char *key;
	lcb_t lcb;
	void *next;
} pcbc_lcb;

ZEND_BEGIN_MODULE_GLOBALS(couchbase)
	// Linked list of bucket connections
	pcbc_lcb *first_bconn;
	pcbc_lcb *last_bconn;
ZEND_END_MODULE_GLOBALS(couchbase)
ZEND_EXTERN_MODULE_GLOBALS(couchbase)

#ifdef ZTS
#define PCBCG(v) TSRMG(couchbase_globals_id, zend_couchbase_globals *, v)
#else
#define PCBCG(v) (couchbase_globals.v)
#endif

void couchbase_init_exceptions(INIT_FUNC_ARGS);
void couchbase_init_cluster(INIT_FUNC_ARGS);
void couchbase_init_bucket(INIT_FUNC_ARGS);

void couchbase_shutdown_bucket(SHUTDOWN_FUNC_ARGS);

#endif /* COUCHBASE_H_ */
