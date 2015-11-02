#ifndef CAS_H_
#define CAS_H_

#include <php.h>
#include <libcouchbase/couchbase.h>

void couchbase_init_cas(INIT_FUNC_ARGS);
lcb_cas_t cas_retrieve(zval * zcas TSRMLS_DC);
void cas_create(zval * zcas, lcb_cas_t value TSRMLS_DC);

#endif // CAS_H_
