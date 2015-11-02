#include <libcouchbase/couchbase.h>
#include <php.h>

int le_cas;

static void cas_dtor(zend_resource *rsrc TSRMLS_DC)
{
    lcb_cas_t *cas_data = (lcb_cas_t*)rsrc->ptr;
    if (cas_data) {
        efree(cas_data);
    }
}

void couchbase_init_cas(INIT_FUNC_ARGS) {
	le_cas = zend_register_list_destructors_ex(cas_dtor, NULL, "CouchbaseCAS", module_number);
}

lcb_cas_t cas_retrieve(zval * zcas TSRMLS_DC) {
	lcb_cas_t *cas = (lcb_cas_t *)zend_fetch_resource2_ex(zcas, "CouchbaseCAS", le_cas, -1);

	if (cas) {
		return *cas;
	} else {
		return 0;
	}
}

void cas_create(zval * zcas, lcb_cas_t value TSRMLS_DC) {
	void *cas_data = emalloc(sizeof(lcb_cas_t));
	*((lcb_cas_t*)cas_data) = value;
	ZVAL_RES(zcas, zend_register_resource(cas_data, le_cas));
}
