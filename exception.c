#include "couchbase.h"
#include <libcouchbase/couchbase.h>
#include "phphelpers.h"

zend_class_entry *default_exception_ce;
zend_class_entry *cb_exception_ce;

void make_exception(zval *ex, zend_class_entry *exception_ce, const char *message, long code TSRMLS_DC) {
	zend_class_entry *default_exception_ce = zend_exception_get_default(TSRMLS_C);

	object_init_ex(ex, exception_ce);

	if (message) {
		zend_update_property_string(default_exception_ce, ex, "message", sizeof("message")-1, message TSRMLS_CC);
	}
	if (code) {
		zend_update_property_long(default_exception_ce, ex, "code", sizeof("code")-1, code TSRMLS_CC);
	}
}

void make_pcbc_exception(zval *ex, const char *message, long code TSRMLS_DC) {
	make_exception(ex, cb_exception_ce, message, code TSRMLS_CC);
}

void make_lcb_exception(zval *ex, long code TSRMLS_DC) {
	const char *str = lcb_strerror(NULL, (lcb_error_t)code);
	return make_exception(ex, cb_exception_ce, str, code TSRMLS_CC);
}

#define setup(var, name, parent) \
	do { \
		zend_class_entry cbe; \
		INIT_CLASS_ENTRY(cbe, name, NULL); \
		var = phlp_zend_register_internal_class_ex(&cbe, parent); \
	} while(0)

void couchbase_init_exceptions(INIT_FUNC_ARGS) {
    default_exception_ce = (zend_class_entry *)phlp_zend_exception_get_default();

	setup(cb_exception_ce, "CouchbaseException", default_exception_ce);
}
