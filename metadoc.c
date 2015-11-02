#include "bucket.h"
#include "cas.h"
#include "transcoding.h"

zend_class_entry *metadoc_ce;

zend_function_entry metadoc_methods[] = {
		{ NULL, NULL, NULL }
};

void couchbase_init_metadoc(INIT_FUNC_ARGS) {
	zend_class_entry ce;

	INIT_CLASS_ENTRY(ce, "CouchbaseMetaDoc", metadoc_methods);
	metadoc_ce = zend_register_internal_class(&ce TSRMLS_CC);

	zend_declare_property_null(metadoc_ce, "error", strlen("error"), ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_null(metadoc_ce, "value", strlen("value"), ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_null(metadoc_ce, "flags", strlen("flags"), ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_null(metadoc_ce, "cas", strlen("cas"), ZEND_ACC_PUBLIC TSRMLS_CC);
}


int metadoc_from_error(zval *doc, zval *zerror TSRMLS_DC) {
	object_init_ex(doc, metadoc_ce);
	zend_update_property(metadoc_ce, doc, "error", sizeof("error") - 1, zerror TSRMLS_CC);
	return SUCCESS;
}

int metadoc_create(zval *doc, zval *value, lcb_cas_t cas,
	lcb_uint32_t flags, lcb_uint8_t datatype TSRMLS_DC) {
	zval zcas, zflags;

	object_init_ex(doc, metadoc_ce);

	if (value) {
		zend_update_property(metadoc_ce, doc, "value", sizeof("value") - 1, value TSRMLS_CC);
	}

	ZVAL_LONG(&zflags, flags);
	zend_update_property(metadoc_ce, doc, "flags", sizeof("flags") - 1, &zflags TSRMLS_CC);
	zval_ptr_dtor(&zflags);

	cas_create(&zcas, cas TSRMLS_CC);
	zend_update_property(metadoc_ce, doc, "cas", sizeof("cas") - 1, &zcas TSRMLS_CC);
	zval_ptr_dtor(&zcas);

	return SUCCESS;
}

int metadoc_from_long(zval *doc, lcb_U64 value,
	lcb_cas_t cas, lcb_uint32_t flags, lcb_uint8_t datatype TSRMLS_DC) {
	zval zvalue;
	ZVAL_LONG(&zvalue, (long)value);

	return metadoc_create(doc, &zvalue, cas, flags, datatype TSRMLS_CC);
}

int metadoc_from_bytes(bucket_object *obj, zval *doc, const void *bytes,
	lcb_size_t nbytes, lcb_cas_t cas, lcb_uint32_t flags,
	lcb_uint8_t datatype TSRMLS_DC) {
	int retval;
    zval zvalue;
	pcbc_bytes_to_zval(obj, &zvalue, bytes, nbytes, flags, datatype TSRMLS_CC);

	retval = metadoc_create(doc, &zvalue, cas, flags, datatype TSRMLS_CC);

	return retval;
}
