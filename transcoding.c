#include "transcoding.h"

int pcbc_bytes_to_zval(bucket_object *obj, zval *zvalue, const void *bytes,
	lcb_size_t nbytes, lcb_uint32_t flags, lcb_uint8_t datatype TSRMLS_DC) {
	zval zparams[3];
	zval *zbytes = &zparams[0];
	zval *zflags = &zparams[1];
	zval *zdatatype = &zparams[2];

	if (nbytes > 0) {
	    ZVAL_STRINGL(zbytes, bytes, nbytes);
	} else {
	    ZVAL_STRINGL(zbytes, "", 0);
	}

	ZVAL_LONG(zflags, flags);

	ZVAL_LONG(zdatatype, datatype);

	if (call_user_function(CG(function_table), NULL, &obj->decoder, zvalue,
		3, zparams TSRMLS_CC) != SUCCESS) {
		return FAILURE;
	}

	return SUCCESS;
}

int pcbc_zval_to_bytes(bucket_object *obj, zval *value,
		const void **bytes, lcb_size_t *nbytes, lcb_uint32_t *flags,
		lcb_uint8_t *datatype TSRMLS_DC) {
	zval zretval, *zpbytes, *zpflags, *zpdatatype;
	HashTable *retval;

	if (call_user_function(CG(function_table), NULL, &obj->encoder, &zretval,
		1, value TSRMLS_CC) != SUCCESS) {
		return FAILURE;
	}

	retval = Z_ARRVAL(zretval);

	if (zend_hash_num_elements(retval) != 3) {
		return FAILURE;
	}

	zpbytes = zend_hash_index_find(retval, 0);
	zpflags = zend_hash_index_find(retval, 1);
	zpdatatype = zend_hash_index_find(retval, 2);

	if (Z_TYPE_P(zpbytes) != IS_STRING) {
		return FAILURE;
	}
	if (Z_TYPE_P(zpflags) != IS_LONG) {
		return FAILURE;
	}
	if (Z_TYPE_P(zpdatatype) != IS_LONG) {
		return FAILURE;
	}

	*nbytes = Z_STRLEN_P(zpbytes);
	*bytes = estrndup(Z_STRVAL_P(zpbytes), *nbytes);
	*flags = Z_LVAL_P(zpflags);
	*datatype = (lcb_uint8_t)Z_LVAL_P(zpdatatype);

	zval_dtor(&zretval);

	return SUCCESS;
}
