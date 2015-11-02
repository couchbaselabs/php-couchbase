#ifndef TRANSCODING_H_
#define TRANSCODING_H_

#include <php.h>
#include <libcouchbase/couchbase.h>
#include "bucket.h"

int pcbc_bytes_to_zval(bucket_object *obj, zval *zvalue, const void *bytes,
	lcb_size_t nbytes, lcb_uint32_t flags, lcb_uint8_t datatype TSRMLS_DC);

int pcbc_zval_to_bytes(bucket_object *obj, zval *value,
	const void **bytes, lcb_size_t *nbytes, lcb_uint32_t *flags,
	lcb_uint8_t *datatype TSRMLS_DC);

#endif // TRANSCODING_H_
