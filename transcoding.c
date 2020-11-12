/**
 *     Copyright 2016-2019 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include "couchbase.h"

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/transcoding", __FILE__, __LINE__

int pcbc_decode_value(zval *return_value, pcbc_bucket_t *bucket, const char *bytes, int bytes_len, uint32_t flags,
                      uint8_t datatype)
{
    int rv;
    zval params[3];

    ZVAL_UNDEF(&params[0]);
    ZVAL_UNDEF(&params[1]);
    ZVAL_UNDEF(&params[2]);

    PCBC_STRINGL(params[0], bytes, bytes_len);
    ZVAL_LONG(&params[1], flags);
    ZVAL_LONG(&params[2], datatype);

    rv = call_user_function(CG(function_table), NULL, &bucket->decoder, return_value, 3, params);

    zval_ptr_dtor(&params[0]);
    zval_ptr_dtor(&params[1]);
    zval_ptr_dtor(&params[2]);
    return rv;
}

int pcbc_encode_value(pcbc_bucket_t *bucket, zval *value, void **bytes, lcb_size_t *nbytes, lcb_uint32_t *flags,
                      uint8_t *datatype)
{
    zval retval;
    int rv;

    ZVAL_UNDEF(&retval);
    ZVAL_NULL(&retval);

    rv = call_user_function(CG(function_table), NULL, &bucket->encoder, &retval, 1, value);
    if (rv != SUCCESS || Z_TYPE_P(&retval) != IS_ARRAY || zend_hash_num_elements(Z_ARRVAL(retval)) != 3) {
        zval_ptr_dtor(&retval);
        return FAILURE;
    }

    {
        zval *zbytes, *zflags, *zdatatype;

        zbytes = zend_hash_index_find(Z_ARRVAL(retval), 0);
        zflags = zend_hash_index_find(Z_ARRVAL(retval), 1);
        zdatatype = zend_hash_index_find(Z_ARRVAL(retval), 2);

        if (!zbytes || Z_TYPE_P(zbytes) != IS_STRING) {
            zval_ptr_dtor(&retval);
            return FAILURE;
        }

        if (!zflags || Z_TYPE_P(zflags) != IS_LONG) {
            zval_ptr_dtor(&retval);
            return FAILURE;
        }

        if (!zdatatype || Z_TYPE_P(zdatatype) != IS_LONG) {
            zval_ptr_dtor(&retval);
            return FAILURE;
        }

        *nbytes = Z_STRLEN_P(zbytes);
        *bytes = estrndup(Z_STRVAL_P(zbytes), *nbytes);
        *flags = (uint32_t)Z_LVAL_P(zflags);
        *datatype = (uint8_t)Z_LVAL_P(zdatatype);
    }

    zval_ptr_dtor(&retval);
    return SUCCESS;
}
