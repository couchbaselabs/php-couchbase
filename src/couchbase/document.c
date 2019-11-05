/**
 *     Copyright 2016-2017 Couchbase, Inc.
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

zend_class_entry *pcbc_document_ce;

// clang-format off
zend_function_entry document_methods[] = {
    PHP_FE_END
};
// clang-format on

void pcbc_document_init_error(zval *return_value, opcookie_res *header TSRMLS_DC)
{
    PCBC_ZVAL exc;
    PCBC_ZVAL_ALLOC(exc);

    object_init_ex(return_value, pcbc_document_ce);
    pcbc_exception_init_lcb(PCBC_P(exc), header->err, NULL, header->err_ctx, header->err_ref TSRMLS_CC);
    zend_update_property(pcbc_document_ce, return_value, ZEND_STRL("error"), PCBC_P(exc) TSRMLS_CC);

    zval_ptr_dtor(&exc);
}

void pcbc_document_init_decode(zval *return_value, pcbc_bucket_t *bucket, const char *bytes, int bytes_len,
                               lcb_U32 flags, lcb_datatype_t datatype, lcb_cas_t cas,
                               const lcb_MUTATION_TOKEN *token TSRMLS_DC)
{
    object_init_ex(return_value, pcbc_document_ce);

    {
        PCBC_ZVAL val;
        PCBC_ZVAL_ALLOC(val);
        pcbc_decode_value(PCBC_P(val), bucket, bytes, bytes_len, flags, datatype TSRMLS_CC);
        zend_update_property(pcbc_document_ce, return_value, ZEND_STRL("value"), PCBC_P(val) TSRMLS_CC);
        zval_ptr_dtor(&val);
    }
    zend_update_property_long(pcbc_document_ce, return_value, ZEND_STRL("flags"), flags TSRMLS_CC);
    {
        PCBC_ZVAL val;
        PCBC_ZVAL_ALLOC(val);
        pcbc_cas_encode(PCBC_P(val), cas TSRMLS_CC);
        zend_update_property(pcbc_document_ce, return_value, ZEND_STRL("cas"), PCBC_P(val) TSRMLS_CC);
        zval_ptr_dtor(&val);
    }

    if (LCB_MUTATION_TOKEN_ISVALID(token)) {
        PCBC_ZVAL val;
        PCBC_ZVAL_ALLOC(val);
        pcbc_mutation_token_init(PCBC_P(val), bucket->conn->bucketname, token TSRMLS_CC);
        zend_update_property(pcbc_document_ce, return_value, ZEND_STRL("token"), PCBC_P(val) TSRMLS_CC);
        zval_ptr_dtor(&val);
    }
}

void pcbc_document_init_counter(zval *return_value, pcbc_bucket_t *bucket, lcb_U64 value, lcb_cas_t cas,
                                const lcb_MUTATION_TOKEN *token TSRMLS_DC)
{
    object_init_ex(return_value, pcbc_document_ce);

    zend_update_property_long(pcbc_document_ce, return_value, ZEND_STRL("value"), value TSRMLS_CC);
    {
        PCBC_ZVAL val;
        PCBC_ZVAL_ALLOC(val);
        pcbc_cas_encode(PCBC_P(val), cas TSRMLS_CC);
        zend_update_property(pcbc_document_ce, return_value, ZEND_STRL("cas"), PCBC_P(val) TSRMLS_CC);
        zval_ptr_dtor(&val);
    }
    if (LCB_MUTATION_TOKEN_ISVALID(token)) {
        PCBC_ZVAL val;
        PCBC_ZVAL_ALLOC(val);
        pcbc_mutation_token_init(PCBC_P(val), bucket->conn->bucketname, token TSRMLS_CC);
        zend_update_property(pcbc_document_ce, return_value, ZEND_STRL("token"), PCBC_P(val) TSRMLS_CC);
        zval_ptr_dtor(&val);
    }
}

void pcbc_document_init(zval *return_value, pcbc_bucket_t *bucket, const char *bytes, int bytes_len, lcb_U32 flags,
                        lcb_cas_t cas, const lcb_MUTATION_TOKEN *token TSRMLS_DC)
{
    object_init_ex(return_value, pcbc_document_ce);

    if (bytes_len) {
        zend_update_property_stringl(pcbc_document_ce, return_value, ZEND_STRL("value"), bytes, bytes_len TSRMLS_CC);
        efree((void *)bytes);
    }
    zend_update_property_long(pcbc_document_ce, return_value, ZEND_STRL("flags"), flags TSRMLS_CC);
    {
        PCBC_ZVAL val;
        PCBC_ZVAL_ALLOC(val);
        pcbc_cas_encode(PCBC_P(val), cas TSRMLS_CC);
        zend_update_property(pcbc_document_ce, return_value, ZEND_STRL("cas"), PCBC_P(val) TSRMLS_CC);
        zval_ptr_dtor(&val);
    }
    if (LCB_MUTATION_TOKEN_ISVALID(token)) {
        PCBC_ZVAL val;
        PCBC_ZVAL_ALLOC(val);
        pcbc_mutation_token_init(PCBC_P(val), bucket->conn->bucketname, token TSRMLS_CC);
        zend_update_property(pcbc_document_ce, return_value, ZEND_STRL("token"), PCBC_P(val) TSRMLS_CC);
        zval_ptr_dtor(&val);
    }
}

PHP_MINIT_FUNCTION(Document)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "Document", document_methods);
    pcbc_document_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_declare_property_null(pcbc_document_ce, "error", strlen("error"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(pcbc_document_ce, "value", strlen("value"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(pcbc_document_ce, "flags", strlen("flags"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(pcbc_document_ce, "cas", strlen("cas"), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(pcbc_document_ce, "token", strlen("token"), ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_register_class_alias("\\CouchbaseMetaDoc", pcbc_document_ce);
    return SUCCESS;
}
