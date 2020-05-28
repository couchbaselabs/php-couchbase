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
#include <Zend/zend_alloc.h>

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/mutation_state", __FILE__, __LINE__

extern zend_class_entry *pcbc_mutation_result_ce;
extern zend_class_entry *pcbc_mutation_token_legacy_ce;
zend_class_entry *pcbc_mutation_state_ce;

PHP_METHOD(MutationState, add)
{
    zval *source;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "O", &source, pcbc_mutation_result_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zval fname;
    zval retval;
    PCBC_STRING(fname, "mutationToken");
    rv = call_user_function_ex(EG(function_table), source, &fname, &retval, 0, NULL, 1, NULL TSRMLS_CC);
    if (rv == FAILURE || EG(exception) || Z_ISUNDEF(retval)) {
        RETURN_NULL();
    }

    zval *tokens, rv1;
    tokens = zend_read_property(pcbc_mutation_state_ce, getThis(), ZEND_STRL("tokens"), 0, &rv1);
    if (Z_TYPE_P(tokens) == IS_NULL) {
        array_init(&rv1);
        tokens = &rv1;
        zend_update_property(pcbc_mutation_state_ce, getThis(), ZEND_STRL("tokens"), tokens TSRMLS_CC);
        Z_DELREF_P(tokens);
    }
    add_next_index_zval(tokens, &retval);
    Z_TRY_ADDREF(retval);
    RETURN_ZVAL(getThis(), 1, 0);
}

void pcbc_mutation_state_export_for_n1ql(zval *mutation_state, zval *scan_vectors TSRMLS_DC)
{
    array_init(scan_vectors);

    zval *tokens, rv1;
    zval fname;
    tokens = zend_read_property(pcbc_mutation_state_ce, mutation_state, ZEND_STRL("tokens"), 0, &rv1);
    if (Z_TYPE_P(tokens) == IS_ARRAY) {
        HashTable *ht = HASH_OF(tokens);
        zval *token;
        ZEND_HASH_FOREACH_VAL(ht, token)
        {
            zval bucket;
            PCBC_STRING(fname, "bucketName");
            call_user_function_ex(EG(function_table), token, &fname, &bucket, 0, NULL, 1, NULL TSRMLS_CC);

            zval new_group;
            zval *bucket_group = zend_symtable_str_find(Z_ARRVAL_P(scan_vectors), Z_STRVAL(bucket), Z_STRLEN(bucket));
            if (!bucket_group) {
                array_init(&new_group);
                add_assoc_zval_ex(scan_vectors, Z_STRVAL(bucket), Z_STRLEN(bucket), &new_group);
                bucket_group = &new_group;
            }

            zval pair;
            array_init_size(&pair, 2);

            zend_string *decoded;

            zval seqno;
            PCBC_STRING(fname, "sequenceNumber");
            call_user_function_ex(EG(function_table), token, &fname, &seqno, 0, NULL, 1, NULL TSRMLS_CC);
            decoded = php_base64_decode_str(Z_STR(seqno));
            if (decoded) {
                if (ZSTR_LEN(decoded) == sizeof(uint64_t)) {
                    uint64_t num = 0;
                    memcpy(&num, ZSTR_VAL(decoded), ZSTR_LEN(decoded));
                    add_next_index_long(&pair, num);
                }
                zend_string_free(decoded);
            }

            char buf[22] = {0};

            zval vb_uuid;
            PCBC_STRING(fname, "partitionUuid");
            call_user_function_ex(EG(function_table), token, &fname, &vb_uuid, 0, NULL, 1, NULL TSRMLS_CC);
            decoded = php_base64_decode_str(Z_STR(vb_uuid));
            if (decoded) {
                if (ZSTR_LEN(decoded) == sizeof(uint64_t)) {
                    uint64_t num = 0;
                    memcpy(&num, ZSTR_VAL(decoded), ZSTR_LEN(decoded));
                    snprintf(buf, 21, "%llu", (unsigned long long)num);
                    add_next_index_string(&pair, buf);
                }
                zend_string_free(decoded);
            }

            zval vb_id;
            PCBC_STRING(fname, "partitionId");
            call_user_function_ex(EG(function_table), token, &fname, &vb_id, 0, NULL, 1, NULL TSRMLS_CC);

            snprintf(buf, 21, "%d", (int)Z_LVAL(vb_id));
            zend_hash_str_update(Z_ARRVAL_P(bucket_group), buf, strlen(buf), &pair TSRMLS_CC);
        }
        ZEND_HASH_FOREACH_END();
    }
}

void pcbc_mutation_state_export_for_search(zval *mutation_state, zval *scan_vectors TSRMLS_DC)
{
    array_init(scan_vectors);

    zval *tokens, rv1;
    zval fname;
    tokens = zend_read_property(pcbc_mutation_state_ce, mutation_state, ZEND_STRL("tokens"), 0, &rv1);
    if (Z_TYPE_P(tokens) == IS_ARRAY) {
        HashTable *ht = HASH_OF(tokens);
        zval *token;
        ZEND_HASH_FOREACH_VAL(ht, token)
        {
            zend_string *decoded;

            char token_key[50] = {0};

            zval vb_id;
            PCBC_STRING(fname, "partitionId");
            call_user_function_ex(EG(function_table), token, &fname, &vb_id, 0, NULL, 1, NULL TSRMLS_CC);

            zval vb_uuid;
            PCBC_STRING(fname, "partitionUuid");
            call_user_function_ex(EG(function_table), token, &fname, &vb_uuid, 0, NULL, 1, NULL TSRMLS_CC);
            decoded = php_base64_decode_str(Z_STR(vb_uuid));
            if (decoded) {
                if (ZSTR_LEN(decoded) == sizeof(uint64_t)) {
                    uint64_t num = 0;
                    memcpy(&num, ZSTR_VAL(decoded), ZSTR_LEN(decoded));
                    snprintf(token_key, 49, "%d/%llu", (int)Z_LVAL(vb_id), (unsigned long long)num);
                }
                zend_string_free(decoded);
            }

            zval seqno;
            PCBC_STRING(fname, "sequenceNumber");
            call_user_function_ex(EG(function_table), token, &fname, &seqno, 0, NULL, 1, NULL TSRMLS_CC);
            decoded = php_base64_decode_str(Z_STR(seqno));
            if (decoded) {
                if (ZSTR_LEN(decoded) == sizeof(uint64_t)) {
                    uint64_t num = 0;
                    memcpy(&num, ZSTR_VAL(decoded), ZSTR_LEN(decoded));
                    add_assoc_long_ex(scan_vectors, token_key, strlen(token_key), (zend_long)num);
                }
                zend_string_free(decoded);
            }
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_METHOD(MutationState, __construct) {}

ZEND_BEGIN_ARG_INFO_EX(ai_MutationState_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_MutationState_add, Couchbase\\MutationState, 0)
ZEND_ARG_OBJ_INFO(0, source, Couchbase\\MutationResult, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry mutation_state_methods[] = {
    PHP_ME(MutationState, __construct, ai_MutationState_none, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(MutationState, add, ai_MutationState_add, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(MutationState)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutationState", mutation_state_methods);
    pcbc_mutation_state_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_mutation_state_ce, ZEND_STRL("tokens"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
