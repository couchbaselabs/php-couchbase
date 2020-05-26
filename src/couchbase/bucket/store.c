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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/store", __FILE__, __LINE__

zend_class_entry *pcbc_durability_level_ce;
static const zend_function_entry pcbc_durability_level_methods[] = {PHP_FE_END};

extern zend_class_entry *pcbc_store_result_impl_ce;
extern zend_class_entry *pcbc_mutation_token_impl_ce;

struct store_cookie {
    lcb_STATUS rc;
    zval *return_value;
};

void store_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPSTORE *resp)
{
    TSRMLS_FETCH();

    const lcb_KEY_VALUE_ERROR_CONTEXT *ectx = NULL;
    struct store_cookie *cookie = NULL;
    lcb_respstore_cookie(resp, (void **)&cookie);
    zval *return_value = cookie->return_value;
    cookie->rc = lcb_respstore_status(resp);
    zend_update_property_long(pcbc_store_result_impl_ce, return_value, ZEND_STRL("status"), cookie->rc TSRMLS_CC);

    lcb_respstore_error_context(resp, &ectx);
    set_property_str(ectx, lcb_errctx_kv_context, pcbc_store_result_impl_ce, "err_ctx");
    set_property_str(ectx, lcb_errctx_kv_ref, pcbc_store_result_impl_ce, "err_ref");
    set_property_str(ectx, lcb_errctx_kv_key, pcbc_store_result_impl_ce, "key");

    if (cookie->rc == LCB_SUCCESS) {
        zend_string *b64;
        {
            uint64_t data;
            lcb_respstore_cas(resp, &data);
            b64 = php_base64_encode((unsigned char *)&data, sizeof(data));
            zend_update_property_str(pcbc_store_result_impl_ce, return_value, ZEND_STRL("cas"), b64 TSRMLS_CC);
            zend_string_release(b64);
        }
        {
            lcb_MUTATION_TOKEN token = {0};
            lcb_respstore_mutation_token(resp, &token);
            if (lcb_mutation_token_is_valid(&token)) {
                zval val;
                object_init_ex(&val, pcbc_mutation_token_impl_ce);

                zend_update_property_long(pcbc_mutation_token_impl_ce, &val, ZEND_STRL("partition_id"),
                                          token.vbid_ TSRMLS_CC);
                b64 = php_base64_encode((unsigned char *)&token.uuid_, sizeof(token.uuid_));
                zend_update_property_str(pcbc_mutation_token_impl_ce, &val, ZEND_STRL("partition_uuid"), b64 TSRMLS_CC);
                zend_string_release(b64);
                b64 = php_base64_encode((unsigned char *)&token.seqno_, sizeof(token.seqno_));
                zend_update_property_str(pcbc_mutation_token_impl_ce, &val, ZEND_STRL("sequence_number"),
                                         b64 TSRMLS_CC);
                zend_string_release(b64);

                const char *bucket;
                lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_BUCKETNAME, &bucket);
                zend_update_property_string(pcbc_mutation_token_impl_ce, &val, ZEND_STRL("bucket_name"),
                                            bucket TSRMLS_CC);

                zend_update_property(pcbc_store_result_impl_ce, return_value, ZEND_STRL("mutation_token"),
                                     &val TSRMLS_CC);
                zval_ptr_dtor(&val);
            }
        }
    }
    if (lcb_respstore_observe_attached(resp)) {
        int store_ok;
        lcb_respstore_observe_stored(resp, &store_ok);
        zend_update_property_bool(pcbc_store_result_impl_ce, return_value, ZEND_STRL("is_stored"), store_ok TSRMLS_CC);
        if (store_ok) {
            set_property_num(uint16_t, lcb_respstore_observe_num_persisted, pcbc_store_result_impl_ce, "num_persisted");
            set_property_num(uint16_t, lcb_respstore_observe_num_replicated, pcbc_store_result_impl_ce,
                             "num_replicated");
        }
    }
}

zend_class_entry *pcbc_insert_options_ce;

PHP_METHOD(InsertOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_insert_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(InsertOptions, expiry)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_insert_options_ce, getThis(), ZEND_STRL("expiry"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(InsertOptions, durabilityLevel)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_insert_options_ce, getThis(), ZEND_STRL("durability_level"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_InsertOptions_timeout, 0, 1, \\Couchbase\\InsertOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_InsertOptions_expiry, 0, 1, \\Couchbase\\InsertOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_InsertOptions_durabilityLevel, 0, 1, \\Couchbase\\InsertOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_insert_options_methods[] = {
    PHP_ME(InsertOptions, timeout, ai_InsertOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(InsertOptions, expiry, ai_InsertOptions_expiry, ZEND_ACC_PUBLIC)
    PHP_ME(InsertOptions, durabilityLevel, ai_InsertOptions_durabilityLevel, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Collection, insert)
{
    zend_string *id;
    zval *value, *options = NULL;
    lcb_STATUS err = LCB_ERR_INVALID_ARGUMENT;

    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Sz|O!", &id, &value, &options, pcbc_insert_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_CMDSTORE *cmd;
    lcb_cmdstore_create(&cmd, LCB_STORE_INSERT);
    lcb_cmdstore_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_insert_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdstore_timeout(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_insert_options_ce, options, ZEND_STRL("expiry"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdstore_expiry(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_insert_options_ce, options, ZEND_STRL("durability_level"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdstore_durability(cmd, Z_LVAL_P(prop));
        }
    }

    lcbtrace_SPAN *parent_span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        parent_span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_INSERT, 0, NULL);
        lcbtrace_span_add_tag_str(parent_span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(parent_span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdstore_parent_span(cmd, parent_span);
    }
    lcbtrace_SPAN *span = NULL;
    if (parent_span) {
        lcbtrace_REF ref;
        ref.type = LCBTRACE_REF_CHILD_OF;
        ref.span = parent_span;
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_REQUEST_ENCODING, LCBTRACE_NOW, &ref);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }
    void *bytes = NULL;
    size_t nbytes;
    uint32_t flags;
    uint8_t datatype;
    rv = pcbc_encode_value(bucket, value, &bytes, &nbytes, &flags, &datatype TSRMLS_CC);
    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (rv != SUCCESS) {
        pcbc_log(LOGARGS(bucket->conn->lcb, ERROR), "Failed to encode value for before storing");
        lcb_cmdstore_destroy(cmd);
        throw_lcb_exception(err, NULL);
        RETURN_NULL();
    }

    lcb_cmdstore_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    lcb_cmdstore_value(cmd, bytes, nbytes);
    lcb_cmdstore_flags(cmd, flags);
    lcb_cmdstore_datatype(cmd, datatype);

    object_init_ex(return_value, pcbc_store_result_impl_ce);
    struct store_cookie cookie = {LCB_SUCCESS, return_value};
    err = lcb_store(bucket->conn->lcb, &cookie, cmd);
    efree(bytes);
    lcb_cmdstore_destroy(cmd);
    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }
    if (parent_span) {
        lcbtrace_span_finish(parent_span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, pcbc_store_result_impl_ce);
    }
}

zend_class_entry *pcbc_upsert_options_ce;

PHP_METHOD(UpsertOptions, cas)
{
    zend_string *arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "S", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_string *decoded = php_base64_decode_str(arg);
    if (decoded) {
        if (ZSTR_LEN(decoded) == sizeof(uint64_t)) {
            zend_update_property_str(pcbc_upsert_options_ce, getThis(), ZEND_STRL("cas"), arg TSRMLS_CC);
        }
        zend_string_free(decoded);
    }
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(UpsertOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_upsert_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(UpsertOptions, expiry)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_upsert_options_ce, getThis(), ZEND_STRL("expiry"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(UpsertOptions, durabilityLevel)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_upsert_options_ce, getThis(), ZEND_STRL("durability_level"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_UpsertOptions_cas, 0, 1, \\Couchbase\\UpsertOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_UpsertOptions_timeout, 0, 1, \\Couchbase\\UpsertOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_UpsertOptions_expiry, 0, 1, \\Couchbase\\UpsertOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_UpsertOptions_durabilityLevel, 0, 1, \\Couchbase\\UpsertOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_upsert_options_methods[] = {
    PHP_ME(UpsertOptions, cas, ai_UpsertOptions_cas, ZEND_ACC_PUBLIC)
    PHP_ME(UpsertOptions, timeout, ai_UpsertOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(UpsertOptions, expiry, ai_UpsertOptions_expiry, ZEND_ACC_PUBLIC)
    PHP_ME(UpsertOptions, durabilityLevel, ai_UpsertOptions_durabilityLevel, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Collection, upsert)
{
    zend_string *id;
    zval *value, *options = NULL;
    lcb_STATUS err = LCB_ERR_INVALID_ARGUMENT;

    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Sz|O!", &id, &value, &options, pcbc_upsert_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_CMDSTORE *cmd;
    lcb_cmdstore_create(&cmd, LCB_STORE_UPSERT);
    lcb_cmdstore_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_upsert_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdstore_timeout(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_upsert_options_ce, options, ZEND_STRL("expiry"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdstore_expiry(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_upsert_options_ce, options, ZEND_STRL("durability_level"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdstore_durability(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_upsert_options_ce, options, ZEND_STRL("cas"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            zend_string *decoded = php_base64_decode_str(Z_STR_P(prop));
            if (decoded) {
                uint64_t cas = 0;
                memcpy(&cas, ZSTR_VAL(decoded), ZSTR_LEN(decoded));
                lcb_cmdstore_cas(cmd, cas);
                zend_string_free(decoded);
            }
        }
    }

    lcbtrace_SPAN *parent_span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        parent_span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_UPSERT, 0, NULL);
        lcbtrace_span_add_tag_str(parent_span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(parent_span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdstore_parent_span(cmd, parent_span);
    }
    lcbtrace_SPAN *span = NULL;
    if (parent_span) {
        lcbtrace_REF ref;
        ref.type = LCBTRACE_REF_CHILD_OF;
        ref.span = parent_span;
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_REQUEST_ENCODING, LCBTRACE_NOW, &ref);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }
    void *bytes = NULL;
    size_t nbytes;
    uint32_t flags;
    uint8_t datatype;

    rv = pcbc_encode_value(bucket, value, &bytes, &nbytes, &flags, &datatype TSRMLS_CC);
    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (rv != SUCCESS) {
        pcbc_log(LOGARGS(bucket->conn->lcb, ERROR), "Failed to encode value for before storing");
        lcb_cmdstore_destroy(cmd);
        throw_lcb_exception(err, NULL);
        RETURN_NULL();
    }

    lcb_cmdstore_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    lcb_cmdstore_value(cmd, bytes, nbytes);
    lcb_cmdstore_flags(cmd, flags);
    lcb_cmdstore_datatype(cmd, datatype);

    object_init_ex(return_value, pcbc_store_result_impl_ce);
    struct store_cookie cookie = {LCB_SUCCESS, return_value};
    err = lcb_store(bucket->conn->lcb, &cookie, cmd);
    efree(bytes);
    lcb_cmdstore_destroy(cmd);
    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }
    if (parent_span) {
        lcbtrace_span_finish(parent_span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, pcbc_store_result_impl_ce);
    }
}

zend_class_entry *pcbc_replace_options_ce;

PHP_METHOD(ReplaceOptions, cas)
{
    zend_string *arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "S", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_string *decoded = php_base64_decode_str(arg);
    if (decoded) {
        if (ZSTR_LEN(decoded) == sizeof(uint64_t)) {
            zend_update_property_str(pcbc_replace_options_ce, getThis(), ZEND_STRL("cas"), arg TSRMLS_CC);
        }
        zend_string_free(decoded);
    }
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ReplaceOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_replace_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ReplaceOptions, expiry)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_replace_options_ce, getThis(), ZEND_STRL("expiry"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ReplaceOptions, durabilityLevel)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_replace_options_ce, getThis(), ZEND_STRL("durability_level"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ReplaceOptions_cas, 0, 1, \\Couchbase\\ReplaceOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ReplaceOptions_timeout, 0, 1, \\Couchbase\\ReplaceOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ReplaceOptions_expiry, 0, 1, \\Couchbase\\ReplaceOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ReplaceOptions_durabilityLevel, 0, 1, \\Couchbase\\ReplaceOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_replace_options_methods[] = {
    PHP_ME(ReplaceOptions, cas, ai_ReplaceOptions_cas, ZEND_ACC_PUBLIC)
    PHP_ME(ReplaceOptions, timeout, ai_ReplaceOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(ReplaceOptions, expiry, ai_ReplaceOptions_expiry, ZEND_ACC_PUBLIC)
    PHP_ME(ReplaceOptions, durabilityLevel, ai_ReplaceOptions_durabilityLevel, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Collection, replace)
{
    zend_string *id;
    zval *value, *options = NULL;
    lcb_STATUS err = LCB_ERR_INVALID_ARGUMENT;

    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Sz|O!", &id, &value, &options, pcbc_replace_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_CMDSTORE *cmd;
    lcb_cmdstore_create(&cmd, LCB_STORE_REPLACE);
    lcb_cmdstore_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_replace_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdstore_timeout(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_replace_options_ce, options, ZEND_STRL("expiry"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdstore_expiry(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_replace_options_ce, options, ZEND_STRL("durability_level"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdstore_durability(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_replace_options_ce, options, ZEND_STRL("cas"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            zend_string *decoded = php_base64_decode_str(Z_STR_P(prop));
            if (decoded) {
                uint64_t cas = 0;
                memcpy(&cas, ZSTR_VAL(decoded), ZSTR_LEN(decoded));
                lcb_cmdstore_cas(cmd, cas);
                zend_string_free(decoded);
            }
        }
    }

    lcbtrace_SPAN *parent_span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        parent_span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_REPLACE, 0, NULL);
        lcbtrace_span_add_tag_str(parent_span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(parent_span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdstore_parent_span(cmd, parent_span);
    }
    lcbtrace_SPAN *span = NULL;
    if (parent_span) {
        lcbtrace_REF ref;
        ref.type = LCBTRACE_REF_CHILD_OF;
        ref.span = parent_span;
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_REQUEST_ENCODING, LCBTRACE_NOW, &ref);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }
    void *bytes = NULL;
    size_t nbytes;
    uint32_t flags;
    uint8_t datatype;
    rv = pcbc_encode_value(bucket, value, &bytes, &nbytes, &flags, &datatype TSRMLS_CC);
    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (rv != SUCCESS) {
        pcbc_log(LOGARGS(bucket->conn->lcb, ERROR), "Failed to encode value for before storing");
        lcb_cmdstore_destroy(cmd);
        throw_lcb_exception(err, NULL);
        RETURN_NULL();
    }

    lcb_cmdstore_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    lcb_cmdstore_value(cmd, bytes, nbytes);
    lcb_cmdstore_flags(cmd, flags);
    lcb_cmdstore_datatype(cmd, datatype);

    object_init_ex(return_value, pcbc_store_result_impl_ce);
    struct store_cookie cookie = {LCB_SUCCESS, return_value};
    err = lcb_store(bucket->conn->lcb, &cookie, cmd);
    efree(bytes);
    lcb_cmdstore_destroy(cmd);
    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }
    if (parent_span) {
        lcbtrace_span_finish(parent_span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception_ex(err, PCBC_OPCODE_REPLACE, pcbc_store_result_impl_ce);
    }
}

zend_class_entry *pcbc_append_options_ce;

PHP_METHOD(AppendOptions, cas)
{
    zend_string *arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "S", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_string *decoded = php_base64_decode_str(arg);
    if (decoded) {
        if (ZSTR_LEN(decoded) == sizeof(uint64_t)) {
            zend_update_property_str(pcbc_append_options_ce, getThis(), ZEND_STRL("cas"), arg TSRMLS_CC);
        }
        zend_string_free(decoded);
    }
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AppendOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_append_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AppendOptions, durabilityLevel)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_append_options_ce, getThis(), ZEND_STRL("durability_level"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AppendOptions_cas, 0, 1, \\Couchbase\\AppendOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AppendOptions_timeout, 0, 1, \\Couchbase\\AppendOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AppendOptions_durabilityLevel, 0, 1, \\Couchbase\\AppendOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_append_options_methods[] = {
    PHP_ME(AppendOptions, cas, ai_AppendOptions_cas, ZEND_ACC_PUBLIC)
    PHP_ME(AppendOptions, timeout, ai_AppendOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(AppendOptions, durabilityLevel, ai_AppendOptions_durabilityLevel, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(BinaryCollection, append)
{
    zend_string *id, *value;
    zval *options = NULL;
    lcb_STATUS err;

    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "SS|O!", &id, &value, &options, pcbc_append_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_BINARY_COLLECTION;

    lcb_CMDSTORE *cmd;
    lcb_cmdstore_create(&cmd, LCB_STORE_APPEND);
    lcb_cmdstore_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_append_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdstore_timeout(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_append_options_ce, options, ZEND_STRL("durability_level"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdstore_durability(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_append_options_ce, options, ZEND_STRL("cas"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            zend_string *decoded = php_base64_decode_str(Z_STR_P(prop));
            if (decoded) {
                uint64_t cas = 0;
                memcpy(&cas, ZSTR_VAL(decoded), ZSTR_LEN(decoded));
                lcb_cmdstore_cas(cmd, cas);
                zend_string_free(decoded);
            }
        }
    }

    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_APPEND, 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdstore_parent_span(cmd, span);
    }

    lcb_cmdstore_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    lcb_cmdstore_value(cmd, ZSTR_VAL(value), ZSTR_LEN(value));

    object_init_ex(return_value, pcbc_store_result_impl_ce);
    struct store_cookie cookie = {LCB_SUCCESS, return_value};
    err = lcb_store(bucket->conn->lcb, &cookie, cmd);
    lcb_cmdstore_destroy(cmd);
    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }
    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, pcbc_store_result_impl_ce);
    }
}

zend_class_entry *pcbc_prepend_options_ce;

PHP_METHOD(PrependOptions, cas)
{
    zend_string *arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "S", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_string *decoded = php_base64_decode_str(arg);
    if (decoded) {
        if (ZSTR_LEN(decoded) == sizeof(uint64_t)) {
            zend_update_property_str(pcbc_prepend_options_ce, getThis(), ZEND_STRL("cas"), arg TSRMLS_CC);
        }
        zend_string_free(decoded);
    }
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(PrependOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_prepend_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(PrependOptions, durabilityLevel)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_prepend_options_ce, getThis(), ZEND_STRL("durability_level"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_PrependOptions_cas, 0, 1, \\Couchbase\\PrependOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_PrependOptions_timeout, 0, 1, \\Couchbase\\PrependOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_PrependOptions_durabilityLevel, 0, 1, \\Couchbase\\PrependOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_prepend_options_methods[] = {
    PHP_ME(PrependOptions, cas, ai_PrependOptions_cas, ZEND_ACC_PUBLIC)
    PHP_ME(PrependOptions, timeout, ai_PrependOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(PrependOptions, durabilityLevel, ai_PrependOptions_durabilityLevel, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(BinaryCollection, prepend)
{
    zend_string *id, *value;
    zval *options = NULL;
    lcb_STATUS err;

    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "SS|O!", &id, &value, &options, pcbc_prepend_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_BINARY_COLLECTION;

    lcb_CMDSTORE *cmd;
    lcb_cmdstore_create(&cmd, LCB_STORE_PREPEND);
    lcb_cmdstore_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_append_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdstore_timeout(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_append_options_ce, options, ZEND_STRL("durability_level"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdstore_durability(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_append_options_ce, options, ZEND_STRL("cas"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            zend_string *decoded = php_base64_decode_str(Z_STR_P(prop));
            if (decoded) {
                uint64_t cas = 0;
                memcpy(&cas, ZSTR_VAL(decoded), ZSTR_LEN(decoded));
                lcb_cmdstore_cas(cmd, cas);
                zend_string_free(decoded);
            }
        }
    }

    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_PREPEND, 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdstore_parent_span(cmd, span);
    }

    lcb_cmdstore_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    lcb_cmdstore_value(cmd, ZSTR_VAL(value), ZSTR_LEN(value));

    object_init_ex(return_value, pcbc_store_result_impl_ce);
    struct store_cookie cookie = {LCB_SUCCESS, return_value};
    err = lcb_store(bucket->conn->lcb, &cookie, cmd);
    lcb_cmdstore_destroy(cmd);
    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }
    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, pcbc_store_result_impl_ce);
    }
}

PHP_MINIT_FUNCTION(CollectionStore)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "InsertOptions", pcbc_insert_options_methods);
    pcbc_insert_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_insert_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_insert_options_ce, ZEND_STRL("expiry"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_insert_options_ce, ZEND_STRL("durability_level"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "UpsertOptions", pcbc_upsert_options_methods);
    pcbc_upsert_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_upsert_options_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_upsert_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_upsert_options_ce, ZEND_STRL("expiry"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_upsert_options_ce, ZEND_STRL("durability_level"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ReplaceOptions", pcbc_replace_options_methods);
    pcbc_replace_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_replace_options_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_replace_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_replace_options_ce, ZEND_STRL("expiry"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_replace_options_ce, ZEND_STRL("durability_level"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "AppendOptions", pcbc_append_options_methods);
    pcbc_append_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_append_options_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_append_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_append_options_ce, ZEND_STRL("durability_level"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "PrependOptions", pcbc_prepend_options_methods);
    pcbc_prepend_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_prepend_options_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_prepend_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_prepend_options_ce, ZEND_STRL("durability_level"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DurabilityLevel", pcbc_durability_level_methods);
    pcbc_durability_level_ce = zend_register_internal_interface(&ce TSRMLS_CC);
    zend_declare_class_constant_long(pcbc_durability_level_ce, ZEND_STRL("NONE"), LCB_DURABILITYLEVEL_NONE TSRMLS_CC);
    zend_declare_class_constant_long(pcbc_durability_level_ce, ZEND_STRL("MAJORITY"),
                                     LCB_DURABILITYLEVEL_MAJORITY TSRMLS_CC);
    zend_declare_class_constant_long(pcbc_durability_level_ce, ZEND_STRL("MAJORITY_AND_PERSIST_TO_ACTIVE"),
                                     LCB_DURABILITYLEVEL_MAJORITY_AND_PERSIST_TO_ACTIVE TSRMLS_CC);
    zend_declare_class_constant_long(pcbc_durability_level_ce, ZEND_STRL("PERSIST_TO_MAJORITY"),
                                     LCB_DURABILITYLEVEL_PERSIST_TO_MAJORITY TSRMLS_CC);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
