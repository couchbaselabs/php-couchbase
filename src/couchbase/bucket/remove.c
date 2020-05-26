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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/remove", __FILE__, __LINE__

extern zend_class_entry *pcbc_mutation_result_impl_ce;
extern zend_class_entry *pcbc_mutation_token_impl_ce;

struct remove_cookie {
    lcb_STATUS rc;
    zval *return_value;
};

void remove_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPREMOVE *resp)
{
    TSRMLS_FETCH();

    const lcb_KEY_VALUE_ERROR_CONTEXT *ectx = NULL;
    struct remove_cookie *cookie = NULL;
    lcb_respremove_cookie(resp, (void **)&cookie);
    zval *return_value = cookie->return_value;
    cookie->rc = lcb_respremove_status(resp);
    zend_update_property_long(pcbc_mutation_result_impl_ce, return_value, ZEND_STRL("status"), cookie->rc TSRMLS_CC);

    lcb_respremove_error_context(resp, &ectx);
    set_property_str(ectx, lcb_errctx_kv_context, pcbc_mutation_result_impl_ce, "err_ctx");
    set_property_str(ectx, lcb_errctx_kv_ref, pcbc_mutation_result_impl_ce, "err_ref");
    set_property_str(ectx, lcb_errctx_kv_key, pcbc_mutation_result_impl_ce, "key");

    if (cookie->rc == LCB_SUCCESS) {
        zend_string *b64;
        {
            uint64_t data;
            lcb_respremove_cas(resp, &data);
            b64 = php_base64_encode((unsigned char *)&data, sizeof(data));
            zend_update_property_str(pcbc_mutation_result_impl_ce, return_value, ZEND_STRL("cas"), b64 TSRMLS_CC);
            zend_string_release(b64);
        }
        {
            lcb_MUTATION_TOKEN token = {0};
            lcb_respremove_mutation_token(resp, &token);
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

                zend_update_property(pcbc_mutation_result_impl_ce, return_value, ZEND_STRL("mutation_token"),
                                     &val TSRMLS_CC);
                zval_ptr_dtor(&val);
            }
        }
    }
}

zend_class_entry *pcbc_remove_options_ce;

PHP_METHOD(RemoveOptions, cas)
{
    zend_string *arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "S", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_string *decoded = php_base64_decode_str(arg);
    if (decoded) {
        if (ZSTR_LEN(decoded) == sizeof(uint64_t)) {
            zend_update_property_str(pcbc_remove_options_ce, getThis(), ZEND_STRL("cas"), arg TSRMLS_CC);
        }
        zend_string_free(decoded);
    }
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(RemoveOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_remove_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(RemoveOptions, durabilityLevel)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_remove_options_ce, getThis(), ZEND_STRL("durability_level"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_RemoveOptions_cas, 0, 1, \\Couchbase\\RemoveOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_RemoveOptions_timeout, 0, 1, \\Couchbase\\RemoveOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_RemoveOptions_durabilityLevel, 0, 1, \\Couchbase\\RemoveOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_remove_options_methods[] = {
    PHP_ME(RemoveOptions, cas, ai_RemoveOptions_cas, ZEND_ACC_PUBLIC)
    PHP_ME(RemoveOptions, timeout, ai_RemoveOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(RemoveOptions, durabilityLevel, ai_RemoveOptions_durabilityLevel, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Collection, remove)
{
    zend_string *id;
    zval *options = NULL;
    lcb_STATUS err;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S|O!", &id, &options, pcbc_remove_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_CMDREMOVE *cmd;
    lcb_cmdremove_create(&cmd);
    lcb_cmdremove_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    lcb_cmdremove_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    uint64_t cas = 0;
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_remove_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdremove_timeout(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_remove_options_ce, options, ZEND_STRL("durability_level"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdremove_durability(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_remove_options_ce, options, ZEND_STRL("cas"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            zend_string *decoded = php_base64_decode_str(Z_STR_P(prop));
            if (decoded) {
                memcpy(&cas, ZSTR_VAL(decoded), ZSTR_LEN(decoded));
                lcb_cmdremove_cas(cmd, cas);
                zend_string_free(decoded);
            }
        }
    }

    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_REMOVE, 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdremove_parent_span(cmd, span);
    }
    object_init_ex(return_value, pcbc_mutation_result_impl_ce);
    struct remove_cookie cookie = {LCB_SUCCESS, return_value};
    err = lcb_remove(bucket->conn->lcb, &cookie, cmd);
    lcb_cmdremove_destroy(cmd);
    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }
    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }

    if (err != LCB_SUCCESS) {
        throw_lcb_exception_ex(err, cas == 0 ? PCBC_OPCODE_UNSPEC : PCBC_OPCODE_DELETE, pcbc_mutation_result_impl_ce);
    }
}

PHP_MINIT_FUNCTION(CollectionRemove)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "RemoveOptions", pcbc_remove_options_methods);
    pcbc_remove_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_remove_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_remove_options_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_remove_options_ce, ZEND_STRL("durability_level"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
