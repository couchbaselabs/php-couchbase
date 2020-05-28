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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/exists", __FILE__, __LINE__

extern zend_class_entry *pcbc_exists_result_impl_ce;

struct exists_cookie {
    lcb_STATUS rc;
    zval *return_value;
};

void exists_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPEXISTS *resp)
{
    TSRMLS_FETCH();

    const lcb_KEY_VALUE_ERROR_CONTEXT *ectx = NULL;
    struct exists_cookie *cookie = NULL;
    lcb_respexists_cookie(resp, (void **)&cookie);
    zval *return_value = cookie->return_value;
    cookie->rc = lcb_respexists_status(resp);
    zend_update_property_long(pcbc_exists_result_impl_ce, return_value, ZEND_STRL("status"), cookie->rc TSRMLS_CC);
    lcb_respexists_error_context(resp, &ectx);

    set_property_str(ectx, lcb_errctx_kv_context, pcbc_exists_result_impl_ce, "err_ctx");
    set_property_str(ectx, lcb_errctx_kv_ref, pcbc_exists_result_impl_ce, "err_ref");
    set_property_str(ectx, lcb_errctx_kv_key, pcbc_exists_result_impl_ce, "key");
    zend_update_property_bool(pcbc_exists_result_impl_ce, return_value, ZEND_STRL("is_found"),
                              lcb_respexists_is_found(resp) TSRMLS_CC);
    if (cookie->rc == LCB_SUCCESS) {
        uint64_t data;
        lcb_respexists_cas(resp, &data);
        zend_string *b64;
        b64 = php_base64_encode((unsigned char *)&data, sizeof(data));
        zend_update_property_str(pcbc_exists_result_impl_ce, return_value, ZEND_STRL("cas"), b64 TSRMLS_CC);
        zend_string_release(b64);
    }
}

zend_class_entry *pcbc_exists_options_ce;

PHP_METHOD(ExistsOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_exists_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ExistsOptions_timeout, 0, 1, Couchbase\\ExistsOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_exists_options_methods[] = {
    PHP_ME(ExistsOptions, timeout, ai_ExistsOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Collection, exists)
{
    zend_string *id;
    zval *options = NULL;
    lcb_STATUS err;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S|O!", &id, &options, pcbc_exists_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_CMDEXISTS *cmd;
    lcb_cmdexists_create(&cmd);
    lcb_cmdexists_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    lcb_cmdexists_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_exists_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdexists_timeout(cmd, Z_LVAL_P(prop));
        }
    }

    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_EXISTS, 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdexists_parent_span(cmd, span);
    }

    object_init_ex(return_value, pcbc_exists_result_impl_ce);
    struct exists_cookie cookie = {LCB_SUCCESS, return_value};
    err = lcb_exists(bucket->conn->lcb, &cookie, cmd);
    lcb_cmdexists_destroy(cmd);

    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        if (span) {
            lcbtrace_span_finish(span, LCBTRACE_NOW);
        }
        err = cookie.rc;
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, pcbc_exists_result_impl_ce);
    }
}

PHP_MINIT_FUNCTION(CollectionExists)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ExistsOptions", pcbc_exists_options_methods);
    pcbc_exists_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_exists_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
