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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/get", __FILE__, __LINE__

extern zend_class_entry *pcbc_get_result_impl_ce;

struct get_cookie {
    lcb_STATUS rc;
    zval *return_value;
};

void get_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPGET *resp)
{
    TSRMLS_FETCH();

    struct get_cookie *cookie = NULL;
    const lcb_KEY_VALUE_ERROR_CONTEXT *ectx = NULL;
    lcb_respget_cookie(resp, (void **)&cookie);
    zval *return_value = cookie->return_value;
    cookie->rc = lcb_respget_status(resp);
    zend_update_property_long(pcbc_get_result_impl_ce, return_value, ZEND_STRL("status"), cookie->rc TSRMLS_CC);
    lcb_respget_error_context(resp, &ectx);

    set_property_str(ectx, lcb_errctx_kv_context, pcbc_get_result_impl_ce, "err_ctx");
    set_property_str(ectx, lcb_errctx_kv_ref, pcbc_get_result_impl_ce, "err_ref");
    set_property_str(ectx, lcb_errctx_kv_key, pcbc_get_result_impl_ce, "key");
    if (cookie->rc == LCB_SUCCESS) {
        set_property_num(uint32_t, lcb_respget_flags, pcbc_get_result_impl_ce, "flags");
        set_property_num(uint8_t, lcb_respget_datatype, pcbc_get_result_impl_ce, "datatype");
        set_property_str(resp, lcb_respget_value, pcbc_get_result_impl_ce, "data");
        {
            uint64_t data;
            lcb_respget_cas(resp, &data);
            zend_string *b64;
            b64 = php_base64_encode((unsigned char *)&data, sizeof(data));
            zend_update_property_str(pcbc_get_result_impl_ce, return_value, ZEND_STRL("cas"), b64 TSRMLS_CC);
            zend_string_release(b64);
        }
    }
}

zend_class_entry *pcbc_get_options_ce;

PHP_METHOD(GetOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_get_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(GetOptions, withExpiry)
{
    zend_bool arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_bool(pcbc_get_options_ce, getThis(), ZEND_STRL("with_expiry"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(GetOptions, project)
{
    zval *arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property(pcbc_get_options_ce, getThis(), ZEND_STRL("project"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetOptions_timeout, 0, 1, Couchbase\\GetOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetOptions_withExpiry, 0, 1, Couchbase\\GetOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetOptions_project, 0, 1, Couchbase\\GetOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_get_options_methods[] = {
    PHP_ME(GetOptions, timeout, ai_GetOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(GetOptions, withExpiry, ai_GetOptions_withExpiry, ZEND_ACC_PUBLIC)
    PHP_ME(GetOptions, project, ai_GetOptions_project, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Collection, get)
{
    zend_string *id;
    zval *options = NULL;
    lcb_STATUS err;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S|O!", &id, &options, pcbc_get_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_CMDGET *cmd;
    lcb_cmdget_create(&cmd);
    lcb_cmdget_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    lcb_cmdget_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_get_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdget_timeout(cmd, Z_LVAL_P(prop));
        }
    }

    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_GET, 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdget_parent_span(cmd, span);
    }

    object_init_ex(return_value, pcbc_get_result_impl_ce);
    struct get_cookie cookie = {LCB_SUCCESS, return_value};
    err = lcb_get(bucket->conn->lcb, &cookie, cmd);
    lcb_cmdget_destroy(cmd);

    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }
    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, pcbc_get_result_impl_ce);
    }
}

zend_class_entry *pcbc_get_and_lock_options_ce;

PHP_METHOD(GetAndLockOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_get_and_lock_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetAndLockOptions_timeout, 0, 1, Couchbase\\GetAndLockOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry pcbc_get_and_lock_options_methods[] = {
    PHP_ME(GetAndLockOptions, timeout, ai_GetAndLockOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

PHP_METHOD(Collection, getAndLock)
{
    zend_string *id;
    zval *options = NULL;
    zend_long expiry;
    lcb_STATUS err;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "Sl|O!", &id, &expiry, &options,
                                         pcbc_get_and_lock_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_CMDGET *cmd;
    lcb_cmdget_create(&cmd);
    lcb_cmdget_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    lcb_cmdget_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    lcb_cmdget_locktime(cmd, expiry);

    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_get_and_lock_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdget_timeout(cmd, Z_LVAL_P(prop));
        }
    }

    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_GET, 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdget_parent_span(cmd, span);
    }
    object_init_ex(return_value, pcbc_get_result_impl_ce);
    struct get_cookie cookie = {LCB_SUCCESS, return_value};
    err = lcb_get(bucket->conn->lcb, &cookie, cmd);
    lcb_cmdget_destroy(cmd);
    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }
    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, pcbc_get_result_impl_ce);
    }
}

zend_class_entry *pcbc_get_and_touch_options_ce;

PHP_METHOD(GetAndTouchOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_get_and_touch_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetAndTouchOptions_timeout, 0, 1, Couchbase\\GetAndTouchOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_get_and_touch_options_methods[] = {
    PHP_ME(GetAndTouchOptions, timeout, ai_GetAndTouchOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Collection, getAndTouch)
{
    zend_string *id;
    zval *options = NULL;
    zend_long expiry;
    lcb_STATUS err;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "Sl|O!", &id, &expiry, &options,
                                         pcbc_get_and_touch_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_CMDGET *cmd;
    lcb_cmdget_create(&cmd);
    lcb_cmdget_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    lcb_cmdget_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    lcb_cmdget_expiry(cmd, expiry);

    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_get_and_touch_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdget_timeout(cmd, Z_LVAL_P(prop));
        }
    }

    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_GET, 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdget_parent_span(cmd, span);
    }
    object_init_ex(return_value, pcbc_get_result_impl_ce);
    struct get_cookie cookie = {LCB_SUCCESS, return_value};
    err = lcb_get(bucket->conn->lcb, &cookie, cmd);
    lcb_cmdget_destroy(cmd);
    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }
    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, pcbc_get_result_impl_ce);
    }
}

PHP_MINIT_FUNCTION(CollectionGet)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GetOptions", pcbc_get_options_methods);
    pcbc_get_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_get_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_get_options_ce, ZEND_STRL("with_expiry"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_get_options_ce, ZEND_STRL("project"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GetAndTouchOptions", pcbc_get_and_touch_options_methods);
    pcbc_get_and_touch_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_get_and_touch_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GetAndLockOptions", pcbc_get_and_lock_options_methods);
    pcbc_get_and_lock_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_get_and_lock_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
