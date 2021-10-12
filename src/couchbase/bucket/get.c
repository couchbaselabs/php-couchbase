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
#include "subdoc_cookie.h"

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/get", __FILE__, __LINE__

extern zend_class_entry *pcbc_get_result_impl_ce;

struct get_cookie {
    lcb_STATUS rc;
    zval *return_value;
};

void get_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPGET *resp)
{
    struct get_cookie *cookie = NULL;
    const lcb_KEY_VALUE_ERROR_CONTEXT *ectx = NULL;
    lcb_respget_cookie(resp, (void **)&cookie);
    zval *return_value = cookie->return_value;
    cookie->rc = lcb_respget_status(resp);
    pcbc_update_property_long(pcbc_get_result_impl_ce, return_value, ("status"), cookie->rc);
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
            pcbc_update_property_str(pcbc_get_result_impl_ce, return_value, ("cas"), b64);
            zend_string_release(b64);
        }
    }
}

void subdoc_get_with_expiry_callback(lcb_INSTANCE *instance, struct subdoc_cookie *cookie, const lcb_RESPSUBDOC *resp)
{
    const lcb_KEY_VALUE_ERROR_CONTEXT *ectx = NULL;
    lcb_respsubdoc_cookie(resp, (void **)&cookie);
    zval *return_value = cookie->return_value;
    cookie->rc = lcb_respsubdoc_status(resp);
    pcbc_update_property_long(pcbc_get_result_impl_ce, return_value, ("status"), cookie->rc);
    lcb_respsubdoc_error_context(resp, &ectx);

    set_property_str(ectx, lcb_errctx_kv_context, pcbc_get_result_impl_ce, "err_ctx");
    set_property_str(ectx, lcb_errctx_kv_ref, pcbc_get_result_impl_ce, "err_ref");
    set_property_str(ectx, lcb_errctx_kv_key, pcbc_get_result_impl_ce, "key");
    if (cookie->rc == LCB_SUCCESS) {
        if (lcb_respsubdoc_result_size(resp) == 4) {
            const char *buf;
            size_t buf_len;
            lcb_respsubdoc_result_value(resp, 0, &buf, &buf_len);
            pcbc_update_property_long(pcbc_get_result_impl_ce, return_value, "expiry", zend_atol(buf, buf_len));
            lcb_respsubdoc_result_value(resp, 1, &buf, &buf_len);
            pcbc_update_property_long(pcbc_get_result_impl_ce, return_value, "flags", zend_atol(buf, buf_len));
            lcb_respsubdoc_result_value(resp, 2, &buf, &buf_len);
            pcbc_update_property_long(pcbc_get_result_impl_ce, return_value, "datatype", zend_atol(buf, buf_len));
            lcb_respsubdoc_result_value(resp, 3, &buf, &buf_len);
            pcbc_update_property_stringl(pcbc_get_result_impl_ce, return_value, "data", buf, buf_len);
        }
        {
            uint64_t data;
            lcb_respsubdoc_cas(resp, &data);
            zend_string *b64;
            b64 = php_base64_encode((unsigned char *)&data, sizeof(data));
            pcbc_update_property_str(pcbc_get_result_impl_ce, return_value, ("cas"), b64);
            zend_string_release(b64);
        }
    }
}

zend_class_entry *pcbc_get_options_ce;

PHP_METHOD(GetOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_long(pcbc_get_options_ce, getThis(), ("timeout"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(GetOptions, withExpiry)
{
    zend_bool arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "b", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_bool(pcbc_get_options_ce, getThis(), ("with_expiry"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(GetOptions, project)
{
    zval *arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "a", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property(pcbc_get_options_ce, getThis(), ("project"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(GetOptions, decoder)
{
    zval *arg;
    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "z", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property(pcbc_get_options_ce, getThis(), ("decoder"), arg);
    zval_ptr_dtor(arg);
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

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetOptions_decoder, 0, 1, Couchbase\\GetOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_get_options_methods[] = {
    PHP_ME(GetOptions, timeout, ai_GetOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(GetOptions, withExpiry, ai_GetOptions_withExpiry, ZEND_ACC_PUBLIC)
    PHP_ME(GetOptions, project, ai_GetOptions_project, ZEND_ACC_PUBLIC)
    PHP_ME(GetOptions, decoder, ai_GetOptions_decoder, ZEND_ACC_PUBLIC)
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

    zval decoder = {0};
    ZVAL_NULL(&decoder);
    zend_bool with_expiry = 0;
    zend_long timeout = 0;
    if (options) {
        zval *prop, ret;
        prop = pcbc_read_property(pcbc_get_options_ce, options, ("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            timeout = Z_LVAL_P(prop);
        }
        prop = pcbc_read_property(pcbc_get_options_ce, options, ("with_expiry"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_TRUE) {
            with_expiry = 1;
        }
        prop = pcbc_read_property(pcbc_get_options_ce, options, ("decoder"), 0, &ret);
        if (Z_TYPE_P(prop) != IS_NULL) {
            ZVAL_COPY(&decoder, prop);
        }
    }

    object_init_ex(return_value, pcbc_get_result_impl_ce);
    pcbc_update_property(pcbc_get_result_impl_ce, return_value, ("decoder"),
                         Z_TYPE(decoder) == IS_NULL ? &bucket->decoder : &decoder);

    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_GET, 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }

    if (with_expiry) {
        struct subdoc_cookie cookie = {LCB_SUCCESS, return_value, 1, 1};
        const char *expiry_path = "$document.exptime";
        const char *flags_path = "$document.flags";
        const char *datatype_path = "$document.datatype";
        lcb_SUBDOCSPECS *specs;
        lcb_subdocspecs_create(&specs, 4);
        lcb_subdocspecs_get(specs, 0, LCB_SUBDOCSPECS_F_XATTRPATH, expiry_path, strlen(expiry_path));
        lcb_subdocspecs_get(specs, 1, LCB_SUBDOCSPECS_F_XATTRPATH, flags_path, strlen(flags_path));
        lcb_subdocspecs_get(specs, 2, LCB_SUBDOCSPECS_F_XATTRPATH, datatype_path, strlen(datatype_path));
        lcb_subdocspecs_get(specs, 3, 0, NULL, 0);
        lcb_CMDSUBDOC *cmd;
        lcb_cmdsubdoc_create(&cmd);
        lcb_cmdsubdoc_collection(cmd, scope_str, scope_len, collection_str, collection_len);
        lcb_cmdsubdoc_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
        lcb_cmdsubdoc_specs(cmd, specs);
        if (timeout > 0) {
            lcb_cmdsubdoc_timeout(cmd, timeout);
        }
        if (span) {
            lcb_cmdsubdoc_parent_span(cmd, span);
        }
        err = lcb_subdoc(bucket->conn->lcb, &cookie, cmd);
        lcb_cmdsubdoc_destroy(cmd);
        lcb_subdocspecs_destroy(specs);
        if (err == LCB_SUCCESS) {
            lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
            err = cookie.rc;
        }
    } else {
        struct get_cookie cookie = {LCB_SUCCESS, return_value};
        lcb_CMDGET *cmd;
        lcb_cmdget_create(&cmd);
        lcb_cmdget_collection(cmd, scope_str, scope_len, collection_str, collection_len);
        lcb_cmdget_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
        if (timeout > 0) {
            lcb_cmdget_timeout(cmd, timeout);
        }
        if (span) {
            lcb_cmdget_parent_span(cmd, span);
        }
        err = lcb_get(bucket->conn->lcb, &cookie, cmd);
        lcb_cmdget_destroy(cmd);
        if (err == LCB_SUCCESS) {
            lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
            err = cookie.rc;
        }
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
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_long(pcbc_get_and_lock_options_ce, getThis(), ("timeout"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(GetAndLockOptions, decoder)
{
    zval *arg;
    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "z", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property(pcbc_get_and_lock_options_ce, getThis(), ("decoder"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetAndLockOptions_timeout, 0, 1, Couchbase\\GetAndLockOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetAndLockOptions_decoder, 0, 1, Couchbase\\GetAndLockOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_get_and_lock_options_methods[] = {
    PHP_ME(GetAndLockOptions, timeout, ai_GetAndLockOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(GetAndLockOptions, decoder, ai_GetAndLockOptions_decoder, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Collection, getAndLock)
{
    zend_string *id;
    zval *options = NULL;
    zend_long expiry;
    lcb_STATUS err;

    int rv =
        zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sl|O!", &id, &expiry, &options, pcbc_get_and_lock_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_CMDGET *cmd;
    lcb_cmdget_create(&cmd);
    lcb_cmdget_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    lcb_cmdget_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    lcb_cmdget_locktime(cmd, expiry);

    zval decoder = {0};
    ZVAL_NULL(&decoder);
    if (options) {
        zval *prop, ret;
        prop = pcbc_read_property(pcbc_get_and_lock_options_ce, options, ("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdget_timeout(cmd, Z_LVAL_P(prop));
        }
        prop = pcbc_read_property(pcbc_get_and_lock_options_ce, options, ("decoder"), 0, &ret);
        if (Z_TYPE_P(prop) != IS_NULL) {
            ZVAL_COPY(&decoder, prop);
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
    pcbc_update_property(pcbc_get_result_impl_ce, return_value, ("decoder"),
                         Z_TYPE(decoder) == IS_NULL ? &bucket->decoder : &decoder);
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
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_long(pcbc_get_and_touch_options_ce, getThis(), ("timeout"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(GetAndTouchOptions, decoder)
{
    zval *arg;
    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "z", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property(pcbc_get_and_touch_options_ce, getThis(), ("decoder"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetAndTouchOptions_timeout, 0, 1, Couchbase\\GetAndTouchOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetAndTouchOptions_decoder, 0, 1, Couchbase\\GetAndTouchOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_get_and_touch_options_methods[] = {
    PHP_ME(GetAndTouchOptions, timeout, ai_GetAndTouchOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(GetAndTouchOptions, decoder, ai_GetAndTouchOptions_decoder, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Collection, getAndTouch)
{
    zend_string *id;
    zval *options = NULL;
    zend_long expiry;
    lcb_STATUS err;

    int rv =
        zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sl|O!", &id, &expiry, &options, pcbc_get_and_touch_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_CMDGET *cmd;
    lcb_cmdget_create(&cmd);
    lcb_cmdget_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    lcb_cmdget_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    lcb_cmdget_expiry(cmd, expiry);

    zval decoder = {0};
    ZVAL_NULL(&decoder);
    if (options) {
        zval *prop, ret;
        prop = pcbc_read_property(pcbc_get_and_touch_options_ce, options, ("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdget_timeout(cmd, Z_LVAL_P(prop));
        }
        prop = pcbc_read_property(pcbc_get_and_touch_options_ce, options, ("decoder"), 0, &ret);
        if (Z_TYPE_P(prop) != IS_NULL) {
            ZVAL_COPY(&decoder, prop);
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
    pcbc_update_property(pcbc_get_result_impl_ce, return_value, ("decoder"),
                         Z_TYPE(decoder) == IS_NULL ? &bucket->decoder : &decoder);
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
    pcbc_get_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_get_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_options_ce, ZEND_STRL("with_expiry"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_options_ce, ZEND_STRL("project"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_options_ce, ZEND_STRL("decoder"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GetAndTouchOptions", pcbc_get_and_touch_options_methods);
    pcbc_get_and_touch_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_get_and_touch_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_and_touch_options_ce, ZEND_STRL("decoder"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GetAndLockOptions", pcbc_get_and_lock_options_methods);
    pcbc_get_and_lock_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_get_and_lock_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_and_lock_options_ce, ZEND_STRL("decoder"), ZEND_ACC_PRIVATE);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
