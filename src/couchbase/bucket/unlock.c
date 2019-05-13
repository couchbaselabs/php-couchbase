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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/unlock", __FILE__, __LINE__

extern zend_class_entry *pcbc_result_impl_ce;

struct unlock_cookie {
    lcb_STATUS rc;
    zval *return_value;
};

void unlock_callback(lcb_INSTANCE *  instance, int cbtype, const lcb_RESPUNLOCK *resp)
{
    TSRMLS_FETCH();

    struct unlock_cookie *cookie = NULL;
    lcb_respunlock_cookie(resp, (void **)&cookie);
    zval *return_value = cookie->return_value;
    cookie->rc = lcb_respunlock_status(resp);
    zend_update_property_long(pcbc_result_impl_ce, return_value, ZEND_STRL("status"), cookie->rc TSRMLS_CC);

    set_property_str(lcb_respunlock_error_context, pcbc_result_impl_ce, "err_ctx");
    set_property_str(lcb_respunlock_error_ref, pcbc_result_impl_ce, "err_ref");
    set_property_str(lcb_respunlock_key, pcbc_result_impl_ce, "key");

    if (cookie->rc == LCB_SUCCESS) {
        zend_string *b64;
        {
            uint64_t data;
            lcb_respunlock_cas(resp, &data);
            b64 = php_base64_encode((unsigned char *)&data, sizeof(data));
            zend_update_property_str(pcbc_result_impl_ce, return_value, ZEND_STRL("cas"), b64 TSRMLS_CC);
        }
    }
}

zend_class_entry *pcbc_unlock_options_ce;

PHP_METHOD(UnlockOptions, timeout)
{
    zend_long *arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_unlock_options_ce, getThis(), ZEND_STRL("timeout"), *arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_UnlockOptions_timeout, 0, 1, \\Couchbase\\UnlockOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry pcbc_unlock_options_methods[] = {
    PHP_ME(UnlockOptions, timeout, ai_UnlockOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_FE_END
};


PHP_METHOD(Collection, unlock)
{
    lcb_STATUS err;

    zend_string *id, *cas;
    zval *options;

    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "SS|O", &id, &cas, &options, pcbc_unlock_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_CMDUNLOCK *cmd;
    lcb_cmdunlock_create(&cmd);
    lcb_cmdunlock_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    lcb_cmdunlock_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    zend_string *decoded = php_base64_decode(ZSTR_VAL(cas), ZSTR_LEN(cas));
    if (decoded) {
        uint64_t cas_val = 0;
        memcpy(&cas_val, ZSTR_VAL(decoded), ZSTR_LEN(decoded));
        lcb_cmdunlock_cas(cmd, cas_val);
        zend_string_free(decoded);
    }
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_unlock_options_ce, getThis(), ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdunlock_timeout(cmd, Z_LVAL_P(prop));
        }
    }

    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_UNLOCK, 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdunlock_parent_span(cmd, span);
    }

    object_init_ex(return_value, pcbc_result_impl_ce);
    struct unlock_cookie cookie = {
        LCB_SUCCESS,
        return_value
    };
    err = lcb_unlock(bucket->conn->lcb, &cookie, cmd);
    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb);
        err = cookie.rc;
    }

    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }

    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, pcbc_result_impl_ce);
    }
}

PHP_MINIT_FUNCTION(CollectionUnlock)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "UnlockOptions", pcbc_unlock_options_methods);
    pcbc_unlock_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_unlock_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
