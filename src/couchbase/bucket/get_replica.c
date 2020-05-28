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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/get_replica", __FILE__, __LINE__

extern zend_class_entry *pcbc_get_replica_result_impl_ce;

struct get_replica_cookie {
    int is_single;
    lcb_STATUS rc;
    zval *return_value;
};

void getreplica_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPGETREPLICA *resp)
{
    TSRMLS_FETCH();

    const lcb_KEY_VALUE_ERROR_CONTEXT *ectx = NULL;
    struct get_replica_cookie *cookie = NULL;
    lcb_respgetreplica_cookie(resp, (void **)&cookie);
    zval *return_value = NULL, value;
    if (cookie->is_single) {
        return_value = cookie->return_value;
    } else {
        return_value = &value;
        object_init_ex(return_value, pcbc_get_replica_result_impl_ce);
        add_next_index_zval(cookie->return_value, return_value);
    }

    cookie->rc = lcb_respgetreplica_status(resp);
    zend_update_property_long(pcbc_get_replica_result_impl_ce, return_value, ZEND_STRL("status"), cookie->rc TSRMLS_CC);
    lcb_respgetreplica_error_context(resp, &ectx);

    set_property_str(ectx, lcb_errctx_kv_context, pcbc_get_replica_result_impl_ce, "err_ctx");
    set_property_str(ectx, lcb_errctx_kv_ref, pcbc_get_replica_result_impl_ce, "err_ref");
    set_property_str(ectx, lcb_errctx_kv_key, pcbc_get_replica_result_impl_ce, "key");
    /* TODO: shall libcouchbase query master for replica? */
    zend_update_property_bool(pcbc_get_replica_result_impl_ce, return_value, ZEND_STRL("is_replica"), 1 TSRMLS_CC);
    if (cookie->rc == LCB_SUCCESS) {
        set_property_num(uint32_t, lcb_respgetreplica_flags, pcbc_get_replica_result_impl_ce, "flags");
        set_property_num(uint8_t, lcb_respgetreplica_datatype, pcbc_get_replica_result_impl_ce, "datatype");
        set_property_str(resp, lcb_respgetreplica_value, pcbc_get_replica_result_impl_ce, "data");
        {
            uint64_t data;
            lcb_respgetreplica_cas(resp, &data);
            zend_string *b64;
            b64 = php_base64_encode((unsigned char *)&data, sizeof(data));
            zend_update_property_str(pcbc_get_replica_result_impl_ce, return_value, ZEND_STRL("cas"), b64 TSRMLS_CC);
            zend_string_release(b64);
        }
    }
}

zend_class_entry *pcbc_get_any_replica_options_ce;

PHP_METHOD(GetAnyReplicaOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_get_any_replica_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetAnyReplicaOptions_timeout, 0, 1, Couchbase\\GetAnyReplicaOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_get_any_replica_options_methods[] = {
    PHP_ME(GetAnyReplicaOptions, timeout, ai_GetAnyReplicaOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Collection, getAnyReplica)
{
    zend_string *id;
    zval *options = NULL;
    lcb_STATUS err;

    int rv =
        zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S|O!", &id, &options, pcbc_get_any_replica_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_CMDGETREPLICA *cmd;
    lcb_cmdgetreplica_create(&cmd, LCB_REPLICA_MODE_ANY);
    lcb_cmdgetreplica_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    lcb_cmdgetreplica_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_get_any_replica_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdgetreplica_timeout(cmd, Z_LVAL_P(prop));
        }
    }

    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_GET_FROM_REPLICA, 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdgetreplica_parent_span(cmd, span);
    }
    object_init_ex(return_value, pcbc_get_replica_result_impl_ce);
    struct get_replica_cookie cookie = {1, LCB_SUCCESS, return_value};
    err = lcb_getreplica(bucket->conn->lcb, &cookie, cmd);
    lcb_cmdgetreplica_destroy(cmd);
    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }
    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, pcbc_get_replica_result_impl_ce);
    }
}

zend_class_entry *pcbc_get_all_replicas_options_ce;

PHP_METHOD(GetAllReplicasOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_get_all_replicas_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetAllReplicasOptions_timeout, 0, 1, Couchbase\\GetAllReplicasOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_get_all_replicas_options_methods[] = {
    PHP_ME(GetAllReplicasOptions, timeout, ai_GetAllReplicasOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Collection, getAllReplicas)
{
    zend_string *id;
    zval *options = NULL;
    lcb_STATUS err;

    int rv =
        zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S|O!", &id, &options, pcbc_get_all_replicas_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_CMDGETREPLICA *cmd;
    lcb_cmdgetreplica_create(&cmd, LCB_REPLICA_MODE_ALL);
    lcb_cmdgetreplica_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    lcb_cmdgetreplica_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_get_all_replicas_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdgetreplica_timeout(cmd, Z_LVAL_P(prop));
        }
    }

    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_GET_FROM_REPLICA, 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdgetreplica_parent_span(cmd, span);
    }
    array_init(return_value);
    struct get_replica_cookie cookie = {0, LCB_SUCCESS, return_value};
    err = lcb_getreplica(bucket->conn->lcb, &cookie, cmd);
    lcb_cmdgetreplica_destroy(cmd);
    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }
    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, NULL);
    }
}

PHP_MINIT_FUNCTION(CollectionGetReplica)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GetAllReplicasOptions", pcbc_get_all_replicas_options_methods);
    pcbc_get_all_replicas_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_get_all_replicas_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GetAnyReplicaOptions", pcbc_get_any_replica_options_methods);
    pcbc_get_any_replica_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_get_any_replica_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
