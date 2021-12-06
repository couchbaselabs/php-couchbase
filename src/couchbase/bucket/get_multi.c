/**
 *     Copyright 2021 Couchbase, Inc.
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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/get_multi", __FILE__, __LINE__

extern zend_class_entry *pcbc_get_result_impl_ce;
extern zend_class_entry *pcbc_get_options_ce;

struct get_multi_cookie {
    lcb_STATUS rc;
    zval *return_value;
    size_t index;
};

void get_multi_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPGET *resp)
{
    struct get_multi_cookie *cookie = NULL;
    const lcb_KEY_VALUE_ERROR_CONTEXT *ectx = NULL;
    lcb_respget_cookie(resp, (void **)&cookie);
    zval *return_value = zend_hash_index_find(HASH_OF(cookie->return_value), cookie->index);
    if (return_value == NULL) {
        cookie->rc = LCB_ERR_INVALID_RANGE;
        return;
    }
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
    (void)instance;
    (void)cbtype;
}

PHP_METHOD(Collection, getMulti)
{
    zval *ids = NULL;
    zval *options = NULL;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "A|O!", &ids, &options, pcbc_get_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    zval decoder = {0};
    ZVAL_NULL(&decoder);
    zend_long timeout = 0;
    if (options) {
        zval ret;
        const zval *prop;
        prop = pcbc_read_property(pcbc_get_options_ce, options, ("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            timeout = Z_LVAL_P(prop);
        }
        prop = pcbc_read_property(pcbc_get_options_ce, options, ("decoder"), 0, &ret);
        if (Z_TYPE_P(prop) != IS_NULL) {
            ZVAL_COPY(&decoder, prop);
        }
    }

    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_GET "_multi", 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }

    size_t num_of_ids = zend_hash_num_elements(Z_ARRVAL_P(ids));
    struct get_multi_cookie *cookies = calloc(num_of_ids, sizeof(struct get_multi_cookie));
    array_init_size(return_value, num_of_ids);
    lcb_sched_enter(bucket->conn->lcb);
    const zval *id;
    lcb_STATUS err = LCB_SUCCESS;
    size_t index = 0;
    ZEND_HASH_FOREACH_VAL(HASH_OF(ids), id)
    {
        if (Z_TYPE_P(id) != IS_STRING) {
            err = LCB_ERR_INVALID_ARGUMENT;
            lcb_sched_fail(bucket->conn->lcb);
            break;
        }
        zval result;
        object_init_ex(&result, pcbc_get_result_impl_ce);
        add_next_index_zval(return_value, &result);
        cookies[index].rc = LCB_SUCCESS;
        cookies[index].return_value = return_value;
        cookies[index].index = index;
        pcbc_update_property(pcbc_get_result_impl_ce, &result, ("decoder"),
                             Z_TYPE(decoder) == IS_NULL ? &bucket->decoder : &decoder);

        lcb_CMDGET *cmd;
        lcb_cmdget_create(&cmd);
        lcb_cmdget_collection(cmd, scope_str, scope_len, collection_str, collection_len);
        lcb_cmdget_key(cmd, Z_STRVAL_P(id), Z_STRLEN_P(id));
        if (timeout > 0) {
            lcb_cmdget_timeout(cmd, timeout);
        }
        if (span) {
            lcb_cmdget_parent_span(cmd, span);
        }
        err = lcb_get(bucket->conn->lcb, &cookies[index], cmd);
        lcb_cmdget_destroy(cmd);
        if (err != LCB_SUCCESS) {
            lcb_sched_fail(bucket->conn->lcb);
            break;
        }
        ++index;
    }
    ZEND_HASH_FOREACH_END();
    lcb_sched_leave(bucket->conn->lcb);

    if (err == LCB_SUCCESS) {
        lcb_RESPCALLBACK prev_cb =
            lcb_install_callback(bucket->conn->lcb, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)get_multi_callback);
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        lcb_install_callback(bucket->conn->lcb, LCB_CALLBACK_GET, prev_cb);
    }
    free(cookies);

    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, NULL);
    }
}

PHP_MINIT_FUNCTION(CollectionGetMulti)
{
    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */