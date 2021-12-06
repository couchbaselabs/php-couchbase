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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/remove_multi", __FILE__, __LINE__

extern zend_class_entry *pcbc_mutation_result_impl_ce;
extern zend_class_entry *pcbc_mutation_token_impl_ce;
extern zend_class_entry *pcbc_remove_options_ce;

struct remove_multi_cookie {
    lcb_STATUS rc;
    zval *return_value;
    size_t index;
};

void remove_multi_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPREMOVE *resp)
{
    const lcb_KEY_VALUE_ERROR_CONTEXT *ectx = NULL;
    struct remove_multi_cookie *cookie = NULL;
    lcb_respremove_cookie(resp, (void **)&cookie);
    zval *return_value = zend_hash_index_find(HASH_OF(cookie->return_value), cookie->index);
    cookie->rc = lcb_respremove_status(resp);
    pcbc_update_property_long(pcbc_mutation_result_impl_ce, return_value, ("status"), cookie->rc);

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
            pcbc_update_property_str(pcbc_mutation_result_impl_ce, return_value, ("cas"), b64);
            zend_string_release(b64);
        }
        {
            lcb_MUTATION_TOKEN token = {0};
            lcb_respremove_mutation_token(resp, &token);
            if (lcb_mutation_token_is_valid(&token)) {
                zval val;
                object_init_ex(&val, pcbc_mutation_token_impl_ce);

                pcbc_update_property_long(pcbc_mutation_token_impl_ce, &val, ("partition_id"), token.vbid_);
                b64 = php_base64_encode((unsigned char *)&token.uuid_, sizeof(token.uuid_));
                pcbc_update_property_str(pcbc_mutation_token_impl_ce, &val, ("partition_uuid"), b64);
                zend_string_release(b64);
                b64 = php_base64_encode((unsigned char *)&token.seqno_, sizeof(token.seqno_));
                pcbc_update_property_str(pcbc_mutation_token_impl_ce, &val, ("sequence_number"), b64);
                zend_string_release(b64);

                char *bucket;
                lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_BUCKETNAME, &bucket);
                pcbc_update_property_string(pcbc_mutation_token_impl_ce, &val, ("bucket_name"), bucket);

                pcbc_update_property(pcbc_mutation_result_impl_ce, return_value, ("mutation_token"), &val);
                zval_ptr_dtor(&val);
            }
        }
    }
    (void)cbtype;
}

PHP_METHOD(Collection, removeMulti)
{
    zval *ids;
    zval *options = NULL;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "A|O!", &ids, &options, pcbc_remove_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    zend_long timeout = 0;
    lcb_DURABILITY_LEVEL level = LCB_DURABILITYLEVEL_NONE;
    if (options) {
        zval *prop, ret;
        prop = pcbc_read_property(pcbc_remove_options_ce, options, ("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            timeout = Z_LVAL_P(prop);
        }
        prop = pcbc_read_property(pcbc_remove_options_ce, options, ("durability_level"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            level = Z_LVAL_P(prop);
        }
    }
    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/remove_multi", 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }

    size_t num_of_ids = zend_hash_num_elements(Z_ARRVAL_P(ids));
    struct remove_multi_cookie *cookies = calloc(num_of_ids, sizeof(struct remove_multi_cookie));
    array_init_size(return_value, num_of_ids);
    lcb_sched_enter(bucket->conn->lcb);
    const zval *id;
    lcb_STATUS err = LCB_SUCCESS;
    size_t index = 0;
    ZEND_HASH_FOREACH_VAL(HASH_OF(ids), id)
    {
        lcb_CMDREMOVE *cmd;
        lcb_cmdremove_create(&cmd);
        lcb_cmdremove_collection(cmd, scope_str, scope_len, collection_str, collection_len);
        if (span) {
            lcb_cmdremove_parent_span(cmd, span);
        }
        lcb_cmdremove_timeout(cmd, timeout);
        lcb_cmdremove_durability(cmd, level);
        if (Z_TYPE_P(id) == IS_STRING) {
            lcb_cmdremove_key(cmd, Z_STRVAL_P(id), Z_STRLEN_P(id));
        } else if (Z_TYPE_P(id) == IS_ARRAY && zend_hash_num_elements(Z_ARRVAL_P(id)) == 2) {
            const zval *id_val = zend_hash_index_find(HASH_OF(id), 0);
            const zval *cas_val = zend_hash_index_find(HASH_OF(id), 1);
            if (id_val == NULL || Z_TYPE_P(id_val) != IS_STRING || cas_val == NULL) {
                lcb_cmdremove_destroy(cmd);
                lcb_sched_fail(bucket->conn->lcb);
                err = LCB_ERR_INVALID_ARGUMENT;
                break;
            }
            lcb_cmdremove_key(cmd, Z_STRVAL_P(id_val), Z_STRLEN_P(id_val));
            if (Z_TYPE_P(cas_val) == IS_STRING) {
                uint64_t cas = 0;
                zend_string *decoded = php_base64_decode_str(Z_STR_P(cas_val));
                if (decoded) {
                    memcpy(&cas, ZSTR_VAL(decoded), ZSTR_LEN(decoded));
                    lcb_cmdremove_cas(cmd, cas);
                    zend_string_free(decoded);
                } else {
                    lcb_cmdremove_destroy(cmd);
                    lcb_sched_fail(bucket->conn->lcb);
                    err = LCB_ERR_INVALID_ARGUMENT;
                    break;
                }
            }
        } else {
            lcb_cmdremove_destroy(cmd);
            lcb_sched_fail(bucket->conn->lcb);
            err = LCB_ERR_INVALID_ARGUMENT;
            break;
        }

        zval result;
        object_init_ex(&result, pcbc_mutation_result_impl_ce);
        add_next_index_zval(return_value, &result);
        cookies[index].rc = LCB_SUCCESS;
        cookies[index].return_value = return_value;
        cookies[index].index = index;
        err = lcb_remove(bucket->conn->lcb, &cookies[index], cmd);
        lcb_cmdremove_destroy(cmd);
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
            lcb_install_callback(bucket->conn->lcb, LCB_CALLBACK_REMOVE, (lcb_RESPCALLBACK)remove_multi_callback);
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        lcb_install_callback(bucket->conn->lcb, LCB_CALLBACK_REMOVE, prev_cb);
    }
    free(cookies);

    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, NULL);
    }
}

PHP_MINIT_FUNCTION(CollectionRemoveMulti)
{
    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
