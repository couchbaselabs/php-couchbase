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

#include "expiry_util.h"

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/multi_upsert", __FILE__, __LINE__

extern zend_class_entry *pcbc_store_result_impl_ce;
extern zend_class_entry *pcbc_mutation_token_impl_ce;
extern zend_class_entry *pcbc_upsert_options_ce;

struct upsert_multi_cookie {
    lcb_STATUS rc;
    zval *return_value;
    size_t index;
};

void upsert_multi_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPSTORE *resp)
{
    const lcb_KEY_VALUE_ERROR_CONTEXT *ectx = NULL;
    struct upsert_multi_cookie *cookie = NULL;
    lcb_respstore_cookie(resp, (void **)&cookie);
    zval *return_value = zend_hash_index_find(HASH_OF(cookie->return_value), cookie->index);
    cookie->rc = lcb_respstore_status(resp);
    pcbc_update_property_long(pcbc_store_result_impl_ce, return_value, ("status"), cookie->rc);

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
            pcbc_update_property_str(pcbc_store_result_impl_ce, return_value, ("cas"), b64);
            zend_string_release(b64);
        }
        {
            lcb_MUTATION_TOKEN token = {0};
            lcb_respstore_mutation_token(resp, &token);
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

                pcbc_update_property(pcbc_store_result_impl_ce, return_value, ("mutation_token"), &val);
                zval_ptr_dtor(&val);
            }
        }
    }
    if (lcb_respstore_observe_attached(resp)) {
        int store_ok;
        lcb_respstore_observe_stored(resp, &store_ok);
        pcbc_update_property_bool(pcbc_store_result_impl_ce, return_value, ("is_stored"), store_ok);
        if (store_ok) {
            set_property_num(uint16_t, lcb_respstore_observe_num_persisted, pcbc_store_result_impl_ce, "num_persisted");
            set_property_num(uint16_t, lcb_respstore_observe_num_replicated, pcbc_store_result_impl_ce,
                             "num_replicated");
        }
    }
    (void)cbtype;
}

PHP_METHOD(Collection, upsertMulti)
{
    zval *entries;
    zval *options = NULL;

    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "A|O!", &entries, &options, pcbc_upsert_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    PCBC_RESOLVE_COLLECTION;

    zend_long timeout = 0;
    zend_long expiry = 0;
    zend_bool preserve_expiry = 0;
    lcb_DURABILITY_LEVEL level = LCB_DURABILITYLEVEL_NONE;
    zval encoder = {0};
    ZVAL_NULL(&encoder);
    if (options) {
        zval *prop, ret;
        prop = pcbc_read_property(pcbc_upsert_options_ce, options, ("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            timeout = Z_LVAL_P(prop);
        }
        prop = pcbc_read_property(pcbc_upsert_options_ce, options, ("expiry"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            expiry = Z_LVAL_P(prop);
        }
        prop = pcbc_read_property(pcbc_upsert_options_ce, options, ("preserve_expiry"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_TRUE) {
            preserve_expiry = 1;
        }
        prop = pcbc_read_property(pcbc_upsert_options_ce, options, ("durability_level"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            level = Z_LVAL_P(prop);
        }
        prop = pcbc_read_property(pcbc_upsert_options_ce, options, ("encoder"), 0, &ret);
        if (Z_TYPE_P(prop) != IS_NULL) {
            ZVAL_COPY(&encoder, prop);
        }
    }

    lcbtrace_SPAN *parent_span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        parent_span = lcbtrace_span_start(tracer, "php/upsert_multi", 0, NULL);
        lcbtrace_span_add_tag_str(parent_span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(parent_span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }

    size_t num_of_entries = zend_hash_num_elements(Z_ARRVAL_P(entries));
    struct upsert_multi_cookie *cookies = calloc(num_of_entries, sizeof(struct upsert_multi_cookie));
    array_init_size(return_value, num_of_entries);
    lcb_sched_enter(bucket->conn->lcb);
    const zval *entry;
    lcb_STATUS err = LCB_SUCCESS;
    size_t index = 0;

    ZEND_HASH_FOREACH_VAL(HASH_OF(entries), entry)
    {
        if (Z_TYPE_P(entry) != IS_ARRAY || zend_hash_num_elements(Z_ARRVAL_P(entry)) != 2) {
            lcb_sched_fail(bucket->conn->lcb);
            err = LCB_ERR_INVALID_ARGUMENT;
            break;
        }
        const zval *id = zend_hash_index_find(HASH_OF(entry), 0);
        zval *value = zend_hash_index_find(HASH_OF(entry), 1);
        if (id == NULL || Z_TYPE_P(id) != IS_STRING || value == NULL) {
            lcb_sched_fail(bucket->conn->lcb);
            err = LCB_ERR_INVALID_ARGUMENT;
            break;
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

        rv = pcbc_encode_value(Z_TYPE(encoder) == IS_NULL ? &bucket->encoder : &encoder, value, &bytes, &nbytes, &flags,
                               &datatype);
        if (span) {
            lcbtrace_span_finish(span, LCBTRACE_NOW);
        }
        if (rv != SUCCESS) {
            pcbc_log(LOGARGS(bucket->conn->lcb, ERROR), "Failed to encode value for before storing");
            lcb_sched_fail(bucket->conn->lcb);
            err = LCB_ERR_INVALID_ARGUMENT;
            break;
        }

        lcb_CMDSTORE *cmd;
        lcb_cmdstore_create(&cmd, LCB_STORE_UPSERT);
        lcb_cmdstore_collection(cmd, scope_str, scope_len, collection_str, collection_len);
        lcb_cmdstore_key(cmd, Z_STRVAL_P(id), Z_STRLEN_P(id));
        lcb_cmdstore_value(cmd, bytes, nbytes);
        lcb_cmdstore_flags(cmd, flags);
        lcb_cmdstore_datatype(cmd, datatype);
        lcb_cmdstore_durability(cmd, level);
        if (parent_span) {
            lcb_cmdstore_parent_span(cmd, parent_span);
        }
        if (preserve_expiry) {
            lcb_cmdstore_preserve_expiry(cmd, 1);
        } else {
            lcb_cmdstore_expiry(cmd, expiry);
        }
        lcb_cmdstore_timeout(cmd, timeout);

        zval result;
        object_init_ex(&result, pcbc_store_result_impl_ce);
        add_next_index_zval(return_value, &result);
        cookies[index].rc = LCB_SUCCESS;
        cookies[index].return_value = return_value;
        cookies[index].index = index;
        err = lcb_store(bucket->conn->lcb, &cookies[index], cmd);
        efree(bytes);
        lcb_cmdstore_destroy(cmd);
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
            lcb_install_callback(bucket->conn->lcb, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)upsert_multi_callback);
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        lcb_install_callback(bucket->conn->lcb, LCB_CALLBACK_STORE, prev_cb);
    }
    free(cookies);

    if (parent_span) {
        lcbtrace_span_finish(parent_span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, pcbc_store_result_impl_ce);
    }
}

PHP_MINIT_FUNCTION(CollectionUpsertMulti)
{
    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
