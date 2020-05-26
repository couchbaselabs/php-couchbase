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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/subdoc", __FILE__, __LINE__

extern zend_class_entry *pcbc_lookup_get_spec_ce;
extern zend_class_entry *pcbc_lookup_count_spec_ce;
extern zend_class_entry *pcbc_lookup_exists_spec_ce;

extern zend_class_entry *pcbc_lookup_in_result_impl_ce;
extern zend_class_entry *pcbc_lookup_in_result_entry_ce;

extern zend_class_entry *pcbc_mutate_insert_spec_ce;
extern zend_class_entry *pcbc_mutate_upsert_spec_ce;
extern zend_class_entry *pcbc_mutate_replace_spec_ce;
extern zend_class_entry *pcbc_mutate_remove_spec_ce;
extern zend_class_entry *pcbc_mutate_array_append_spec_ce;
extern zend_class_entry *pcbc_mutate_array_prepend_spec_ce;
extern zend_class_entry *pcbc_mutate_array_insert_spec_ce;
extern zend_class_entry *pcbc_mutate_array_add_unique_spec_ce;
extern zend_class_entry *pcbc_mutate_counter_spec_ce;

extern zend_class_entry *pcbc_mutate_in_result_impl_ce;
extern zend_class_entry *pcbc_mutate_in_result_entry_ce;
extern zend_class_entry *pcbc_mutation_token_impl_ce;

struct subdoc_cookie {
    lcb_STATUS rc;
    zval *return_value;
};

void subdoc_lookup_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPSUBDOC *resp)
{
    TSRMLS_FETCH();

    const lcb_KEY_VALUE_ERROR_CONTEXT *ectx = NULL;
    struct subdoc_cookie *cookie = NULL;
    lcb_respsubdoc_cookie(resp, (void **)&cookie);
    zval *return_value = cookie->return_value;
    cookie->rc = lcb_respsubdoc_status(resp);
    zend_update_property_long(pcbc_lookup_in_result_impl_ce, return_value, ZEND_STRL("status"), cookie->rc TSRMLS_CC);

    lcb_respsubdoc_error_context(resp, &ectx);
    set_property_str(ectx, lcb_errctx_kv_context, pcbc_lookup_in_result_impl_ce, "err_ctx");
    set_property_str(ectx, lcb_errctx_kv_ref, pcbc_lookup_in_result_impl_ce, "err_ref");
    set_property_str(ectx, lcb_errctx_kv_key, pcbc_lookup_in_result_impl_ce, "key");
    if (cookie->rc == LCB_SUCCESS) {
        uint64_t data;
        lcb_respsubdoc_cas(resp, &data);
        zend_string *b64;
        b64 = php_base64_encode((unsigned char *)&data, sizeof(data));
        zend_update_property_str(pcbc_lookup_in_result_impl_ce, return_value, ZEND_STRL("cas"), b64 TSRMLS_CC);
        zend_string_release(b64);
    }
    size_t num_results = lcb_respsubdoc_result_size(resp);
    size_t idx;
    zval data;
    array_init(&data);
    zend_update_property(pcbc_lookup_in_result_impl_ce, return_value, ZEND_STRL("data"), &data TSRMLS_CC);
    Z_DELREF(data);
    for (idx = 0; idx < num_results; idx++) {
        zval entry;
        array_init(&entry);
        object_init_ex(&entry, pcbc_lookup_in_result_entry_ce);

        zend_update_property_long(pcbc_lookup_in_result_entry_ce, &entry, ZEND_STRL("code"),
                                  lcb_respsubdoc_result_status(resp, idx) TSRMLS_CC);
        const char *bytes;
        size_t nbytes;
        lcb_respsubdoc_result_value(resp, idx, &bytes, &nbytes);
        zval value;
        ZVAL_NULL(&value);
        if (nbytes > 0) {
            int last_error;
            PCBC_JSON_COPY_DECODE(&value, bytes, nbytes, PHP_JSON_OBJECT_AS_ARRAY, last_error);
            if (last_error != 0) {
                pcbc_log(LOGARGS(instance, WARN),
                         "Failed to decode subdoc lookup response idx=%d as JSON: json_last_error=%d", (int)idx,
                         last_error);
            }
        }
        zend_update_property(pcbc_lookup_in_result_entry_ce, &entry, ZEND_STRL("value"), &value TSRMLS_CC);
        add_index_zval(&data, idx, &entry);
        Z_TRY_ADDREF(entry);
    }
}

void subdoc_mutate_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPSUBDOC *resp)
{
    TSRMLS_FETCH();

    const lcb_KEY_VALUE_ERROR_CONTEXT *ectx = NULL;
    struct subdoc_cookie *cookie = NULL;
    lcb_respsubdoc_cookie(resp, (void **)&cookie);
    zval *return_value = cookie->return_value;
    cookie->rc = lcb_respsubdoc_status(resp);
    zend_update_property_long(pcbc_mutate_in_result_impl_ce, return_value, ZEND_STRL("status"), cookie->rc TSRMLS_CC);

    lcb_respsubdoc_error_context(resp, &ectx);

    set_property_str(ectx, lcb_errctx_kv_context, pcbc_mutate_in_result_impl_ce, "err_ctx");
    set_property_str(ectx, lcb_errctx_kv_ref, pcbc_mutate_in_result_impl_ce, "err_ref");
    set_property_str(ectx, lcb_errctx_kv_key, pcbc_mutate_in_result_impl_ce, "key");
    if (cookie->rc == LCB_SUCCESS) {
        uint64_t data;
        lcb_respsubdoc_cas(resp, &data);
        zend_string *b64;
        b64 = php_base64_encode((unsigned char *)&data, sizeof(data));
        zend_update_property_str(pcbc_mutate_in_result_impl_ce, return_value, ZEND_STRL("cas"), b64 TSRMLS_CC);
        zend_string_release(b64);
        {
            lcb_MUTATION_TOKEN token = {0};
            lcb_respsubdoc_mutation_token(resp, &token);
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

                zend_update_property(pcbc_mutate_in_result_impl_ce, return_value, ZEND_STRL("mutation_token"),
                                     &val TSRMLS_CC);
                zval_ptr_dtor(&val);
            }
        }
    }
    size_t num_results = lcb_respsubdoc_result_size(resp);
    size_t idx;
    zval data;
    array_init(&data);
    zend_update_property(pcbc_mutate_in_result_impl_ce, return_value, ZEND_STRL("data"), &data TSRMLS_CC);
    Z_DELREF(data);
    for (idx = 0; idx < num_results; idx++) {
        zval entry;
        array_init(&entry);
        object_init_ex(&entry, pcbc_mutate_in_result_entry_ce);

        zend_update_property_long(pcbc_mutate_in_result_entry_ce, &entry, ZEND_STRL("code"),
                                  lcb_respsubdoc_result_status(resp, idx) TSRMLS_CC);
        const char *bytes;
        size_t nbytes;
        lcb_respsubdoc_result_value(resp, idx, &bytes, &nbytes);
        zval value;
        ZVAL_NULL(&value);
        if (nbytes > 0) {
            int last_error;
            PCBC_JSON_COPY_DECODE(&value, bytes, nbytes, PHP_JSON_OBJECT_AS_ARRAY, last_error);
            if (last_error != 0) {
                pcbc_log(LOGARGS(instance, WARN),
                         "Failed to decode subdoc mutate response idx=%d as JSON: json_last_error=%d", (int)idx,
                         last_error);
            }
        }
        zend_update_property(pcbc_mutate_in_result_entry_ce, &entry, ZEND_STRL("value"), &value TSRMLS_CC);
        add_index_zval(&data, idx, &entry);
        Z_TRY_ADDREF(entry);
    }
}

zend_class_entry *pcbc_lookup_in_options_ce;

PHP_METHOD(LookupInOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_lookup_in_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(LookupInOptions, withExpiry)
{
    zend_bool arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_bool(pcbc_lookup_in_options_ce, getThis(), ZEND_STRL("with_expiry"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_LookupInOptions_timeout, 0, 1, \\Couchbase\\LookupInOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_LookupInOptions_withExpiry, 0, 1, \\Couchbase\\LookupInOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_lookup_in_options_methods[] = {
    PHP_ME(LookupInOptions, timeout, ai_LookupInOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(LookupInOptions, withExpiry, ai_LookupInOptions_withExpiry, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Collection, lookupIn)
{
    zend_string *id;
    zval *options = NULL;
    HashTable *spec = NULL;
    int rv;

    rv =
        zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "Sh|O!", &id, &spec, &options, pcbc_lookup_in_options_ce);
    if (rv == FAILURE) {
        return;
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_SUBDOCSPECS *operations;
    lcb_subdocspecs_create(&operations, zend_hash_num_elements(spec));
    zval *val, *prop, tmp;
    int idx = 0;
    uint32_t flags;
    ZEND_HASH_FOREACH_VAL(spec, val)
    {
        flags = 0;
        if (Z_OBJCE_P(val) == pcbc_lookup_get_spec_ce) {
            if (Z_TYPE_P(zend_read_property(pcbc_lookup_get_spec_ce, val, ZEND_STRL("is_xattr"), 0, &tmp)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTRPATH;
            }
            prop = zend_read_property(pcbc_lookup_get_spec_ce, val, ZEND_STRL("path"), 0, &tmp);
            lcb_subdocspecs_get(operations, idx, flags, Z_STRVAL_P(prop), Z_STRLEN_P(prop));
        } else if (Z_OBJCE_P(val) == pcbc_lookup_count_spec_ce) {
            if (Z_TYPE_P(zend_read_property(pcbc_lookup_count_spec_ce, val, ZEND_STRL("is_xattr"), 0, &tmp)) ==
                IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTRPATH;
            }
            prop = zend_read_property(pcbc_lookup_count_spec_ce, val, ZEND_STRL("path"), 0, &tmp);
            lcb_subdocspecs_get_count(operations, idx, flags, Z_STRVAL_P(prop), Z_STRLEN_P(prop));
        } else if (Z_OBJCE_P(val) == pcbc_lookup_exists_spec_ce) {
            if (Z_TYPE_P(zend_read_property(pcbc_lookup_exists_spec_ce, val, ZEND_STRL("is_xattr"), 0, &tmp)) ==
                IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTRPATH;
            }
            prop = zend_read_property(pcbc_lookup_exists_spec_ce, val, ZEND_STRL("path"), 0, &tmp);
            lcb_subdocspecs_exists(operations, idx, flags, Z_STRVAL_P(prop), Z_STRLEN_P(prop));
        } else {
            /* TODO: raise argument exception */
            lcb_subdocspecs_destroy(operations);
            return;
        }
        idx++;
    }
    ZEND_HASH_FOREACH_END();

    lcb_CMDSUBDOC *cmd;
    lcb_cmdsubdoc_create(&cmd);
    lcb_cmdsubdoc_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    lcb_cmdsubdoc_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_lookup_in_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdsubdoc_timeout(cmd, Z_LVAL_P(prop));
        }
    }

    object_init_ex(return_value, pcbc_lookup_in_result_impl_ce);
    struct subdoc_cookie cookie = {LCB_SUCCESS, return_value};
    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/subdoc", 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdsubdoc_parent_span(cmd, span);
    }
    lcb_cmdsubdoc_specs(cmd, operations);
    lcb_STATUS err = lcb_subdoc(bucket->conn->lcb, &cookie, cmd);
    lcb_cmdsubdoc_destroy(cmd);
    lcb_subdocspecs_destroy(operations);
    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }

    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }

    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, pcbc_lookup_in_result_impl_ce);
    }
}

zend_class_entry *pcbc_mutate_in_options_ce;

PHP_METHOD(MutateInOptions, cas)
{
    zend_string *arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "S", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_string *decoded = php_base64_decode_str(arg);
    if (decoded) {
        if (ZSTR_LEN(decoded) == sizeof(uint64_t)) {
            zend_update_property_str(pcbc_mutate_in_options_ce, getThis(), ZEND_STRL("cas"), arg TSRMLS_CC);
        }
        zend_string_free(decoded);
    }
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(MutateInOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_mutate_in_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(MutateInOptions, expiry)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_mutate_in_options_ce, getThis(), ZEND_STRL("expiry"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(MutateInOptions, durabilityLevel)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_mutate_in_options_ce, getThis(), ZEND_STRL("durability_level"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(MutateInOptions, storeSemantics)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_mutate_in_options_ce, getThis(), ZEND_STRL("store_semantics"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_MutateInOptions_cas, 0, 1, \\Couchbase\\MutateInOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_MutateInOptions_timeout, 0, 1, \\Couchbase\\MutateInOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_MutateInOptions_expiry, 0, 1, \\Couchbase\\MutateInOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_MutateInOptions_durabilityLevel, 0, 1, \\Couchbase\\MutateInOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_MutateInOptions_storeSemantics, 0, 1, \\Couchbase\\MutateInOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_mutate_in_options_methods[] = {
    PHP_ME(MutateInOptions, cas, ai_MutateInOptions_cas, ZEND_ACC_PUBLIC)
    PHP_ME(MutateInOptions, timeout, ai_MutateInOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(MutateInOptions, expiry, ai_MutateInOptions_expiry, ZEND_ACC_PUBLIC)
    PHP_ME(MutateInOptions, durabilityLevel, ai_MutateInOptions_durabilityLevel, ZEND_ACC_PUBLIC)
    PHP_ME(MutateInOptions, storeSemantics, ai_MutateInOptions_storeSemantics, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Collection, mutateIn)
{
    zend_string *id;
    zval *options = NULL;
    HashTable *spec = NULL;
    int rv;

    rv =
        zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "Sh|O!", &id, &spec, &options, pcbc_mutate_in_options_ce);
    if (rv == FAILURE) {
        return;
    }
    PCBC_RESOLVE_COLLECTION;

    lcb_SUBDOCSPECS *operations;
    lcb_subdocspecs_create(&operations, zend_hash_num_elements(spec));
    zval *entry, *path, *value, rv1, rv2;
    int idx = 0;
    uint32_t flags;
    ZEND_HASH_FOREACH_VAL(spec, entry)
    {
        flags = 0;
        if (Z_OBJCE_P(entry) == pcbc_mutate_insert_spec_ce) {
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("is_xattr"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTRPATH;
            }
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("create_path"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_MKINTERMEDIATES;
            }
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("expand_macros"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTR_MACROVALUES;
            }
            path = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("path"), 0, &rv1);
            value = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("value"), 0, &rv2);
            lcb_subdocspecs_dict_add(operations, idx, flags, Z_STRVAL_P(path), Z_STRLEN_P(path), Z_STRVAL_P(value),
                                     Z_STRLEN_P(value));
        } else if (Z_OBJCE_P(entry) == pcbc_mutate_upsert_spec_ce) {
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("is_xattr"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTRPATH;
            }
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("create_path"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_MKINTERMEDIATES;
            }
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("expand_macros"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTR_MACROVALUES;
            }
            path = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("path"), 0, &rv1);
            value = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("value"), 0, &rv2);
            lcb_subdocspecs_dict_upsert(operations, idx, flags, Z_STRVAL_P(path), Z_STRLEN_P(path), Z_STRVAL_P(value),
                                        Z_STRLEN_P(value));
        } else if (Z_OBJCE_P(entry) == pcbc_mutate_replace_spec_ce) {
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("is_xattr"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTRPATH;
            }
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("expand_macros"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTR_MACROVALUES;
            }
            path = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("path"), 0, &rv1);
            value = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("value"), 0, &rv2);
            lcb_subdocspecs_replace(operations, idx, flags, Z_STRVAL_P(path), Z_STRLEN_P(path), Z_STRVAL_P(value),
                                    Z_STRLEN_P(value));
        } else if (Z_OBJCE_P(entry) == pcbc_mutate_remove_spec_ce) {
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("is_xattr"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTRPATH;
            }
            path = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("path"), 0, &rv1);
            lcb_subdocspecs_remove(operations, idx, flags, Z_STRVAL_P(path), Z_STRLEN_P(path));
        } else if (Z_OBJCE_P(entry) == pcbc_mutate_array_append_spec_ce) {
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("is_xattr"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTRPATH;
            }
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("create_path"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_MKINTERMEDIATES;
            }
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("expand_macros"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTR_MACROVALUES;
            }
            path = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("path"), 0, &rv1);
            value = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("value"), 0, &rv2);
            lcb_subdocspecs_array_add_last(operations, idx, flags, Z_STRVAL_P(path), Z_STRLEN_P(path),
                                           Z_STRVAL_P(value), Z_STRLEN_P(value));
        } else if (Z_OBJCE_P(entry) == pcbc_mutate_array_prepend_spec_ce) {
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("is_xattr"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTRPATH;
            }
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("create_path"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_MKINTERMEDIATES;
            }
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("expand_macros"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTR_MACROVALUES;
            }
            path = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("path"), 0, &rv1);
            value = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("value"), 0, &rv2);
            lcb_subdocspecs_array_add_first(operations, idx, flags, Z_STRVAL_P(path), Z_STRLEN_P(path),
                                            Z_STRVAL_P(value), Z_STRLEN_P(value));
        } else if (Z_OBJCE_P(entry) == pcbc_mutate_array_insert_spec_ce) {
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("is_xattr"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTRPATH;
            }
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("create_path"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_MKINTERMEDIATES;
            }
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("expand_macros"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTR_MACROVALUES;
            }
            path = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("path"), 0, &rv1);
            value = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("value"), 0, &rv2);
            lcb_subdocspecs_array_insert(operations, idx, flags, Z_STRVAL_P(path), Z_STRLEN_P(path), Z_STRVAL_P(value),
                                         Z_STRLEN_P(value));
        } else if (Z_OBJCE_P(entry) == pcbc_mutate_array_add_unique_spec_ce) {
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("is_xattr"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTRPATH;
            }
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("create_path"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_MKINTERMEDIATES;
            }
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("expand_macros"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTR_MACROVALUES;
            }
            path = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("path"), 0, &rv1);
            value = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("value"), 0, &rv2);
            lcb_subdocspecs_array_add_unique(operations, idx, flags, Z_STRVAL_P(path), Z_STRLEN_P(path),
                                             Z_STRVAL_P(value), Z_STRLEN_P(value));
        } else if (Z_OBJCE_P(entry) == pcbc_mutate_counter_spec_ce) {
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("is_xattr"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_XATTRPATH;
            }
            if (Z_TYPE_P(zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("create_path"), 0, &rv1)) == IS_TRUE) {
                flags |= LCB_SUBDOCSPECS_F_MKINTERMEDIATES;
            }
            path = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("path"), 0, &rv1);
            value = zend_read_property(Z_OBJCE_P(entry), entry, ZEND_STRL("delta"), 0, &rv2);
            lcb_subdocspecs_counter(operations, idx, flags, Z_STRVAL_P(path), Z_STRLEN_P(path), Z_LVAL_P(value));
        } else {
            /* TODO: raise argument exception */
            lcb_subdocspecs_destroy(operations);
            return;
        }
        idx++;
    }
    ZEND_HASH_FOREACH_END();

    lcb_CMDSUBDOC *cmd;
    lcb_cmdsubdoc_create(&cmd);
    lcb_cmdsubdoc_collection(cmd, scope_str, scope_len, collection_str, collection_len);
    lcb_cmdsubdoc_key(cmd, ZSTR_VAL(id), ZSTR_LEN(id));
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_mutate_in_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdsubdoc_timeout(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_mutate_in_options_ce, options, ZEND_STRL("expiry"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdsubdoc_expiry(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_mutate_in_options_ce, options, ZEND_STRL("durability_level"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdsubdoc_durability(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_mutate_in_options_ce, options, ZEND_STRL("store_semantics"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdsubdoc_store_semantics(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_mutate_in_options_ce, options, ZEND_STRL("cas"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            zend_string *decoded = php_base64_decode_str(Z_STR_P(prop));
            if (decoded) {
                uint64_t cas = 0;
                memcpy(&cas, ZSTR_VAL(decoded), ZSTR_LEN(decoded));
                lcb_cmdsubdoc_cas(cmd, cas);
                zend_string_free(decoded);
            }
        }
    }

    object_init_ex(return_value, pcbc_mutate_in_result_impl_ce);
    struct subdoc_cookie cookie = {LCB_SUCCESS, return_value};
    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/subdoc", 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        lcb_cmdsubdoc_parent_span(cmd, span);
    }
    lcb_cmdsubdoc_specs(cmd, operations);
    lcb_STATUS err = lcb_subdoc(bucket->conn->lcb, &cookie, cmd);
    lcb_cmdsubdoc_destroy(cmd);
    lcb_subdocspecs_destroy(operations);
    if (err == LCB_SUCCESS) {
        lcb_wait(bucket->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }

    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }

    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, pcbc_mutate_in_result_impl_ce);
    }
}

zend_class_entry *pcbc_store_semantics_ce;
static const zend_function_entry pcbc_store_semantics_methods[] = {PHP_FE_END};

PHP_MINIT_FUNCTION(CollectionSubdoc)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "LookupInOptions", pcbc_lookup_in_options_methods);
    pcbc_lookup_in_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_lookup_in_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_lookup_in_options_ce, ZEND_STRL("with_expiry"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutateInOptions", pcbc_mutate_in_options_methods);
    pcbc_mutate_in_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_mutate_in_options_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_mutate_in_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_mutate_in_options_ce, ZEND_STRL("expiry"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_mutate_in_options_ce, ZEND_STRL("durability_level"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_mutate_in_options_ce, ZEND_STRL("store_semantics"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "StoreSemantics", pcbc_store_semantics_methods);
    pcbc_store_semantics_ce = zend_register_internal_interface(&ce TSRMLS_CC);
    zend_declare_class_constant_long(pcbc_store_semantics_ce, ZEND_STRL("REPLACE"), LCB_SUBDOC_STORE_REPLACE TSRMLS_CC);
    zend_declare_class_constant_long(pcbc_store_semantics_ce, ZEND_STRL("UPSERT"), LCB_SUBDOC_STORE_UPSERT TSRMLS_CC);
    zend_declare_class_constant_long(pcbc_store_semantics_ce, ZEND_STRL("INSERT"), LCB_SUBDOC_STORE_INSERT TSRMLS_CC);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
