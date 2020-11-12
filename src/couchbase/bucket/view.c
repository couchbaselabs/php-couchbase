/**
 *     Copyright 2017-2019 Couchbase, Inc.
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
#include <ext/standard/php_http.h>
#include <ext/standard/url.h>

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/view", __FILE__, __LINE__

extern zend_class_entry *pcbc_view_result_impl_ce;
extern zend_class_entry *pcbc_view_result_entry_ce;
extern zend_class_entry *pcbc_view_meta_data_impl_ce;

struct view_cookie {
    lcb_STATUS rc;
    zval *return_value;
};

static void viewrow_callback(lcb_INSTANCE *instance, int ignoreme, const lcb_RESPVIEW *resp)
{
    struct view_cookie *cookie;
    lcb_respview_cookie(resp, (void **)&cookie);
    cookie->rc = lcb_respview_status(resp);

    const lcb_RESPHTTP *http;
    lcb_respview_http_response(resp, &http);
    uint16_t htstatus;
    lcb_resphttp_http_status(http, &htstatus);

    zval *return_value = cookie->return_value;

    zend_update_property_long(pcbc_view_result_impl_ce, return_value, ZEND_STRL("status"), cookie->rc);
    zend_update_property_long(pcbc_view_result_impl_ce, return_value, ZEND_STRL("http_status"), htstatus);

    int last_error;
    if (cookie->rc == LCB_SUCCESS) {
        if (lcb_respview_is_final(resp)) {
            zval meta, *mval, value;
            object_init_ex(&meta, pcbc_view_meta_data_impl_ce);

            const char *value_str;
            size_t value_len;
            lcb_respview_row(resp, &value_str, &value_len);
            if (value_len) {
                PCBC_JSON_COPY_DECODE(&value, value_str, value_len, PHP_JSON_OBJECT_AS_ARRAY, last_error);
                if (last_error) {
                    pcbc_log(LOGARGS(instance, WARN), "Failed to decode VIEW meta as JSON: json_last_error=%d",
                             last_error);
                } else {
                    HashTable *marr = Z_ARRVAL(value);

                    mval = zend_symtable_str_find(marr, ZEND_STRL("total_rows"));
                    if (mval && Z_TYPE_P(mval) == IS_LONG) {
                        zend_update_property(pcbc_view_meta_data_impl_ce, &meta, ZEND_STRL("total_rows"),
                                             mval);
                    }
                    zval_dtor(&value);
                }
            }
            zend_update_property(pcbc_view_result_impl_ce, return_value, ZEND_STRL("meta"), &meta);
            zval_ptr_dtor(&meta);
        } else {
            zval entry;
            object_init_ex(&entry, pcbc_view_result_entry_ce);

            const char *id_str;
            size_t id_len;
            lcb_respview_doc_id(resp, &id_str, &id_len);
            if (id_len) {
                zend_update_property_stringl(pcbc_view_result_entry_ce, &entry, ZEND_STRL("id"), id_str,
                                             id_len);
            }

            const char *key_str;
            size_t key_len;
            lcb_respview_key(resp, &key_str, &key_len);
            zval key;
            if (key_len) {
                PCBC_JSON_COPY_DECODE(&key, key_str, key_len, PHP_JSON_OBJECT_AS_ARRAY, last_error);
                if (last_error) {
                    pcbc_log(LOGARGS(instance, WARN), "Failed to decode VIEW key as JSON: json_last_error=%d",
                             last_error);
                } else {
                    zend_update_property(pcbc_view_result_entry_ce, &entry, ZEND_STRL("key"), &key);
                }
            }

            const char *value_str;
            size_t value_len;
            lcb_respview_row(resp, &value_str, &value_len);
            zval value;
            if (value_len) {
                PCBC_JSON_COPY_DECODE(&value, value_str, value_len, PHP_JSON_OBJECT_AS_ARRAY, last_error);
                if (last_error) {
                    pcbc_log(LOGARGS(instance, WARN), "Failed to decode VIEW value as JSON: json_last_error=%d",
                             last_error);
                } else {
                    zend_update_property(pcbc_view_result_entry_ce, &entry, ZEND_STRL("value"), &value);
                }
            }

            const lcb_RESPGET *get;
            lcb_respview_document(resp, &get);
            zval document;
            if (get) {
                const char *doc_str;
                size_t doc_len;
                lcb_respget_value(get, &doc_str, &doc_len);
                if (doc_len) {
                    PCBC_JSON_COPY_DECODE(&document, doc_str, doc_len, PHP_JSON_OBJECT_AS_ARRAY, last_error);
                    if (last_error) {
                        pcbc_log(LOGARGS(instance, WARN), "Failed to decode VIEW document as JSON: json_last_error=%d",
                                 last_error);
                    } else {
                        zend_update_property(pcbc_view_result_entry_ce, &entry, ZEND_STRL("document"),
                                             &document);
                    }
                }
            }

            zval *rows, rv;
            rows = zend_read_property(pcbc_view_result_impl_ce, return_value, ZEND_STRL("rows"), 0, &rv);
            add_next_index_zval(rows, &entry);
        }
    } else {
        const char *body_str;
        size_t body_len;
        lcb_resphttp_body(http, &body_str, &body_len);
        zval body;
        if (body_len) {
            PCBC_JSON_COPY_DECODE(&body, body_str, body_len, PHP_JSON_OBJECT_AS_ARRAY, last_error);
            if (last_error) {
                pcbc_log(LOGARGS(instance, WARN), "Failed to decode VIEW body as JSON: json_last_error=%d", last_error);
                zend_update_property_stringl(pcbc_view_result_impl_ce, return_value, ZEND_STRL("body_str"), body_str,
                                             body_len);
            } else {
                zend_update_property(pcbc_view_result_impl_ce, return_value, ZEND_STRL("body"), &body);
            }
        }
    }
}

zend_class_entry *pcbc_view_order_ce;
static const zend_function_entry pcbc_view_order_methods[] = {PHP_FE_END};

zend_class_entry *pcbc_view_consistency_ce;
static const zend_function_entry pcbc_view_consistency_methods[] = {PHP_FE_END};

zend_class_entry *pcbc_view_options_ce;

PHP_METHOD(ViewOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_view_options_ce, getThis(), ZEND_STRL("timeout"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ViewOptions, includeDocuments)
{
    zend_bool arg;
    zend_long mcd = 0;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "b|l", &arg, &mcd);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_bool(pcbc_view_options_ce, getThis(), ZEND_STRL("include_docs"), arg);
    if (mcd) {
        zend_update_property_long(pcbc_view_options_ce, getThis(), ZEND_STRL("max_concurrent_docs"), mcd);
    }
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ViewOptions, key)
{
    zval *arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "z", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1;
    data = zend_read_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), 0, &rv1);
    if (Z_TYPE_P(data) == IS_NULL) {
        array_init(&rv1);
        data = &rv1;
        zend_update_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), data);
        Z_DELREF_P(data);
    }
    {
        smart_str buf = {0};
        int last_error;
        PCBC_JSON_ENCODE(&buf, arg, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(NULL, WARN), "Failed to encode key as JSON: json_last_error=%d", last_error);
            smart_str_free(&buf);
            RETURN_NULL();
        }
        smart_str_0(&buf);
        add_assoc_str_ex(data, ZEND_STRL("key"), buf.s);
    }
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ViewOptions, limit)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1;
    data = zend_read_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), 0, &rv1);
    if (Z_TYPE_P(data) == IS_NULL) {
        array_init(&rv1);
        data = &rv1;
        zend_update_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), data);
        Z_DELREF_P(data);
    }
    add_assoc_long_ex(data, ZEND_STRL("limit"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ViewOptions, skip)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1;
    data = zend_read_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), 0, &rv1);
    if (Z_TYPE_P(data) == IS_NULL) {
        array_init(&rv1);
        data = &rv1;
        zend_update_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), data);
        Z_DELREF_P(data);
    }
    add_assoc_long_ex(data, ZEND_STRL("skip"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ViewOptions, scanConsistency)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1;
    data = zend_read_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), 0, &rv1);
    if (Z_TYPE_P(data) == IS_NULL) {
        array_init(&rv1);
        data = &rv1;
        zend_update_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), data);
        Z_DELREF_P(data);
    }
    switch (arg) {
    case 0:
        add_assoc_string_ex(data, ZEND_STRL("stale"), "ok");
        break;
    case 1:
        add_assoc_string_ex(data, ZEND_STRL("stale"), "false");
        break;
    case 2:
        add_assoc_string_ex(data, ZEND_STRL("stale"), "update_after");
        break;
    }
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ViewOptions, order)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1;
    data = zend_read_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), 0, &rv1);
    if (Z_TYPE_P(data) == IS_NULL) {
        array_init(&rv1);
        data = &rv1;
        zend_update_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), data);
        Z_DELREF_P(data);
    }
    switch (arg) {
    case 0:
        add_assoc_string_ex(data, ZEND_STRL("descending"), "false");
        break;
    case 1:
        add_assoc_string_ex(data, ZEND_STRL("descending"), "true");
        break;
    }
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ViewOptions, reduce)
{
    zend_bool arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "b", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1;
    data = zend_read_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), 0, &rv1);
    if (Z_TYPE_P(data) == IS_NULL) {
        array_init(&rv1);
        data = &rv1;
        zend_update_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), data);
        Z_DELREF_P(data);
    }
    add_assoc_string_ex(data, ZEND_STRL("reduce"), arg ? "true" : "false");
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ViewOptions, group)
{
    zend_bool arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "b", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1;
    data = zend_read_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), 0, &rv1);
    if (Z_TYPE_P(data) == IS_NULL) {
        array_init(&rv1);
        data = &rv1;
        zend_update_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), data);
        Z_DELREF_P(data);
    }
    add_assoc_string_ex(data, ZEND_STRL("group"), arg ? "true" : "false");
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ViewOptions, groupLevel)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1;
    data = zend_read_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), 0, &rv1);
    if (Z_TYPE_P(data) == IS_NULL) {
        array_init(&rv1);
        data = &rv1;
        zend_update_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), data);
        Z_DELREF_P(data);
    }
    add_assoc_long_ex(data, ZEND_STRL("group_level"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ViewOptions, range)
{
    zval *start, *end = NULL;
    zend_bool inclusive_end = 0;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "zz!|b", &start, &end, &inclusive_end);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1;
    data = zend_read_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), 0, &rv1);
    if (Z_TYPE_P(data) == IS_NULL) {
        array_init(&rv1);
        data = &rv1;
        zend_update_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), data);
        Z_DELREF_P(data);
    }
    add_assoc_string_ex(data, ZEND_STRL("inclusive_end"), inclusive_end ? "true" : "false");
    {
        smart_str buf = {0};
        int last_error;
        PCBC_JSON_ENCODE(&buf, start, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(NULL, WARN), "Failed to encode startkey as JSON: json_last_error=%d", last_error);
            smart_str_free(&buf);
            RETURN_NULL();
        }
        smart_str_0(&buf);
        add_assoc_str_ex(data, ZEND_STRL("startkey"), buf.s);
    }
    if (end != NULL) {
        smart_str buf = {0};
        int last_error;
        PCBC_JSON_ENCODE(&buf, end, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(NULL, WARN), "Failed to encode endkey as JSON: json_last_error=%d", last_error);
            smart_str_free(&buf);
            RETURN_NULL();
        }
        smart_str_0(&buf);
        add_assoc_str_ex(data, ZEND_STRL("endkey"), buf.s);
    }

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ViewOptions, idRange)
{
    zend_string *start, *end = NULL;
    zend_bool inclusive_end = 0;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "SS!|b", &start, &end, &inclusive_end);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1;
    data = zend_read_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), 0, &rv1);
    if (Z_TYPE_P(data) == IS_NULL) {
        array_init(&rv1);
        data = &rv1;
        zend_update_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), data);
        Z_DELREF_P(data);
    }
    add_assoc_string_ex(data, ZEND_STRL("inclusive_end"), inclusive_end ? "true" : "false");
    add_assoc_str_ex(data, ZEND_STRL("startkey_docid"), zend_string_copy(start));
    if (end != NULL) {
        add_assoc_str_ex(data, ZEND_STRL("endkey_docid"), zend_string_copy(end));
    }

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ViewOptions, raw)
{
    zend_string *key, *value;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "SS", &key, &value);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1;
    data = zend_read_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), 0, &rv1);
    if (Z_TYPE_P(data) == IS_NULL) {
        array_init(&rv1);
        data = &rv1;
        zend_update_property(pcbc_view_options_ce, getThis(), ZEND_STRL("query"), data);
        Z_DELREF_P(data);
    }
    add_assoc_str_ex(data, ZSTR_VAL(key), ZSTR_LEN(key), zend_string_copy(value));

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ViewOptions, keys)
{
    zval *arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "a", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1;
    data = zend_read_property(pcbc_view_options_ce, getThis(), ZEND_STRL("body"), 0, &rv1);
    if (Z_TYPE_P(data) == IS_NULL) {
        array_init(&rv1);
        data = &rv1;
        zend_update_property(pcbc_view_options_ce, getThis(), ZEND_STRL("body"), data);
        Z_DELREF_P(data);
    }
    add_assoc_zval_ex(data, ZEND_STRL("keys"), arg);
    Z_ADDREF_P(arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewOptions_timeout, 0, 1, Couchbase\\ViewOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewOptions_includeDocuments, 0, 1, Couchbase\\ViewOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, maxConcurrentDocuments, IS_LONG, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewOptions_key, 0, 1, Couchbase\\ViewOptions, 0)
ZEND_ARG_INFO(0, arg)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewOptions_keys, 0, 1, Couchbase\\ViewOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewOptions_limit, 0, 1, Couchbase\\ViewOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewOptions_skip, 0, 1, Couchbase\\ViewOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewOptions_scanConsistency, 0, 1, Couchbase\\ViewOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewOptions_order, 0, 1, Couchbase\\ViewOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewOptions_reduce, 0, 1, Couchbase\\ViewOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewOptions_group, 0, 1, Couchbase\\ViewOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewOptions_groupLevel, 0, 1, Couchbase\\ViewOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewOptions_range, 0, 2, Couchbase\\ViewOptions, 0)
ZEND_ARG_INFO(0, start)
ZEND_ARG_TYPE_INFO(0, end, 0, 1)
ZEND_ARG_TYPE_INFO(0, inclusiveEnd, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewOptions_idRange, 0, 2, Couchbase\\ViewOptions, 0)
ZEND_ARG_TYPE_INFO(0, start, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, end, IS_STRING, 1)
ZEND_ARG_TYPE_INFO(0, inclusiveEnd, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewOptions_raw, 0, 2, Couchbase\\ViewOptions, 0)
ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_view_options_methods[] = {
    PHP_ME(ViewOptions, timeout, ai_ViewOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(ViewOptions, includeDocuments, ai_ViewOptions_includeDocuments, ZEND_ACC_PUBLIC)
    PHP_ME(ViewOptions, key, ai_ViewOptions_key, ZEND_ACC_PUBLIC)
    PHP_ME(ViewOptions, keys, ai_ViewOptions_keys, ZEND_ACC_PUBLIC)
    PHP_ME(ViewOptions, limit, ai_ViewOptions_limit, ZEND_ACC_PUBLIC)
    PHP_ME(ViewOptions, skip, ai_ViewOptions_skip, ZEND_ACC_PUBLIC)
    PHP_ME(ViewOptions, scanConsistency, ai_ViewOptions_scanConsistency, ZEND_ACC_PUBLIC)
    PHP_ME(ViewOptions, order, ai_ViewOptions_order, ZEND_ACC_PUBLIC)
    PHP_ME(ViewOptions, reduce, ai_ViewOptions_reduce, ZEND_ACC_PUBLIC)
    PHP_ME(ViewOptions, group, ai_ViewOptions_group, ZEND_ACC_PUBLIC)
    PHP_ME(ViewOptions, groupLevel, ai_ViewOptions_groupLevel, ZEND_ACC_PUBLIC)
    PHP_ME(ViewOptions, range, ai_ViewOptions_range, ZEND_ACC_PUBLIC)
    PHP_ME(ViewOptions, idRange, ai_ViewOptions_idRange, ZEND_ACC_PUBLIC)
    PHP_ME(ViewOptions, raw, ai_ViewOptions_raw, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Bucket, viewQuery)
{
    int rv;
    zend_string *design_doc;
    zend_string *view_name;
    zval *options = NULL;

    rv = zend_parse_parameters(ZEND_NUM_ARGS(), "SS|O!", &design_doc, &view_name, &options,
                               pcbc_view_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    if (obj->type == LCB_BTYPE_EPHEMERAL) {
        throw_pcbc_exception("Ephemeral bucket do not support Couchbase Views", LCB_ERR_INVALID_ARGUMENT);
        RETURN_NULL();
    }

    lcb_CMDVIEW *cmd;
    lcb_cmdview_create(&cmd);
    lcb_cmdview_design_document(cmd, ZSTR_VAL(design_doc), ZSTR_LEN(design_doc));
    lcb_cmdview_view_name(cmd, ZSTR_VAL(view_name), ZSTR_LEN(view_name));
    smart_str query_str = {0}, body_str = {0};
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_view_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdview_timeout(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_view_options_ce, options, ZEND_STRL("include_docs"), 0, &ret);
        switch (Z_TYPE_P(prop)) {
        case IS_TRUE:
            lcb_cmdview_include_docs(cmd, 1);
            break;
        case IS_FALSE:
            lcb_cmdview_include_docs(cmd, 0);
            break;
        }
        prop = zend_read_property(pcbc_view_options_ce, options, ZEND_STRL("max_concurrent_docs"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdview_max_concurrent_docs(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_view_options_ce, options, ZEND_STRL("query"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_ARRAY) {
            php_url_encode_hash_ex(HASH_OF(prop), &query_str, NULL, 0, NULL, 0, NULL, 0, NULL, NULL,
                                        PHP_QUERY_RFC1738);
            if (!PCBC_SMARTSTR_EMPTY(query_str)) {
                lcb_cmdview_option_string(cmd, ZSTR_VAL(query_str.s), ZSTR_LEN(query_str.s));
            }
        }
        prop = zend_read_property(pcbc_view_options_ce, options, ZEND_STRL("body"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_ARRAY) {
            int last_error;
            PCBC_JSON_ENCODE(&body_str, prop, 0, last_error);
            if (last_error != 0) {
                pcbc_log(LOGARGS(obj->conn->lcb, WARN), "Failed to encode query body as JSON: json_last_error=%d",
                         last_error);
            } else {
                smart_str_0(&body_str);
                lcb_cmdview_post_data(cmd, ZSTR_VAL(body_str.s), ZSTR_LEN(body_str.s));
            }
        }
    }

    lcb_cmdview_callback(cmd, viewrow_callback);

    lcb_VIEW_HANDLE *handle = NULL;
    lcb_cmdview_handle(cmd, &handle);

    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(obj->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/view", 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_VIEW);
        lcb_cmdview_parent_span(cmd, span);
    }

    rv = object_init_ex(return_value, pcbc_view_result_impl_ce);
    if (rv != SUCCESS) {
        return;
    }
    zval rows;
    array_init(&rows);
    zend_update_property(pcbc_view_result_impl_ce, return_value, ZEND_STRL("rows"), &rows);
    Z_DELREF(rows);
    struct view_cookie cookie = {LCB_SUCCESS, return_value};
    lcb_STATUS err = lcb_view(obj->conn->lcb, &cookie, cmd);
    smart_str_free(&query_str);
    smart_str_free(&body_str);
    lcb_cmdview_destroy(cmd);
    if (err == LCB_SUCCESS) {
        lcb_wait(obj->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }
    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, NULL);
    }
}

PHP_MINIT_FUNCTION(BucketView)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ViewOptions", pcbc_view_options_methods);
    pcbc_view_options_ce = zend_register_internal_class(&ce);

    zend_declare_property_null(pcbc_view_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_view_options_ce, ZEND_STRL("include_docs"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_view_options_ce, ZEND_STRL("max_concurrent_docs"), ZEND_ACC_PRIVATE);

    zend_declare_property_null(pcbc_view_options_ce, ZEND_STRL("query"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_view_options_ce, ZEND_STRL("body"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ViewScanConsistency", pcbc_view_consistency_methods);
    pcbc_view_consistency_ce = zend_register_internal_interface(&ce);
    zend_declare_class_constant_long(pcbc_view_consistency_ce, ZEND_STRL("NOT_BOUNDED"), 0);
    zend_declare_class_constant_long(pcbc_view_consistency_ce, ZEND_STRL("REQUEST_PLUS"), 1);
    zend_declare_class_constant_long(pcbc_view_consistency_ce, ZEND_STRL("UPDATE_AFTER"), 2);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ViewOrdering", pcbc_view_order_methods);
    pcbc_view_order_ce = zend_register_internal_interface(&ce);
    zend_declare_class_constant_long(pcbc_view_order_ce, ZEND_STRL("ASCENDING"), 0);
    zend_declare_class_constant_long(pcbc_view_order_ce, ZEND_STRL("DESCENDING"), 1);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
