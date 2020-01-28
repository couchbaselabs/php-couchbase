/**
 *     Copyright 2016-2017 Couchbase, Inc.
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
#include "ext/standard/url.h"
#include <ext/standard/php_http.h>

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/view_query", __FILE__, __LINE__

zend_class_entry *pcbc_view_query_ce;

/* {{{ proto ViewQuery::__construct() */
PHP_METHOD(ViewQuery, __construct)
{
    throw_pcbc_exception("Accessing private constructor.", LCB_EINVAL);
}
/* }}} */

void pcbc_view_query_init(zval *return_value, char *design_document, int design_document_len, char *view_name,
                          int view_name_len TSRMLS_DC)
{
    pcbc_view_query_t *obj;

    object_init_ex(return_value, pcbc_view_query_ce);
    obj = Z_VIEW_QUERY_OBJ_P(return_value);
    obj->design_document = estrndup(design_document, design_document_len);
    obj->view_name = estrndup(view_name, view_name_len);
    PCBC_ZVAL_ALLOC(obj->options);
    array_init(PCBC_P(obj->options));
    obj->keys = NULL;
}

/* {{{ proto \Couchbase\ViewQuery ViewQuery::limit(int $limit)
 */
PHP_METHOD(ViewQuery, limit)
{
    pcbc_view_query_t *obj;
    long limit = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &limit);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_VIEW_QUERY_OBJ_P(getThis());
    ADD_ASSOC_LONG_EX(PCBC_P(obj->options), "limit", limit);

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::skip(int $skip)
 */
PHP_METHOD(ViewQuery, skip)
{
    pcbc_view_query_t *obj;
    long skip = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &skip);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_VIEW_QUERY_OBJ_P(getThis());
    ADD_ASSOC_LONG_EX(PCBC_P(obj->options), "skip", skip);

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::from(string $designDocumentName, string $viewName) */
PHP_METHOD(ViewQuery, from)
{
    char *design_document = NULL, *view_name = NULL;
    pcbc_str_arg_size design_document_len = 0, view_name_len = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &design_document, &design_document_len, &view_name,
                               &view_name_len);
    if (rv == FAILURE) {
        return;
    }

    pcbc_view_query_init(return_value, design_document, design_document_len, view_name, view_name_len TSRMLS_CC);
} /* }}} */

/* {{{ proto \Couchbase\SpatialViewQuery ViewQuery::fromSpatial(string $designDocumentName, string $viewName) */
PHP_METHOD(ViewQuery, fromSpatial)
{
    char *design_document = NULL, *view_name = NULL;
    pcbc_str_arg_size design_document_len = 0, view_name_len = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &design_document, &design_document_len, &view_name,
                               &view_name_len);
    if (rv == FAILURE) {
        return;
    }

    pcbc_spatial_view_query_init(return_value, design_document, design_document_len, view_name,
                                 view_name_len TSRMLS_CC);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::consistency(int $consistency)
 */
PHP_METHOD(ViewQuery, consistency)
{
    pcbc_view_query_t *obj;
    long consistency = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &consistency);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_VIEW_QUERY_OBJ_P(getThis());
    switch (consistency) {
    case UPDATE_NONE:
        ADD_ASSOC_STRING(PCBC_P(obj->options), "stale", "ok");
        break;
    case UPDATE_BEFORE:
        ADD_ASSOC_STRING(PCBC_P(obj->options), "stale", "false");
        break;
    case UPDATE_AFTER:
        ADD_ASSOC_STRING(PCBC_P(obj->options), "stale", "update_after");
        break;
    default:
        throw_pcbc_exception("invalid consistency level", LCB_EINVAL);
        RETURN_NULL();
    }

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::order(int $order)
 */
PHP_METHOD(ViewQuery, order)
{
    pcbc_view_query_t *obj;
    long order = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &order);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_VIEW_QUERY_OBJ_P(getThis());
    switch (order) {
    case ORDER_ASCENDING:
        ADD_ASSOC_STRING(PCBC_P(obj->options), "descending", "false");
        break;
    case ORDER_DESCENDING:
        ADD_ASSOC_STRING(PCBC_P(obj->options), "descending", "true");
        break;
    default:
        throw_pcbc_exception("invalid order", LCB_EINVAL);
        RETURN_NULL();
    }

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::includeDocuments(boolean $includeDocuments)
 */
PHP_METHOD(ViewQuery, includeDocuments)
{
    pcbc_view_query_t *obj;
    zend_bool include_docs = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &include_docs);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_VIEW_QUERY_OBJ_P(getThis());
    obj->include_docs = include_docs;
    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::reduce(boolean $reduce)
 */
PHP_METHOD(ViewQuery, reduce)
{
    pcbc_view_query_t *obj;
    zend_bool reduce = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &reduce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_VIEW_QUERY_OBJ_P(getThis());
    if (reduce) {
        ADD_ASSOC_STRING(PCBC_P(obj->options), "reduce", "true");
    } else {
        ADD_ASSOC_STRING(PCBC_P(obj->options), "reduce", "false");
    }

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::group(boolean $group)
 */
PHP_METHOD(ViewQuery, group)
{
    pcbc_view_query_t *obj;
    zend_bool group = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &group);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_VIEW_QUERY_OBJ_P(getThis());
    if (group) {
        ADD_ASSOC_STRING(PCBC_P(obj->options), "group", "true");
    } else {
        ADD_ASSOC_STRING(PCBC_P(obj->options), "group", "false");
    }

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::groupLevel(int $level)
 */
PHP_METHOD(ViewQuery, groupLevel)
{
    pcbc_view_query_t *obj;
    long level = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &level);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_VIEW_QUERY_OBJ_P(getThis());
    ADD_ASSOC_LONG_EX(PCBC_P(obj->options), "group_level", level);

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::key(mixed $key)
 */
PHP_METHOD(ViewQuery, key)
{
    pcbc_view_query_t *obj;
    zval *key = NULL;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &key);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_VIEW_QUERY_OBJ_P(getThis());
    {
        smart_str buf = {0};
        int last_error;

        PCBC_JSON_ENCODE(&buf, key, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(WARN), "Failed to encode key as JSON: json_last_error=%d", last_error);
        } else {
            ADD_ASSOC_STRINGL(PCBC_P(obj->options), "key", PCBC_SMARTSTR_VAL(buf), PCBC_SMARTSTR_LEN(buf));
        }
        smart_str_free(&buf);
    }

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::keys(array $keys)
 */
PHP_METHOD(ViewQuery, keys)
{
    pcbc_view_query_t *obj;
    zval *keys = NULL;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &keys);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_VIEW_QUERY_OBJ_P(getThis());
    {
        PCBC_ZVAL payload;
        smart_str buf = {0};
        int last_error;

        PCBC_ZVAL_ALLOC(payload);
        array_init_size(PCBC_P(payload), 1);
        Z_ADDREF_P(keys);
        ADD_ASSOC_ZVAL_EX(PCBC_P(payload), "keys", keys);
        PCBC_JSON_ENCODE(&buf, PCBC_P(payload), 0, last_error);
        zval_ptr_dtor(&payload);
        if (last_error != 0) {
            pcbc_log(LOGARGS(WARN), "Failed to encode keys as JSON: json_last_error=%d", last_error);
        } else {
            obj->keys_len = PCBC_SMARTSTR_LEN(buf);
            PCBC_SMARTSTR_DUP(buf, obj->keys);
        }
        smart_str_free(&buf);
    }

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::range(mixed $startKey, mixed $endKey, boolean $inclusiveEnd = false)
 */
PHP_METHOD(ViewQuery, range)
{
    pcbc_view_query_t *obj;
    zval *start_key = NULL, *end_key = NULL;
    zend_bool inclusive_end = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|b", &start_key, &end_key, &inclusive_end);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_VIEW_QUERY_OBJ_P(getThis());
    ADD_ASSOC_STRING(PCBC_P(obj->options), "inclusive_end", (inclusive_end) ? "true" : "false");
    {
        smart_str buf = {0};
        int last_error;

        PCBC_JSON_ENCODE(&buf, start_key, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(WARN), "Failed to encode startKey as JSON: json_last_error=%d", last_error);
        } else {
            ADD_ASSOC_STRINGL(PCBC_P(obj->options), "startkey", PCBC_SMARTSTR_VAL(buf), PCBC_SMARTSTR_LEN(buf));
        }
        smart_str_free(&buf);
    }
    {
        smart_str buf = {0};
        int last_error;

        PCBC_JSON_ENCODE(&buf, end_key, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(WARN), "Failed to encode endKey as JSON: json_last_error=%d", last_error);
        } else {
            ADD_ASSOC_STRINGL(PCBC_P(obj->options), "endkey", PCBC_SMARTSTR_VAL(buf), PCBC_SMARTSTR_LEN(buf));
        }
        smart_str_free(&buf);
    }

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::range(string $startKeyDocumentId, string $endKeyDocumentId)
 */
PHP_METHOD(ViewQuery, idRange)
{
    pcbc_view_query_t *obj;
    char *start_id = NULL, *end_id = NULL;
    pcbc_str_arg_size start_id_len = 0, end_id_len = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &start_id, &start_id_len, &end_id, &end_id_len);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_VIEW_QUERY_OBJ_P(getThis());
    ADD_ASSOC_STRINGL(PCBC_P(obj->options), "startkey_docid", start_id, start_id_len);
    ADD_ASSOC_STRINGL(PCBC_P(obj->options), "endkey_docid", end_id, end_id_len);

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::custom(array $options)
 */
PHP_METHOD(ViewQuery, custom)
{
    pcbc_view_query_t *obj;
    zval *custom_options = NULL;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &custom_options);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_VIEW_QUERY_OBJ_P(getThis());

    {
#if PHP_VERSION_ID >= 70000
        HashTable *ht;
        zend_ulong num_key;
        zend_string *string_key = NULL;
        zval *entry;

        ht = HASH_OF(custom_options);
        ZEND_HASH_FOREACH_KEY_VAL(ht, num_key, string_key, entry)
        {
            if (string_key) {
                add_assoc_zval_ex(PCBC_P(obj->options), ZSTR_VAL(string_key), ZSTR_LEN(string_key), entry);
                PCBC_ADDREF_P(entry);
            }
        }
        ZEND_HASH_FOREACH_END();
#else
        HashPosition pos;
        zval **entry;

        zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(custom_options), &pos);
        while (zend_hash_get_current_data_ex(Z_ARRVAL_P(custom_options), (void **)&entry, &pos) == SUCCESS) {
            if (zend_hash_get_current_key_type_ex(Z_ARRVAL_P(custom_options), &pos) == HASH_KEY_IS_STRING) {
                char *key = NULL;
                unsigned key_len = 0;
                zend_hash_get_current_key_ex(Z_ARRVAL_P(custom_options), &key, &key_len, NULL, 0, &pos);
                add_assoc_zval_ex(obj->options, key, key_len, *entry);
                PCBC_ADDREF_P(*entry);
            }
            zend_hash_move_forward_ex(Z_ARRVAL_P(custom_options), &pos);
        }
#endif
    }

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::encode()
 */
PHP_METHOD(ViewQuery, encode)
{
    pcbc_view_query_t *obj;
    int rv;

    rv = zend_parse_parameters_none();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_VIEW_QUERY_OBJ_P(getThis());

    array_init_size(return_value, 5);

    ADD_ASSOC_STRING(return_value, "ddoc", obj->design_document);
    ADD_ASSOC_STRING(return_value, "view", obj->view_name);
    /* ADD_ASSOC_BOOL_EX(return_value, "include_docs", obj->include_docs); */
    {
        smart_str buf = {0};
        rv = php_url_encode_hash_ex(HASH_OF(PCBC_P(obj->options)), &buf, NULL, 0, NULL, 0, NULL, 0, NULL, NULL,
                                    PHP_QUERY_RFC1738 TSRMLS_CC);
        if (rv == FAILURE) {
            pcbc_log(LOGARGS(WARN), "Failed to encode options as RFC1738 query");
        } else {
            if (!PCBC_SMARTSTR_EMPTY(buf)) {
                ADD_ASSOC_STRINGL(return_value, "optstr", PCBC_SMARTSTR_VAL(buf), PCBC_SMARTSTR_LEN(buf));
            }
        }
        smart_str_free(&buf);
    }
    if (obj->keys) {
        ADD_ASSOC_STRINGL(return_value, "postdata", obj->keys, obj->keys_len);
    }
} /* }}} */

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_from, 0, 0, 2)
ZEND_ARG_INFO(0, designDocumentName)
ZEND_ARG_INFO(0, viewName)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_skip, 0, 0, 1)
ZEND_ARG_INFO(0, skip)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_limit, 0, 0, 1)
ZEND_ARG_INFO(0, limit)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_consistency, 0, 0, 1)
ZEND_ARG_INFO(0, consistency)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_custom, 0, 0, 1)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_order, 0, 0, 1)
ZEND_ARG_INFO(0, order)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_reduce, 0, 0, 1)
ZEND_ARG_INFO(0, reduce)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_group, 0, 0, 1)
ZEND_ARG_INFO(0, group)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_groupLevel, 0, 0, 1)
ZEND_ARG_INFO(0, group_level)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_key, 0, 0, 1)
ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_keys, 0, 0, 1)
ZEND_ARG_INFO(0, keys)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_range, 0, 0, 3)
ZEND_ARG_INFO(0, startKey)
ZEND_ARG_INFO(0, endKey)
ZEND_ARG_INFO(0, inclusiveEnd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_idRange, 0, 0, 2)
ZEND_ARG_INFO(0, startKeyDocumentId)
ZEND_ARG_INFO(0, endKeyDocumentId)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_includeDocuments, 0, 0, 1)
ZEND_ARG_INFO(0, includeDocuments)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewQuery_encode, 0, 0, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry view_query_methods[] = {
    PHP_ME(ViewQuery, __construct, ai_ViewQuery_none, ZEND_ACC_PRIVATE | ZEND_ACC_FINAL | ZEND_ACC_CTOR)
    PHP_ME(ViewQuery, from, ai_ViewQuery_from, ZEND_ACC_STATIC | ZEND_ACC_PUBLIC)
    PHP_ME(ViewQuery, fromSpatial, ai_ViewQuery_from, ZEND_ACC_STATIC | ZEND_ACC_PUBLIC)
    PHP_ME(ViewQuery, encode, ai_ViewQuery_none, ZEND_ACC_PUBLIC)
    PHP_ME(ViewQuery, limit, ai_ViewQuery_limit, ZEND_ACC_PUBLIC)
    PHP_ME(ViewQuery, skip, ai_ViewQuery_skip, ZEND_ACC_PUBLIC)
    PHP_ME(ViewQuery, consistency, ai_ViewQuery_consistency, ZEND_ACC_PUBLIC)
    PHP_MALIAS(ViewQuery, stale, consistency, ai_ViewQuery_consistency, ZEND_ACC_PUBLIC) // ZEND_ACC_DEPRECATED
    PHP_ME(ViewQuery, custom, ai_ViewQuery_custom, ZEND_ACC_PUBLIC)
    PHP_ME(ViewQuery, order, ai_ViewQuery_order, ZEND_ACC_PUBLIC)
    PHP_ME(ViewQuery, reduce, ai_ViewQuery_reduce, ZEND_ACC_PUBLIC)
    PHP_ME(ViewQuery, group, ai_ViewQuery_group, ZEND_ACC_PUBLIC)
    PHP_ME(ViewQuery, groupLevel, ai_ViewQuery_groupLevel, ZEND_ACC_PUBLIC)
    PHP_MALIAS(ViewQuery, group_level, groupLevel, ai_ViewQuery_groupLevel, ZEND_ACC_PUBLIC) // ZEND_ACC_DEPRECATED
    PHP_ME(ViewQuery, key, ai_ViewQuery_key, ZEND_ACC_PUBLIC)
    PHP_ME(ViewQuery, keys, ai_ViewQuery_keys, ZEND_ACC_PUBLIC)
    PHP_ME(ViewQuery, range, ai_ViewQuery_range, ZEND_ACC_PUBLIC)
    PHP_ME(ViewQuery, idRange, ai_ViewQuery_idRange, ZEND_ACC_PUBLIC)
    PHP_MALIAS(ViewQuery, id_range, idRange, ai_ViewQuery_idRange, ZEND_ACC_PUBLIC) // ZEND_ACC_DEPRECATED
    /* PHP_ME(ViewQuery, includeDocuments, ai_ViewQuery_includeDocuments, ZEND_ACC_PUBLIC) */
    PHP_FE_END
};
// clang-format on

zend_object_handlers view_query_handlers;

static void view_query_free_object(pcbc_free_object_arg *object TSRMLS_DC) /* {{{ */
{
    pcbc_view_query_t *obj = Z_VIEW_QUERY_OBJ(object);

    if (obj->design_document != NULL) {
        efree(obj->design_document);
    }
    if (obj->view_name != NULL) {
        efree(obj->view_name);
    }
    if (obj->keys != NULL) {
        efree(obj->keys);
    }
    if (!Z_ISUNDEF(obj->options)) {
        zval_ptr_dtor(&obj->options);
        ZVAL_UNDEF(PCBC_P(obj->options));
    }

    zend_object_std_dtor(&obj->std TSRMLS_CC);
#if PHP_VERSION_ID < 70000
    efree(obj);
#endif
} /* }}} */

static pcbc_create_object_retval view_query_create_object(zend_class_entry *class_type TSRMLS_DC)
{
    pcbc_view_query_t *obj = NULL;

    obj = PCBC_ALLOC_OBJECT_T(pcbc_view_query_t, class_type);

    zend_object_std_init(&obj->std, class_type TSRMLS_CC);
    object_properties_init(&obj->std, class_type);

#if PHP_VERSION_ID >= 70000
    obj->std.handlers = &view_query_handlers;
    return &obj->std;
#else
    {
        zend_object_value ret;
        ret.handle = zend_objects_store_put(obj, (zend_objects_store_dtor_t)zend_objects_destroy_object,
                                            view_query_free_object, NULL TSRMLS_CC);
        ret.handlers = &view_query_handlers;
        return ret;
    }
#endif
}

static HashTable *pcbc_view_query_get_debug_info(zval *object, int *is_temp TSRMLS_DC) /* {{{ */
{
    pcbc_view_query_t *obj = NULL;
#if PHP_VERSION_ID >= 70000
    zval retval;
#else
    zval retval = zval_used_for_init;
#endif

    *is_temp = 1;
    obj = Z_VIEW_QUERY_OBJ_P(object);

    array_init(&retval);
    ADD_ASSOC_STRING(&retval, "designDocumentName", obj->design_document);
    ADD_ASSOC_STRING(&retval, "viewName", obj->view_name);
    /* ADD_ASSOC_BOOL_EX(&retval, "includeDocuments", obj->include_docs); */
    if (obj->keys_len) {
        ADD_ASSOC_STRINGL(&retval, "keys", obj->keys, obj->keys_len);
    }
    if (!Z_ISUNDEF(obj->options)) {
        ADD_ASSOC_ZVAL_EX(&retval, "options", PCBC_P(obj->options));
        PCBC_ADDREF_P(PCBC_P(obj->options));
    }

    return Z_ARRVAL(retval);
} /* }}} */

PHP_MINIT_FUNCTION(ViewQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ViewQuery", view_query_methods);
    pcbc_view_query_ce = zend_register_internal_class(&ce TSRMLS_CC);
    pcbc_view_query_ce->create_object = view_query_create_object;
    PCBC_CE_DISABLE_SERIALIZATION(pcbc_view_query_ce);

    zend_declare_class_constant_long(pcbc_view_query_ce, ZEND_STRL("UPDATE_BEFORE"), UPDATE_BEFORE TSRMLS_CC);
    zend_declare_class_constant_long(pcbc_view_query_ce, ZEND_STRL("UPDATE_NONE"), UPDATE_NONE TSRMLS_CC);
    zend_declare_class_constant_long(pcbc_view_query_ce, ZEND_STRL("UPDATE_AFTER"), UPDATE_AFTER TSRMLS_CC);

    zend_declare_class_constant_long(pcbc_view_query_ce, ZEND_STRL("ORDER_ASCENDING"), ORDER_ASCENDING TSRMLS_CC);
    zend_declare_class_constant_long(pcbc_view_query_ce, ZEND_STRL("ORDER_DESCENDING"), ORDER_DESCENDING TSRMLS_CC);

    zend_class_implements(pcbc_view_query_ce TSRMLS_CC, 1, pcbc_view_query_encodable_ce);

    memcpy(&view_query_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    view_query_handlers.get_debug_info = pcbc_view_query_get_debug_info;
#if PHP_VERSION_ID >= 70000
    view_query_handlers.free_obj = view_query_free_object;
    view_query_handlers.offset = XtOffsetOf(pcbc_view_query_t, std);
#endif

    zend_register_class_alias("\\CouchbaseViewQuery", pcbc_view_query_ce);
    return SUCCESS;
}
