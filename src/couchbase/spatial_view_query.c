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
#include <ext/standard/php_http.h>
#include <ext/standard/php_string.h>
#include <ext/standard/url.h>

#if PHP_VERSION_ID >= 70000
static inline pcbc_spatial_view_query_t *pcbc_spatial_view_query_fetch_object(zend_object *obj)
{
    return (pcbc_spatial_view_query_t *)((char *)obj - XtOffsetOf(pcbc_spatial_view_query_t, std));
}
#define Z_SPATIAL_VIEW_QUERY_OBJ(zo) (pcbc_spatial_view_query_fetch_object(zo))
#define Z_SPATIAL_VIEW_QUERY_OBJ_P(zv) (pcbc_spatial_view_query_fetch_object(Z_OBJ_P(zv)))
#else
#define Z_SPATIAL_VIEW_QUERY_OBJ(zo) ((pcbc_spatial_view_query_t *)zo)
#define Z_SPATIAL_VIEW_QUERY_OBJ_P(zv) ((pcbc_spatial_view_query_t *)zend_object_store_get_object(zv TSRMLS_CC))
#endif

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/spatial_view_query", __FILE__, __LINE__

zend_class_entry *pcbc_spatial_view_query_ce;

/* {{{ proto SpatialViewQuery::__construct() */
PHP_METHOD(SpatialViewQuery, __construct)
{
    throw_pcbc_exception("Accessing private constructor.", LCB_EINVAL);
}
/* }}} */

void pcbc_spatial_view_query_init(zval *return_value, char *design_document, int design_document_len, char *view_name,
                                  int view_name_len TSRMLS_DC)
{
    pcbc_spatial_view_query_t *obj;

    object_init_ex(return_value, pcbc_spatial_view_query_ce);
    obj = Z_SPATIAL_VIEW_QUERY_OBJ_P(return_value);
    obj->design_document = estrndup(design_document, design_document_len);
    obj->view_name = estrndup(view_name, view_name_len);
    PCBC_ZVAL_ALLOC(obj->options);
    array_init(PCBC_P(obj->options));
}

/* {{{ proto \Couchbase\SpatialViewQuery SpatialViewQuery::limit(int $limit)
 */
PHP_METHOD(SpatialViewQuery, limit)
{
    pcbc_spatial_view_query_t *obj;
    long limit = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &limit);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_SPATIAL_VIEW_QUERY_OBJ_P(getThis());
    ADD_ASSOC_LONG_EX(PCBC_P(obj->options), "limit", limit);

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\SpatialViewQuery SpatialViewQuery::skip(int $skip)
 */
PHP_METHOD(SpatialViewQuery, skip)
{
    pcbc_spatial_view_query_t *obj;
    long skip = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &skip);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_SPATIAL_VIEW_QUERY_OBJ_P(getThis());
    ADD_ASSOC_LONG_EX(PCBC_P(obj->options), "skip", skip);

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\SpatialViewQuery SpatialViewQuery::bbox(array $bbox)
 */
PHP_METHOD(SpatialViewQuery, bbox)
{
    pcbc_spatial_view_query_t *obj;
    zval *bbox;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &bbox);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_SPATIAL_VIEW_QUERY_OBJ_P(getThis());
    {
#if PHP_VERSION_ID >= 70000
        zend_string *delim;
        ALLOCA_FLAG(use_heap);
#else
        PCBC_ZVAL delim;
#endif
        PCBC_ZVAL res;

        PCBC_ZVAL_ALLOC(res);
#if PHP_VERSION_ID >= 70000
        ZSTR_ALLOCA_ALLOC(delim, 1, use_heap);
        ZSTR_VAL(delim)[0] = ',';
        ZSTR_VAL(delim)[1] = '\0';
#else
        PCBC_ZVAL_ALLOC(delim);
        PCBC_STRINGL(delim, ",", 1);
#endif

        php_implode(delim, bbox, PCBC_P(res) TSRMLS_CC);
        ADD_ASSOC_STRINGL(PCBC_P(obj->options), "bbox", Z_STRVAL_P(PCBC_P(res)), Z_STRLEN_P(PCBC_P(res)));
#if PHP_VERSION_ID >= 70000
        ZSTR_ALLOCA_FREE(delim, use_heap);
#else
        zval_ptr_dtor(&delim);
#endif
        zval_ptr_dtor(&res);
    }

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::startRange(array $range)
 */
PHP_METHOD(SpatialViewQuery, startRange)
{
    pcbc_spatial_view_query_t *obj;
    zval *range = NULL;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &range);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_SPATIAL_VIEW_QUERY_OBJ_P(getThis());
    {
        smart_str buf = {0};
        int last_error;

        PCBC_JSON_ENCODE(&buf, range, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(WARN), "Failed to encode start range as JSON: json_last_error=%d", last_error);
        } else {
            ADD_ASSOC_STRINGL(PCBC_P(obj->options), "start_range", PCBC_SMARTSTR_VAL(buf), PCBC_SMARTSTR_LEN(buf));
        }
        smart_str_free(&buf);
    }

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\ViewQuery ViewQuery::endRange(array $range)
 */
PHP_METHOD(SpatialViewQuery, endRange)
{
    pcbc_spatial_view_query_t *obj;
    zval *range = NULL;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &range);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_SPATIAL_VIEW_QUERY_OBJ_P(getThis());
    {
        smart_str buf = {0};
        int last_error;

        PCBC_JSON_ENCODE(&buf, range, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(WARN), "Failed to encode end range as JSON: json_last_error=%d", last_error);
        } else {
            ADD_ASSOC_STRINGL(PCBC_P(obj->options), "end_range", PCBC_SMARTSTR_VAL(buf), PCBC_SMARTSTR_LEN(buf));
        }
        smart_str_free(&buf);
    }

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\SpatialViewQuery SpatialViewQuery::from(string $designDocumentName, string $viewName) */
PHP_METHOD(SpatialViewQuery, from)
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

/* {{{ proto \Couchbase\SpatialViewQuery SpatialViewQuery::consistency(int $consistency)
 */
PHP_METHOD(SpatialViewQuery, consistency)
{
    pcbc_spatial_view_query_t *obj;
    long consistency = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &consistency);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_SPATIAL_VIEW_QUERY_OBJ_P(getThis());
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

/* {{{ proto \Couchbase\SpatialViewQuery SpatialViewQuery::includeDocuments(boolean $includeDocuments)
 */
PHP_METHOD(SpatialViewQuery, includeDocuments)
{
    pcbc_spatial_view_query_t *obj;
    zend_bool include_docs = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &include_docs);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_SPATIAL_VIEW_QUERY_OBJ_P(getThis());
    obj->include_docs = include_docs;
    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\SpatialViewQuery SpatialViewQuery::custom(array $options)
 */
PHP_METHOD(SpatialViewQuery, custom)
{
    pcbc_spatial_view_query_t *obj;
    zval *custom_options = NULL;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &custom_options);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_SPATIAL_VIEW_QUERY_OBJ_P(getThis());

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

/* {{{ proto \Couchbase\SpatialViewQuery SpatialViewQuery::encode()
 */
PHP_METHOD(SpatialViewQuery, encode)
{
    pcbc_spatial_view_query_t *obj;
    int rv;

    rv = zend_parse_parameters_none();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_SPATIAL_VIEW_QUERY_OBJ_P(getThis());

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
} /* }}} */

ZEND_BEGIN_ARG_INFO_EX(ai_SpatialViewQuery_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SpatialViewQuery_from, 0, 0, 2)
ZEND_ARG_INFO(0, designDocumentName)
ZEND_ARG_INFO(0, viewName)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SpatialViewQuery_skip, 0, 0, 1)
ZEND_ARG_INFO(0, skip)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SpatialViewQuery_limit, 0, 0, 1)
ZEND_ARG_INFO(0, limit)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SpatialViewQuery_consistency, 0, 0, 1)
ZEND_ARG_INFO(0, consistency)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SpatialViewQuery_bbox, 0, 0, 1)
ZEND_ARG_INFO(0, bbox)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SpatialViewQuery_range, 0, 0, 1)
ZEND_ARG_INFO(0, range)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SpatialViewQuery_custom, 0, 0, 1)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SpatialViewQuery_includeDocuments, 0, 0, 1)
ZEND_ARG_INFO(0, includeDocuments)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SpatialViewQuery_encode, 0, 0, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry spatial_view_query_methods[] = {
    PHP_ME(SpatialViewQuery, __construct, ai_SpatialViewQuery_none, ZEND_ACC_PRIVATE | ZEND_ACC_FINAL | ZEND_ACC_CTOR)
    PHP_ME(SpatialViewQuery, from, ai_SpatialViewQuery_from, ZEND_ACC_STATIC | ZEND_ACC_PUBLIC)
    PHP_ME(SpatialViewQuery, encode, ai_SpatialViewQuery_none, ZEND_ACC_PUBLIC)
    PHP_ME(SpatialViewQuery, limit, ai_SpatialViewQuery_limit, ZEND_ACC_PUBLIC)
    PHP_ME(SpatialViewQuery, skip, ai_SpatialViewQuery_skip, ZEND_ACC_PUBLIC)
    PHP_ME(SpatialViewQuery, consistency, ai_SpatialViewQuery_consistency, ZEND_ACC_PUBLIC)
    PHP_MALIAS(SpatialViewQuery, stale, consistency, ai_SpatialViewQuery_consistency, ZEND_ACC_PUBLIC) // ZEND_ACC_DEPRECATED
    PHP_ME(SpatialViewQuery, bbox, ai_SpatialViewQuery_bbox, ZEND_ACC_PUBLIC)
    PHP_ME(SpatialViewQuery, startRange, ai_SpatialViewQuery_range, ZEND_ACC_PUBLIC)
    PHP_ME(SpatialViewQuery, endRange, ai_SpatialViewQuery_range, ZEND_ACC_PUBLIC)
    PHP_ME(SpatialViewQuery, custom, ai_SpatialViewQuery_custom, ZEND_ACC_PUBLIC)
    /* PHP_ME(SpatialViewQuery, includeDocuments, ai_SpatialViewQuery_includeDocuments, ZEND_ACC_PUBLIC) */
    PHP_FE_END
};
// clang-format on

zend_object_handlers spatial_view_query_handlers;

static void spatial_view_query_free_object(pcbc_free_object_arg *object TSRMLS_DC) /* {{{ */
{
    pcbc_spatial_view_query_t *obj = Z_SPATIAL_VIEW_QUERY_OBJ(object);

    if (obj->design_document != NULL) {
        efree(obj->design_document);
    }
    if (obj->view_name != NULL) {
        efree(obj->view_name);
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

static pcbc_create_object_retval spatial_view_query_create_object(zend_class_entry *class_type TSRMLS_DC)
{
    pcbc_spatial_view_query_t *obj = NULL;

    obj = PCBC_ALLOC_OBJECT_T(pcbc_spatial_view_query_t, class_type);

    zend_object_std_init(&obj->std, class_type TSRMLS_CC);
    object_properties_init(&obj->std, class_type);

#if PHP_VERSION_ID >= 70000
    obj->std.handlers = &spatial_view_query_handlers;
    return &obj->std;
#else
    {
        zend_object_value ret;
        ret.handle = zend_objects_store_put(obj, (zend_objects_store_dtor_t)zend_objects_destroy_object,
                                            spatial_view_query_free_object, NULL TSRMLS_CC);
        ret.handlers = &spatial_view_query_handlers;
        return ret;
    }
#endif
}

static HashTable *pcbc_spatial_view_query_get_debug_info(zval *object, int *is_temp TSRMLS_DC) /* {{{ */
{
    pcbc_spatial_view_query_t *obj = NULL;
#if PHP_VERSION_ID >= 70000
    zval retval;
#else
    zval retval = zval_used_for_init;
#endif

    *is_temp = 1;
    obj = Z_SPATIAL_VIEW_QUERY_OBJ_P(object);

    array_init(&retval);
    ADD_ASSOC_STRING(&retval, "designDocumentName", obj->design_document);
    ADD_ASSOC_STRING(&retval, "viewName", obj->view_name);
    /* ADD_ASSOC_BOOL_EX(&retval, "includeDocuments", obj->include_docs); */
    if (!Z_ISUNDEF(obj->options)) {
        ADD_ASSOC_ZVAL_EX(&retval, "options", PCBC_P(obj->options));
        PCBC_ADDREF_P(PCBC_P(obj->options));
    }

    return Z_ARRVAL(retval);
} /* }}} */

PHP_MINIT_FUNCTION(SpatialViewQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SpatialViewQuery", spatial_view_query_methods);
    pcbc_spatial_view_query_ce = zend_register_internal_class(&ce TSRMLS_CC);
    pcbc_spatial_view_query_ce->create_object = spatial_view_query_create_object;
    PCBC_CE_DISABLE_SERIALIZATION(pcbc_spatial_view_query_ce);

    zend_class_implements(pcbc_spatial_view_query_ce TSRMLS_CC, 1, pcbc_view_query_encodable_ce);

    memcpy(&spatial_view_query_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    spatial_view_query_handlers.get_debug_info = pcbc_spatial_view_query_get_debug_info;
#if PHP_VERSION_ID >= 70000
    spatial_view_query_handlers.free_obj = spatial_view_query_free_object;
    spatial_view_query_handlers.offset = XtOffsetOf(pcbc_spatial_view_query_t, std);
#endif
    return SUCCESS;
}
