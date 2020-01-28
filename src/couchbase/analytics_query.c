/**
 *     Copyright 2017 Couchbase, Inc.
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
#include <Zend/zend_alloc.h>

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/analytics_query", __FILE__, __LINE__

zend_class_entry *pcbc_analytics_query_ce;

/* {{{ proto void AnalyticsQuery::__construct() Should not be called directly */
PHP_METHOD(AnalyticsQuery, __construct)
{
    throw_pcbc_exception("Accessing private constructor.", LCB_EINVAL);
}
/* }}} */

/* {{{ proto \Couchbase\AnalyticsQuery AnalyticsQuery::fromString(string $statement) */
PHP_METHOD(AnalyticsQuery, fromString)
{
    char *statement = NULL;
    pcbc_str_arg_size statement_len = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &statement, &statement_len);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_analytics_query_init(return_value, statement, statement_len TSRMLS_CC);
} /* }}} */

PHP_METHOD(AnalyticsQuery, rawParam)
{
    zval *value;
    zval *options;
    char *name = NULL;
    pcbc_str_arg_size name_len = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &name, &name_len, &value);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    PCBC_READ_PROPERTY(options, pcbc_analytics_query_ce, getThis(), "options", 0);
    PCBC_ADDREF_P(value);
    add_assoc_zval_ex(options, name, name_len, value);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AnalyticsQuery, positionalParams)
{
    zval *params;
    zval *options;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &params);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    PCBC_READ_PROPERTY(options, pcbc_analytics_query_ce, getThis(), "options", 0);
    PCBC_ADDREF_P(params);
    add_assoc_zval(options, "args", params);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AnalyticsQuery, namedParams)
{
    zval *params;
    zval *options;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &params);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    PCBC_READ_PROPERTY(options, pcbc_analytics_query_ce, getThis(), "options", 0);
    {
#if PHP_VERSION_ID >= 70000
        HashTable *ht;
        zend_ulong num_key;
        zend_string *string_key = NULL;
        zval *entry;

        ht = HASH_OF(params);
        ZEND_HASH_FOREACH_KEY_VAL(ht, num_key, string_key, entry)
        {
            if (string_key) {
                char *prefixed_key = NULL;
                spprintf(&prefixed_key, 0, "$%s", ZSTR_VAL(string_key));
                add_assoc_zval(options, prefixed_key, entry);
                PCBC_ADDREF_P(entry);
                efree(prefixed_key);
            }
        }
        ZEND_HASH_FOREACH_END();
#else
        HashPosition pos;
        zval **entry;

        zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(params), &pos);
        while (zend_hash_get_current_data_ex(Z_ARRVAL_P(params), (void **)&entry, &pos) == SUCCESS) {
            if (zend_hash_get_current_key_type_ex(Z_ARRVAL_P(params), &pos) == HASH_KEY_IS_STRING) {
                char *key = NULL, *prefixed_key = NULL;
                unsigned key_len = 0;
                zend_hash_get_current_key_ex(Z_ARRVAL_P(params), &key, &key_len, NULL, 0, &pos);
                spprintf(&prefixed_key, 0, "$%s", key);
                add_assoc_zval(options, prefixed_key, *entry);
                PCBC_ADDREF_P(*entry);
                efree(prefixed_key);
            }
            zend_hash_move_forward_ex(Z_ARRVAL_P(params), &pos);
        }
#endif
    }
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsQuery_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsQuery_fromString, 0, 0, 1)
ZEND_ARG_INFO(0, statement)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsQuery_params, 0, 0, 1)
ZEND_ARG_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsQuery_rawParam, 0, 0, 2)
ZEND_ARG_INFO(0, name)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry analytics_query_methods[] = {
    PHP_ME(AnalyticsQuery, __construct, ai_AnalyticsQuery_none, ZEND_ACC_PRIVATE | ZEND_ACC_FINAL | ZEND_ACC_CTOR)
    PHP_ME(AnalyticsQuery, fromString, ai_AnalyticsQuery_fromString, ZEND_ACC_STATIC | ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsQuery, positionalParams, ai_AnalyticsQuery_params, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsQuery, namedParams, ai_AnalyticsQuery_params, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsQuery, rawParam, ai_AnalyticsQuery_rawParam, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

zend_object_handlers pcbc_analytics_query_handlers;

void pcbc_analytics_query_init(zval *return_value, const char *statement, int statement_len TSRMLS_DC)
{
    pcbc_analytics_query_t *query;
    PCBC_ZVAL options;

    object_init_ex(return_value, pcbc_analytics_query_ce);
    query = Z_ANALYTICS_QUERY_OBJ_P(return_value);

    PCBC_ZVAL_ALLOC(options);
    array_init(PCBC_P(options));
    ADD_ASSOC_STRINGL(PCBC_P(options), "statement", statement, statement_len);
    zend_update_property(pcbc_analytics_query_ce, return_value, ZEND_STRL("options"), PCBC_P(options) TSRMLS_CC);
    zval_ptr_dtor(&options);
}

static void analytics_query_free_object(pcbc_free_object_arg *object TSRMLS_DC) /* {{{ */
{
    pcbc_analytics_query_t *obj = Z_ANALYTICS_QUERY_OBJ(object);

    zend_object_std_dtor(&obj->std TSRMLS_CC);
#if PHP_VERSION_ID < 70000
    efree(obj);
#endif
} /* }}} */

static pcbc_create_object_retval analytics_query_create_object(zend_class_entry *class_type TSRMLS_DC)
{
    pcbc_analytics_query_t *obj = NULL;

    obj = PCBC_ALLOC_OBJECT_T(pcbc_analytics_query_t, class_type);

    zend_object_std_init(&obj->std, class_type TSRMLS_CC);
    object_properties_init(&obj->std, class_type);

#if PHP_VERSION_ID >= 70000
    obj->std.handlers = &pcbc_analytics_query_handlers;
    return &obj->std;
#else
    {
        zend_object_value ret;
        ret.handle = zend_objects_store_put(obj, (zend_objects_store_dtor_t)zend_objects_destroy_object,
                                            analytics_query_free_object, NULL TSRMLS_CC);
        ret.handlers = &pcbc_analytics_query_handlers;
        return ret;
    }
#endif
}

static HashTable *analytics_query_get_debug_info(zval *object, int *is_temp TSRMLS_DC) /* {{{ */
{
    pcbc_analytics_query_t *obj = NULL;
#if PHP_VERSION_ID >= 70000
    zval retval;
#else
    zval retval = zval_used_for_init;
#endif
    zval *options;

    *is_temp = 1;
    obj = Z_ANALYTICS_QUERY_OBJ_P(object);

    array_init(&retval);
    PCBC_READ_PROPERTY(options, pcbc_analytics_query_ce, object, "options", 0);
    PCBC_ADDREF_P(options);
    add_assoc_zval(&retval, "options", options);

    return Z_ARRVAL(retval);
} /* }}} */

PHP_MINIT_FUNCTION(AnalyticsQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "AnalyticsQuery", analytics_query_methods);
    pcbc_analytics_query_ce = zend_register_internal_class(&ce TSRMLS_CC);
    pcbc_analytics_query_ce->create_object = analytics_query_create_object;
    PCBC_CE_DISABLE_SERIALIZATION(pcbc_analytics_query_ce);

    memcpy(&pcbc_analytics_query_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    pcbc_analytics_query_handlers.get_debug_info = analytics_query_get_debug_info;
#if PHP_VERSION_ID >= 70000
    pcbc_analytics_query_handlers.free_obj = analytics_query_free_object;
    pcbc_analytics_query_handlers.offset = XtOffsetOf(pcbc_analytics_query_t, std);
#endif
    zend_declare_property_null(pcbc_analytics_query_ce, ZEND_STRL("options"), ZEND_ACC_PUBLIC TSRMLS_CC);
    return SUCCESS;
}
