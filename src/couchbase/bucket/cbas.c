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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/cbas", __FILE__, __LINE__

extern zend_class_entry *pcbc_analytics_result_impl_ce;
extern zend_class_entry *pcbc_query_meta_data_impl_ce;
zend_class_entry *pcbc_analytics_options_ce;

struct query_cookie {
    lcb_STATUS rc;
    zval *return_value;
};

static void analytics_callback(lcb_INSTANCE *instance, int ignoreme, const lcb_RESPANALYTICS *resp)
{
    TSRMLS_FETCH();

    struct query_cookie *cookie;
    lcb_respanalytics_cookie(resp, (void **)&cookie);
    cookie->rc = lcb_respanalytics_status(resp);
    zval *return_value = cookie->return_value;

    zend_update_property_long(pcbc_analytics_result_impl_ce, return_value, ZEND_STRL("status"), cookie->rc TSRMLS_CC);

    const char *row = NULL;
    size_t nrow = 0;
    lcb_respanalytics_row(resp, &row, &nrow);

    if (nrow > 0) {
        zval value;
        ZVAL_NULL(&value);

        int last_error;
        PCBC_JSON_COPY_DECODE(&value, row, nrow, PHP_JSON_OBJECT_AS_ARRAY, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(instance, WARN), "Failed to decode N1QL response as JSON: json_last_error=%d", last_error);
        }

        if (lcb_respanalytics_is_final(resp)) {
            zval meta, *mval;
            object_init_ex(&meta, pcbc_query_meta_data_impl_ce);
            HashTable *marr = Z_ARRVAL(value);

            mval = zend_symtable_str_find(marr, ZEND_STRL("status"));
            if (mval) {
                zend_update_property(pcbc_query_meta_data_impl_ce, &meta, ZEND_STRL("status"), mval TSRMLS_CC);
            }
            mval = zend_symtable_str_find(marr, ZEND_STRL("requestID"));
            if (mval) {
                zend_update_property(pcbc_query_meta_data_impl_ce, &meta, ZEND_STRL("request_id"), mval TSRMLS_CC);
            }
            mval = zend_symtable_str_find(marr, ZEND_STRL("clientContextID"));
            if (mval) {
                zend_update_property(pcbc_query_meta_data_impl_ce, &meta, ZEND_STRL("client_context_id"),
                                     mval TSRMLS_CC);
            }
            mval = zend_symtable_str_find(marr, ZEND_STRL("signature"));
            if (mval) {
                zend_update_property(pcbc_query_meta_data_impl_ce, &meta, ZEND_STRL("signature"), mval TSRMLS_CC);
            }
            mval = zend_symtable_str_find(marr, ZEND_STRL("errors"));
            if (mval) {
                zend_update_property(pcbc_query_meta_data_impl_ce, &meta, ZEND_STRL("errors"), mval TSRMLS_CC);
            }
            mval = zend_symtable_str_find(marr, ZEND_STRL("warnings"));
            if (mval) {
                zend_update_property(pcbc_query_meta_data_impl_ce, &meta, ZEND_STRL("warnings"), mval TSRMLS_CC);
            }
            mval = zend_symtable_str_find(marr, ZEND_STRL("metrics"));
            if (mval) {
                zend_update_property(pcbc_query_meta_data_impl_ce, &meta, ZEND_STRL("metrics"), mval TSRMLS_CC);
            }
            zend_update_property(pcbc_analytics_result_impl_ce, return_value, ZEND_STRL("meta"), &meta TSRMLS_CC);
            zval_ptr_dtor(&meta);
            zval_dtor(&value);
        } else {
            zval *rows, rv;
            rows = zend_read_property(pcbc_analytics_result_impl_ce, return_value, ZEND_STRL("rows"), 0, &rv);
            add_next_index_zval(rows, &value);
        }
    }
}

PHP_METHOD(AnalyticsOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_long(pcbc_analytics_options_ce, getThis(), ZEND_STRL("timeout"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AnalyticsOptions, namedParameters)
{
    zval *arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval params;
    array_init(&params);
    HashTable *ht = HASH_OF(arg);
    zend_string *string_key = NULL;
    zval *entry;
    ZEND_HASH_FOREACH_STR_KEY_VAL(ht, string_key, entry)
    {
        if (string_key) {
            smart_str buf = {0};
            int last_error;
            PCBC_JSON_ENCODE(&buf, entry, 0, last_error);
            if (last_error != 0) {
                pcbc_log(LOGARGS(NULL, WARN), "Failed to encode value of parameter '%.*s' as JSON: json_last_error=%d",
                         (int)ZSTR_LEN(string_key), ZSTR_VAL(string_key), last_error);
                smart_str_free(&buf);
                continue;
            }
            smart_str_0(&buf);
            add_assoc_str_ex(&params, ZSTR_VAL(string_key), ZSTR_LEN(string_key), buf.s TSRMLS_CC);
        }
    }
    ZEND_HASH_FOREACH_END();
    zend_update_property(pcbc_analytics_options_ce, getThis(), ZEND_STRL("named_params"), &params TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AnalyticsOptions, positionalParameters)
{
    zval *arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval params;
    array_init(&params);
    HashTable *ht = HASH_OF(arg);
    zval *entry;
    ZEND_HASH_FOREACH_VAL(ht, entry)
    {
        smart_str buf = {0};
        int last_error;
        PCBC_JSON_ENCODE(&buf, entry, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(NULL, WARN), "Failed to encode value of positional parameter as JSON: json_last_error=%d",
                     last_error);
            smart_str_free(&buf);
            RETURN_NULL();
        } else {
            smart_str_0(&buf);
            add_next_index_str(&params, buf.s TSRMLS_CC);
        }
    }
    ZEND_HASH_FOREACH_END();
    zend_update_property(pcbc_analytics_options_ce, getThis(), ZEND_STRL("positional_params"), &params TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AnalyticsOptions, raw)
{
    zend_string *key;
    zval *value = NULL;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Sz!", &key, &value);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1;
    data = zend_read_property(pcbc_analytics_options_ce, getThis(), ZEND_STRL("raw_params"), 0, &rv1);
    if (Z_TYPE_P(data) == IS_NULL) {
        array_init(&rv1);
        data = &rv1;
        zend_update_property(pcbc_analytics_options_ce, getThis(), ZEND_STRL("raw_params"), data TSRMLS_CC);
    }
    smart_str buf = {0};
    int last_error;
    PCBC_JSON_ENCODE(&buf, value, 0, last_error);
    if (last_error != 0) {
        pcbc_log(LOGARGS(NULL, WARN), "Failed to encode value of raw parameter as JSON: json_last_error=%d",
                 last_error);
        smart_str_free(&buf);
        RETURN_NULL();
    }
    smart_str_0(&buf);
    add_assoc_str_ex(data, ZSTR_VAL(key), ZSTR_LEN(key), buf.s TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AnalyticsOptions, clientContextId)
{
    zend_string *arg;
    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_str(pcbc_analytics_options_ce, getThis(), ZEND_STRL("client_context_id"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AnalyticsOptions, scanConsistency)
{
    zend_string *arg;
    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_str(pcbc_analytics_options_ce, getThis(), ZEND_STRL("scan_consistency"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AnalyticsOptions, priority)
{
    zend_bool arg;
    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_bool(pcbc_analytics_options_ce, getThis(), ZEND_STRL("priority"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AnalyticsOptions, readonly)
{
    zend_bool arg;
    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_bool(pcbc_analytics_options_ce, getThis(), ZEND_STRL("readonly"), arg TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AnalyticsOptions_timeout, 0, 1, Couchbase\\AnalyticsOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AnalyticsOptions_namedParameters, 0, 1, Couchbase\\AnalyticsOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AnalyticsOptions_positionalParameters, 0, 1, Couchbase\\AnalyticsOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AnalyticsOptions_raw, 0, 2, Couchbase\\AnalyticsOptions, 0)
ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, value, 0, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AnalyticsOptions_clientContextId, 0, 2, Couchbase\\AnalyticsOptions, 0)
ZEND_ARG_TYPE_INFO(0, value, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AnalyticsOptions_readonly, 0, 1, Couchbase\\AnalyticsOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AnalyticsOptions_scanConsistency, 0, 1, Couchbase\\AnalyticsOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AnalyticsOptions_priority, 0, 1, Couchbase\\AnalyticsOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry pcbc_analytics_options_methods[] = {
    PHP_ME(AnalyticsOptions, timeout, ai_AnalyticsOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsOptions, namedParameters, ai_AnalyticsOptions_namedParameters, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsOptions, positionalParameters, ai_AnalyticsOptions_positionalParameters, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsOptions, raw, ai_AnalyticsOptions_raw, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsOptions, clientContextId, ai_AnalyticsOptions_clientContextId, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsOptions, priority, ai_AnalyticsOptions_priority, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsOptions, readonly, ai_AnalyticsOptions_readonly, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsOptions, scanConsistency, ai_AnalyticsOptions_scanConsistency, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Cluster, analyticsQuery)
{
    lcb_STATUS err;
    zend_string *statement;
    zval *options = NULL;

    int rv =
        zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S|O!", &statement, &options, pcbc_analytics_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_cluster_t *cluster = Z_CLUSTER_OBJ_P(getThis());

    lcb_CMDANALYTICS *cmd;
    lcb_cmdanalytics_create(&cmd);
    lcb_cmdanalytics_callback(cmd, analytics_callback);
    lcb_cmdanalytics_statement(cmd, ZSTR_VAL(statement), ZSTR_LEN(statement));
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_analytics_options_ce, options, ZEND_STRL("timeout"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            lcb_cmdanalytics_timeout(cmd, Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_analytics_options_ce, options, ZEND_STRL("named_params"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_ARRAY) {
            HashTable *ht = HASH_OF(prop);
            zend_string *string_key = NULL;
            zval *entry;
            ZEND_HASH_FOREACH_STR_KEY_VAL(ht, string_key, entry)
            {
                if (string_key && Z_TYPE_P(entry) == IS_STRING) {
                    lcb_cmdanalytics_named_param(cmd, ZSTR_VAL(string_key), ZSTR_LEN(string_key), Z_STRVAL_P(entry),
                                                 Z_STRLEN_P(entry));
                }
            }
            ZEND_HASH_FOREACH_END();
        }
        prop = zend_read_property(pcbc_analytics_options_ce, options, ZEND_STRL("positional_params"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_ARRAY) {
            HashTable *ht = HASH_OF(prop);
            zval *entry;
            ZEND_HASH_FOREACH_VAL(ht, entry)
            {
                if (Z_TYPE_P(entry) == IS_STRING) {
                    lcb_cmdanalytics_positional_param(cmd, Z_STRVAL_P(entry), Z_STRLEN_P(entry));
                }
            }
            ZEND_HASH_FOREACH_END();
        }
        prop = zend_read_property(pcbc_analytics_options_ce, options, ZEND_STRL("raw_params"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_ARRAY) {
            HashTable *ht = HASH_OF(prop);
            zend_string *string_key = NULL;
            zval *entry;
            ZEND_HASH_FOREACH_STR_KEY_VAL(ht, string_key, entry)
            {
                if (string_key && Z_TYPE_P(entry) == IS_STRING) {
                    lcb_cmdanalytics_option(cmd, ZSTR_VAL(string_key), ZSTR_LEN(string_key), Z_STRVAL_P(entry),
                                            Z_STRLEN_P(entry));
                }
            }
            ZEND_HASH_FOREACH_END();
        }
    }

    lcb_ANALYTICS_HANDLE *handle = NULL;
    lcb_cmdanalytics_handle(cmd, &handle);

    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(cluster->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/analytics", 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_ANALYTICS);
        lcb_cmdanalytics_parent_span(cmd, span);
    }
    rv = object_init_ex(return_value, pcbc_analytics_result_impl_ce);
    if (rv != SUCCESS) {
        return;
    }
    zval rows;
    array_init(&rows);
    zend_update_property(pcbc_analytics_result_impl_ce, return_value, ZEND_STRL("rows"), &rows TSRMLS_CC);
    struct query_cookie cookie = {LCB_SUCCESS, return_value};
    err = lcb_analytics(cluster->conn->lcb, &cookie, cmd);
    lcb_cmdanalytics_destroy(cmd);
    if (err == LCB_SUCCESS) {
        lcb_wait(cluster->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }
    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, NULL);
    }
}

PHP_MINIT_FUNCTION(AnalyticsQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "AnalyticsOptions", pcbc_analytics_options_methods);
    pcbc_analytics_options_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_declare_property_null(pcbc_analytics_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_analytics_options_ce, ZEND_STRL("positional_params"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_analytics_options_ce, ZEND_STRL("named_params"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_analytics_options_ce, ZEND_STRL("raw_params"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_analytics_options_ce, ZEND_STRL("scan_consistency"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_analytics_options_ce, ZEND_STRL("priority"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_analytics_options_ce, ZEND_STRL("readonly"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_analytics_options_ce, ZEND_STRL("client_context_id"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
