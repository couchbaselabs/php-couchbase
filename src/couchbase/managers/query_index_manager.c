/**
 *     Copyright 2016-2020 Couchbase, Inc.
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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/query_index_manager", __FILE__, __LINE__

zend_class_entry *pcbc_query_index_manager_ce;
zend_class_entry *pcbc_query_index_ce;
zend_class_entry *pcbc_create_query_index_options_ce;
zend_class_entry *pcbc_create_query_primary_index_options_ce;
zend_class_entry *pcbc_drop_query_index_options_ce;
zend_class_entry *pcbc_drop_query_primary_index_options_ce;
zend_class_entry *pcbc_watch_query_indexes_options_ce;
extern zend_class_entry *pcbc_default_exception_ce;

static void httpcb_getAllIndexes(void *ctx, zval *return_value, zval *response)
{
    array_init(return_value);

    if (!response || Z_TYPE_P(response) != IS_ARRAY) {
        return;
    }
    zval *rows = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("results"));
    if (rows && Z_TYPE_P(rows) == IS_ARRAY) {
        zval *entry;
        ZEND_HASH_FOREACH_VAL(HASH_OF(rows), entry)
        {
            zval index, *val;
            object_init_ex(&index, pcbc_query_index_ce);
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("name"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                zend_update_property(pcbc_query_index_ce, &index, ZEND_STRL("name"), val TSRMLS_CC);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("using"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                zend_update_property(pcbc_query_index_ce, &index, ZEND_STRL("type"), val TSRMLS_CC);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("is_primary"));
            if (val && (Z_TYPE_P(val) == IS_FALSE || Z_TYPE_P(val) == IS_TRUE)) {
                zend_update_property(pcbc_query_index_ce, &index, ZEND_STRL("is_primary"), val TSRMLS_CC);
            } else {
                zend_update_property_bool(pcbc_query_index_ce, &index, ZEND_STRL("is_primary"), 0 TSRMLS_CC);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("state"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                zend_update_property(pcbc_query_index_ce, &index, ZEND_STRL("state"), val TSRMLS_CC);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("keyspace_id"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                zend_update_property(pcbc_query_index_ce, &index, ZEND_STRL("keyspace"), val TSRMLS_CC);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("index_key"));
            if (val && Z_TYPE_P(val) == IS_ARRAY) {
                zend_update_property(pcbc_query_index_ce, &index, ZEND_STRL("index_key"), val TSRMLS_CC);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("condition"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                zend_update_property(pcbc_query_index_ce, &index, ZEND_STRL("condition"), val TSRMLS_CC);
            }
            add_next_index_zval(return_value, &index);
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_METHOD(QueryIndexManager, getAllIndexes)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    zend_string *bucket;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &bucket);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_query_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_QUERY);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    char *payload = NULL;
    size_t payload_len;
    payload_len = spprintf(&payload, 0,
                           "{\"statement\":\"SELECT idx.* FROM system:indexes AS idx WHERE keyspace_id = \\\"%.*s\\\" "
                           "AND `using` = \\\"gsi\\\"\"}",
                           (int)ZSTR_LEN(bucket), ZSTR_VAL(bucket));
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, payload, payload_len);
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getAllIndexes, NULL TSRMLS_CC);
    efree(payload);
}

static int errcb_createIndex(void *ctx, zval *return_value)
{
    zend_bool *ignore_exists_error = (zend_bool *)ctx;
    if (*ignore_exists_error && return_value) {
        zval *code, *msg, rv1, rv2;
        msg = zend_read_property(pcbc_default_exception_ce, return_value, ZEND_STRL("message"), 0, &rv1);
        code = zend_read_property(pcbc_default_exception_ce, return_value, ZEND_STRL("code"), 0, &rv2);
        if (code && Z_TYPE_P(code) == IS_LONG && msg && Z_TYPE_P(msg) == IS_STRING) {
            if ((Z_LVAL_P(code) == 5000 || Z_LVAL_P(code) == 4300) && strstr(Z_STRVAL_P(msg), " already exist")) {
                return 0;
            }
        }
    }
    return 1;
}

PHP_METHOD(QueryIndexManager, createIndex)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val, ret2;
    zend_string *index, *bucket;
    zval *fields, *options = NULL, *where = NULL;
    zend_bool ignore_exists_error = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "SSa|O!", &bucket, &index, &fields, &options,
                                         pcbc_create_query_index_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_query_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    smart_str with_options = {0};
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_create_query_index_options_ce, options, ZEND_STRL("ignore_if_exists"), 0, &ret);
        if (prop && Z_TYPE_P(prop) == IS_TRUE) {
            ignore_exists_error = 1;
        }
        prop = zend_read_property(pcbc_create_query_index_options_ce, options, ZEND_STRL("condition"), 0, &ret2);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            where = prop;
        }
        smart_str_appends(&with_options, "{");
        prop = zend_read_property(pcbc_create_query_index_options_ce, options, ZEND_STRL("num_replicas"), 0, &ret);
        if (prop && Z_TYPE_P(prop) == IS_LONG) {
            smart_str_append_printf(&with_options, "\\\"num_replicas\\\":%d", (int)Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_create_query_index_options_ce, options, ZEND_STRL("deferred"), 0, &ret);
        if (prop && (Z_TYPE_P(prop) == IS_TRUE || Z_TYPE_P(prop) == IS_FALSE)) {
            if (ZSTR_LEN(with_options.s) > 2) {
                smart_str_appendc(&with_options, ',');
            }
            smart_str_append_printf(&with_options, "\\\"defer_build\\\":%s",
                                    Z_TYPE_P(prop) == IS_TRUE ? "true" : "false");
        }
        smart_str_appends(&with_options, "}");
    }

    smart_str payload = {0};

    smart_str_append_printf(&payload, "{\"statement\":\"CREATE INDEX %.*s ON `%.*s` (", (int)ZSTR_LEN(index),
                            ZSTR_VAL(index), (int)ZSTR_LEN(bucket), ZSTR_VAL(bucket));
    zval *ent;
    size_t num_fields = 0;
    ZEND_HASH_FOREACH_VAL(HASH_OF(fields), ent)
    {
        if (Z_TYPE_P(ent) == IS_STRING) {
            smart_str_append_printf(&payload, "%.*s,", (int)Z_STRLEN_P(ent), Z_STRVAL_P(ent));
            num_fields++;
        }
    }
    ZEND_HASH_FOREACH_END();
    if (num_fields) {
        ZSTR_LEN(payload.s)--;
    }
    smart_str_appendc(&payload, ')');
    if (where) {
        smart_str_append_printf(&payload, " WHERE %.*s", (int)Z_STRLEN_P(where), Z_STRVAL_P(where));
    }
    if (with_options.s && ZSTR_LEN(with_options.s) > 2) {
        smart_str_appends(&payload, " WITH ");
        smart_str_append_smart_str(&payload, &with_options);
    }
    smart_str_appends(&payload, "\"}");

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_QUERY);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, ZSTR_VAL(payload.s), ZSTR_LEN(payload.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, &ignore_exists_error, NULL,
                      errcb_createIndex TSRMLS_CC);
    smart_str_free(&with_options);
    smart_str_free(&payload);
}

PHP_METHOD(QueryIndexManager, createPrimaryIndex)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val, val2;
    zend_string *bucket;
    zval *index = NULL, *options = NULL;
    zend_bool ignore_exists_error = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S|O!", &bucket, &options,
                                         pcbc_create_query_primary_index_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_query_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    smart_str with_options = {0};
    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_create_query_primary_index_options_ce, options, ZEND_STRL("ignore_if_exists"), 0,
                                  &ret);
        if (prop && Z_TYPE_P(prop) == IS_TRUE) {
            ignore_exists_error = 1;
        }
        prop =
            zend_read_property(pcbc_create_query_primary_index_options_ce, options, ZEND_STRL("index_name"), 0, &val2);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            index = prop;
        }
        smart_str_appends(&with_options, "{");
        prop =
            zend_read_property(pcbc_create_query_primary_index_options_ce, options, ZEND_STRL("num_replicas"), 0, &ret);
        if (prop && Z_TYPE_P(prop) == IS_LONG) {
            smart_str_append_printf(&with_options, "\\\"num_replicas\\\":%d", (int)Z_LVAL_P(prop));
        }
        prop = zend_read_property(pcbc_create_query_primary_index_options_ce, options, ZEND_STRL("deferred"), 0, &ret);
        if (prop && (Z_TYPE_P(prop) == IS_TRUE || Z_TYPE_P(prop) == IS_FALSE)) {
            if (ZSTR_LEN(with_options.s) > 2) {
                smart_str_appendc(&with_options, ',');
            }
            smart_str_append_printf(&with_options, "\\\"defer_build\\\":%s",
                                    Z_TYPE_P(prop) == IS_TRUE ? "true" : "false");
        }
        smart_str_appends(&with_options, "}");
    }

    smart_str payload = {0};
    if (index) {
        smart_str_append_printf(&payload, "{\"statement\":\"CREATE PRIMARY INDEX %.*s ON `%.*s`",
                                (int)Z_STRLEN_P(index), Z_STRVAL_P(index), (int)ZSTR_LEN(bucket), ZSTR_VAL(bucket));
    } else {
        smart_str_append_printf(&payload, "{\"statement\":\"CREATE PRIMARY INDEX ON `%.*s`", (int)ZSTR_LEN(bucket),
                                ZSTR_VAL(bucket));
    }
    if (with_options.s && ZSTR_LEN(with_options.s) > 2) {
        smart_str_appends(&payload, " WITH ");
        smart_str_append_smart_str(&payload, &with_options);
    }
    smart_str_appends(&payload, "\"}");

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_QUERY);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, ZSTR_VAL(payload.s), ZSTR_LEN(payload.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, &ignore_exists_error, NULL,
                      errcb_createIndex TSRMLS_CC);
    smart_str_free(&with_options);
    smart_str_free(&payload);
}

static int errcb_dropIndex(void *ctx, zval *return_value)
{
    zend_bool *ignore_exists_error = (zend_bool *)ctx;
    if (*ignore_exists_error && return_value) {
        zval *code, *msg, rv1, rv2;
        msg = zend_read_property(pcbc_default_exception_ce, return_value, ZEND_STRL("message"), 0, &rv1);
        code = zend_read_property(pcbc_default_exception_ce, return_value, ZEND_STRL("code"), 0, &rv2);
        if (code && Z_TYPE_P(code) == IS_LONG && msg && Z_TYPE_P(msg) == IS_STRING) {
            switch (Z_LVAL_P(code)) {
            case 5000:
                if (strstr(Z_STRVAL_P(msg), " not found") == NULL) {
                    return 1;
                }
                /* fall through */
            case 12004:
            case 12006:
                return 0;
            }
        }
    }
    return 1;
}

PHP_METHOD(QueryIndexManager, dropIndex)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    zend_string *bucket, *index;
    zval *options = NULL;
    zend_bool ignore_not_exists_error = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "SS|O!", &bucket, &index, &options,
                                         pcbc_drop_query_index_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_query_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    if (options) {
        zval *prop, ret;
        prop =
            zend_read_property(pcbc_drop_query_index_options_ce, options, ZEND_STRL("ignore_if_not_exists"), 0, &ret);
        if (prop && Z_TYPE_P(prop) == IS_TRUE) {
            ignore_not_exists_error = 1;
        }
    }

    smart_str payload = {0};
    smart_str_append_printf(&payload, "{\"statement\":\"DROP INDEX `%.*s`.`%.*s`\"}", (int)ZSTR_LEN(bucket),
                            ZSTR_VAL(bucket), (int)ZSTR_LEN(index), ZSTR_VAL(index));

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_QUERY);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, ZSTR_VAL(payload.s), ZSTR_LEN(payload.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, &ignore_not_exists_error, NULL,
                      errcb_dropIndex TSRMLS_CC);
    smart_str_free(&payload);
}

PHP_METHOD(QueryIndexManager, dropPrimaryIndex)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val, val2;
    zend_string *bucket;
    zval *options = NULL, *index = NULL;
    zend_bool ignore_not_exists_error = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S|O!", &bucket, &options,
                                         pcbc_drop_query_primary_index_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_query_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    if (options) {
        zval *prop, ret;
        prop = zend_read_property(pcbc_drop_query_primary_index_options_ce, options, ZEND_STRL("ignore_if_not_exists"),
                                  0, &ret);
        if (prop && Z_TYPE_P(prop) == IS_TRUE) {
            ignore_not_exists_error = 1;
        }
        prop = zend_read_property(pcbc_drop_query_primary_index_options_ce, options, ZEND_STRL("index_name"), 0, &val2);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            index = prop;
        }
    }

    smart_str payload = {0};
    if (index) {
        smart_str_append_printf(&payload, "{\"statement\":\"DROP INDEX `%.*s`.`%.*s`\"}", (int)ZSTR_LEN(bucket),
                                ZSTR_VAL(bucket), (int)Z_STRLEN_P(index), Z_STRVAL_P(index));
    } else {
        smart_str_append_printf(&payload, "{\"statement\":\"DROP PRIMARY INDEX ON `%.*s`\"}", (int)ZSTR_LEN(bucket),
                                ZSTR_VAL(bucket));
    }

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_QUERY);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, ZSTR_VAL(payload.s), ZSTR_LEN(payload.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, &ignore_not_exists_error, NULL,
                      errcb_dropIndex TSRMLS_CC);
    smart_str_free(&payload);
}

struct watch_context {
    zval *indexes;
    zend_long deadline;
    zend_long start_time;
    zend_bool watch_primary;
    int rc;
};

static void httpcb_watchIndexes(void *ctx, zval *return_value, zval *response)
{
    struct watch_context *wctx = ctx;
    zend_long now = lcbtrace_now();
    if (wctx->deadline < now) {
        wctx->rc = -1;
        return;
    }
    if (!response || Z_TYPE_P(response) != IS_ARRAY) {
        wctx->rc = -1;
        return;
    }
    int has_incomplete = 0;
    zval *rows = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("results"));
    if (rows && Z_TYPE_P(rows) == IS_ARRAY) {
        zval *entry;
        ZEND_HASH_FOREACH_VAL(HASH_OF(rows), entry)
        {
            zval *val;
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("state"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                if (zend_binary_strcmp("online", 4, Z_STRVAL_P(val), Z_STRLEN_P(val)) != 0) {
                    if (wctx->watch_primary) {
                        val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("is_primary"));
                        if (val && Z_TYPE_P(val) == IS_TRUE) {
                            has_incomplete = 1;
                            break;
                        }
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("name"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        zval *idx;
                        ZEND_HASH_FOREACH_VAL(HASH_OF(wctx->indexes), idx)
                        {
                            if (Z_TYPE_P(idx) && zend_binary_strcmp(Z_STRVAL_P(idx), Z_STRLEN_P(idx), Z_STRVAL_P(val),
                                                                    Z_STRLEN_P(val)) == 0) {
                                has_incomplete = 1;
                                break;
                            }
                        }
                        ZEND_HASH_FOREACH_END();
                    }
                }
            }
            if (has_incomplete) {
                break;
            }
        }
        ZEND_HASH_FOREACH_END();
    }
    wctx->rc = has_incomplete == 0;
}

PHP_METHOD(QueryIndexManager, watchIndexes)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    zend_string *bucket;
    zval *indexes = NULL, *options = NULL;
    zend_long timeout;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "Sal|O!", &bucket, &indexes, &timeout, &options,
                                         pcbc_watch_query_indexes_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_query_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    struct watch_context ctx;
    ctx.indexes = indexes;
    ctx.start_time = lcbtrace_now();
    ctx.deadline = ctx.start_time + timeout;
    ctx.rc = 0;
    ctx.watch_primary = 0;

    if (options) {
        zval ret;
        prop = zend_read_property(pcbc_watch_query_indexes_options_ce, options, ZEND_STRL("watch_primary"), 0, &ret);
        if (prop && Z_TYPE_P(prop) == IS_TRUE) {
            ctx.watch_primary = 1;
        }
    }

    char *payload = NULL;
    size_t payload_len;
    payload_len = spprintf(&payload, 0,
                           "{\"statement\":\"SELECT idx.* FROM system:indexes AS idx WHERE keyspace_id = \\\"%.*s\\\" "
                           "AND `using` = \\\"gsi\\\"\"}",
                           (int)ZSTR_LEN(bucket), ZSTR_VAL(bucket));

    while (ctx.rc == 0) {
        lcb_CMDHTTP *cmd;
        lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_QUERY);
        lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
        lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
        lcb_cmdhttp_body(cmd, payload, payload_len);
        pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, &ctx, httpcb_watchIndexes, NULL TSRMLS_CC);
    }
    efree(payload);
}

PHP_METHOD(QueryIndexManager, buildDeferredIndexes)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    zend_string *bucket;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &bucket);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_query_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_QUERY);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    char *payload = NULL;
    size_t payload_len;

    payload_len = spprintf(&payload, 0,
                           "{\"statement\":\"BUILD INDEX ON `%.*s` ((SELECT RAW name FROM system:indexes WHERE "
                           "keyspace_id = \\\"%.*s\\\" AND state = 'deferred' ))\"}",
                           (int)ZSTR_LEN(bucket), ZSTR_VAL(bucket), (int)ZSTR_LEN(bucket), ZSTR_VAL(bucket));
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, payload, payload_len);
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(payload);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_QueryIndexManager_getAllIndexes, 0, 1, IS_ARRAY, 0)
ZEND_ARG_TYPE_INFO(0, bucketName, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_QueryIndexManager_createIndex, 0, 0, 3)
ZEND_ARG_TYPE_INFO(0, bucketName, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, indexName, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, fields, IS_ARRAY, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\CreateQueryIndexOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_QueryIndexManager_createPrimaryIndex, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, bucketName, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\CreateQueryPrimaryIndexOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_QueryIndexManager_dropIndex, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, bucketName, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, indexName, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\DropQueryIndexOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_QueryIndexManager_dropPrimaryIndex, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, bucketName, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\DropQueryPrimaryIndexOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_QueryIndexManager_watchIndexes, 0, 0, 3)
ZEND_ARG_TYPE_INFO(0, bucketName, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, indexNames, IS_ARRAY, 0)
ZEND_ARG_TYPE_INFO(0, timeout, IS_LONG, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\WatchQueryIndexesOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_QueryIndexManager_buildDeferredIndexes, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, bucketName, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry query_index_manager_methods[] = {
    PHP_ME(QueryIndexManager, getAllIndexes, ai_QueryIndexManager_getAllIndexes, ZEND_ACC_PUBLIC)
    PHP_ME(QueryIndexManager, createIndex, ai_QueryIndexManager_createIndex, ZEND_ACC_PUBLIC)
    PHP_ME(QueryIndexManager, createPrimaryIndex, ai_QueryIndexManager_createPrimaryIndex, ZEND_ACC_PUBLIC)
    PHP_ME(QueryIndexManager, dropIndex, ai_QueryIndexManager_dropIndex, ZEND_ACC_PUBLIC)
    PHP_ME(QueryIndexManager, dropPrimaryIndex, ai_QueryIndexManager_dropPrimaryIndex, ZEND_ACC_PUBLIC)
    PHP_ME(QueryIndexManager, watchIndexes, ai_QueryIndexManager_watchIndexes, ZEND_ACC_PUBLIC)
    PHP_ME(QueryIndexManager, buildDeferredIndexes, ai_QueryIndexManager_buildDeferredIndexes, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(QueryIndex, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_query_index_ce, getThis(), ZEND_STRL("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(QueryIndex, isPrimary)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_query_index_ce, getThis(), ZEND_STRL("is_primary"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(QueryIndex, type)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_query_index_ce, getThis(), ZEND_STRL("type"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(QueryIndex, state)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_query_index_ce, getThis(), ZEND_STRL("state"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(QueryIndex, keyspace)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_query_index_ce, getThis(), ZEND_STRL("keyspace"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(QueryIndex, indexKey)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_query_index_ce, getThis(), ZEND_STRL("index_key"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(QueryIndex, condition)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_query_index_ce, getThis(), ZEND_STRL("condition"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_QueryIndex_name, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_QueryIndex_isPrimary, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_QueryIndex_type, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_QueryIndex_state, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_QueryIndex_keyspace, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_QueryIndex_indexKey, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_QueryIndex_condition, 0, 0, IS_STRING, 1)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry query_index_methods[] = {
    PHP_ME(QueryIndex, name, ai_QueryIndex_name, ZEND_ACC_PUBLIC)
    PHP_ME(QueryIndex, isPrimary, ai_QueryIndex_isPrimary, ZEND_ACC_PUBLIC)
    PHP_ME(QueryIndex, type, ai_QueryIndex_type, ZEND_ACC_PUBLIC)
    PHP_ME(QueryIndex, state, ai_QueryIndex_state, ZEND_ACC_PUBLIC)
    PHP_ME(QueryIndex, keyspace, ai_QueryIndex_keyspace, ZEND_ACC_PUBLIC)
    PHP_ME(QueryIndex, indexKey, ai_QueryIndex_indexKey, ZEND_ACC_PUBLIC)
    PHP_ME(QueryIndex, condition, ai_QueryIndex_condition, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(CreateQueryIndexOptions, condition)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_create_query_index_options_ce, getThis(), ZEND_STRL("condition"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CreateQueryIndexOptions, ignoreIfExists)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_bool(pcbc_create_query_index_options_ce, getThis(), ZEND_STRL("ignore_if_exists"),
                              val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CreateQueryIndexOptions, deferred)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_bool(pcbc_create_query_index_options_ce, getThis(), ZEND_STRL("deferred"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CreateQueryIndexOptions, numReplicas)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_long(pcbc_create_query_index_options_ce, getThis(), ZEND_STRL("num_replicas"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateQueryIndexOptions_condition, 0, 1, Couchbase\\CreateQueryIndexOptions,
                                       0)
ZEND_ARG_TYPE_INFO(0, condition, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateQueryIndexOptions_ignoreIfExists, 0,
                                       1, Couchbase\\CreateQueryIndexOptions, 0)
ZEND_ARG_TYPE_INFO(0, shouldIgnore, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateQueryIndexOptions_numReplicas, 0,
                                       1, Couchbase\\CreateQueryIndexOptions, 0)
ZEND_ARG_TYPE_INFO(0, number, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateQueryIndexOptions_deferred, 0, 1, Couchbase\\CreateQueryIndexOptions,
                                       0)
ZEND_ARG_TYPE_INFO(0, isDeferred, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry create_query_index_options_methods[] = {
    PHP_ME(CreateQueryIndexOptions, condition, ai_CreateQueryIndexOptions_condition, ZEND_ACC_PUBLIC)
    PHP_ME(CreateQueryIndexOptions, ignoreIfExists, ai_CreateQueryIndexOptions_ignoreIfExists, ZEND_ACC_PUBLIC)
    PHP_ME(CreateQueryIndexOptions, numReplicas, ai_CreateQueryIndexOptions_numReplicas, ZEND_ACC_PUBLIC)
    PHP_ME(CreateQueryIndexOptions, deferred, ai_CreateQueryIndexOptions_deferred, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(CreateQueryPrimaryIndexOptions, indexName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_create_query_primary_index_options_ce, getThis(), ZEND_STRL("index_name"),
                             val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CreateQueryPrimaryIndexOptions, ignoreIfExists)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_bool(pcbc_create_query_primary_index_options_ce, getThis(), ZEND_STRL("ignore_if_exists"),
                              val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CreateQueryPrimaryIndexOptions, deferred)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_bool(pcbc_create_query_primary_index_options_ce, getThis(), ZEND_STRL("deferred"),
                              val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CreateQueryPrimaryIndexOptions, numReplicas)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_long(pcbc_create_query_primary_index_options_ce, getThis(), ZEND_STRL("num_replicas"),
                              val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateQueryPrimaryIndexOptions_indexName, 0,
                                       1, Couchbase\\CreateQueryPrimaryIndexOptions, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateQueryPrimaryIndexOptions_ignoreIfExists, 0,
                                       1, Couchbase\\CreateQueryPrimaryIndexOptions, 0)
ZEND_ARG_TYPE_INFO(0, shouldIgnore, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateQueryPrimaryIndexOptions_numReplicas, 0,
                                       1, Couchbase\\CreateQueryPrimaryIndexOptions, 0)
ZEND_ARG_TYPE_INFO(0, number, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateQueryPrimaryIndexOptions_deferred, 0,
                                       1, Couchbase\\CreateQueryPrimaryIndexOptions, 0)
ZEND_ARG_TYPE_INFO(0, isDeferred, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry create_query_primary_index_options_methods[] = {
    PHP_ME(CreateQueryPrimaryIndexOptions, indexName, ai_CreateQueryPrimaryIndexOptions_indexName, ZEND_ACC_PUBLIC)
    PHP_ME(CreateQueryPrimaryIndexOptions, ignoreIfExists, ai_CreateQueryPrimaryIndexOptions_ignoreIfExists, ZEND_ACC_PUBLIC)
    PHP_ME(CreateQueryPrimaryIndexOptions, numReplicas, ai_CreateQueryPrimaryIndexOptions_numReplicas, ZEND_ACC_PUBLIC)
    PHP_ME(CreateQueryPrimaryIndexOptions, deferred, ai_CreateQueryPrimaryIndexOptions_deferred, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(DropQueryIndexOptions, ignoreIfNotExists)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_bool(pcbc_drop_query_index_options_ce, getThis(), ZEND_STRL("ignore_if_not_exists"),
                              val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DropQueryIndexOptions_ignoreIfNotExists, 0,
                                       1, Couchbase\\DropQueryIndexOptions, 0)
ZEND_ARG_TYPE_INFO(0, shouldIgnore, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry drop_query_index_options_methods[] = {
    PHP_ME(DropQueryIndexOptions, ignoreIfNotExists, ai_DropQueryIndexOptions_ignoreIfNotExists, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(DropQueryPrimaryIndexOptions, indexName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_drop_query_primary_index_options_ce, getThis(), ZEND_STRL("index_name"),
                             val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(DropQueryPrimaryIndexOptions, ignoreIfNotExists)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_bool(pcbc_drop_query_primary_index_options_ce, getThis(), ZEND_STRL("ignore_if_not_exists"),
                              val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DropQueryPrimaryIndexOptions_indexName, 0,
                                       1, Couchbase\\DropQueryPrimaryIndexOptions, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DropQueryPrimaryIndexOptions_ignoreIfNotExists, 0,
                                       1, Couchbase\\DropQueryPrimaryIndexOptions, 0)
ZEND_ARG_TYPE_INFO(0, shouldIgnore, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry drop_query_primary_index_options_methods[] = {
    PHP_ME(DropQueryPrimaryIndexOptions, indexName, ai_DropQueryPrimaryIndexOptions_indexName, ZEND_ACC_PUBLIC)
    PHP_ME(DropQueryPrimaryIndexOptions, ignoreIfNotExists, ai_DropQueryPrimaryIndexOptions_ignoreIfNotExists, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(WatchQueryIndexesOptions, watchPrimary)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_bool(pcbc_watch_query_indexes_options_ce, getThis(), ZEND_STRL("watch_primary"),
                              val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_WatchQueryIndexesOptions_watchPrimary, 0,
                                       1, Couchbase\\WatchQueryIndexesOptions, 0)
ZEND_ARG_TYPE_INFO(0, shouldWatch, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry watch_query_indexes_options_methods[] = {
    PHP_ME(WatchQueryIndexesOptions, watchPrimary, ai_WatchQueryIndexesOptions_watchPrimary, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(QueryIndexManager)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "QueryIndexManager", query_index_manager_methods);
    pcbc_query_index_manager_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_query_index_manager_ce, ZEND_STRL("cluster"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "QueryIndex", query_index_methods);
    pcbc_query_index_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_query_index_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_query_index_ce, ZEND_STRL("is_primary"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_query_index_ce, ZEND_STRL("type"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_query_index_ce, ZEND_STRL("state"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_query_index_ce, ZEND_STRL("keyspace"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_query_index_ce, ZEND_STRL("index_key"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_query_index_ce, ZEND_STRL("condition"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "CreateQueryIndexOptions", create_query_index_options_methods);
    pcbc_create_query_index_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_create_query_index_options_ce, ZEND_STRL("condition"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_create_query_index_options_ce, ZEND_STRL("ignore_if_exists"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_create_query_index_options_ce, ZEND_STRL("num_replicas"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_create_query_index_options_ce, ZEND_STRL("deferred"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "CreateQueryPrimaryIndexOptions", create_query_primary_index_options_methods);
    pcbc_create_query_primary_index_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_create_query_primary_index_options_ce, ZEND_STRL("index_name"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_create_query_primary_index_options_ce, ZEND_STRL("ignore_if_exists"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_create_query_primary_index_options_ce, ZEND_STRL("num_replicas"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_create_query_primary_index_options_ce, ZEND_STRL("deferred"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DropQueryIndexOptions", drop_query_index_options_methods);
    pcbc_drop_query_index_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_drop_query_index_options_ce, ZEND_STRL("ignore_if_not_exists"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DropQueryPrimaryIndexOptions", drop_query_primary_index_options_methods);
    pcbc_drop_query_primary_index_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_drop_query_primary_index_options_ce, ZEND_STRL("index_name"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_drop_query_primary_index_options_ce, ZEND_STRL("ignore_if_not_exists"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "WatchQueryIndexesOptions", watch_query_indexes_options_methods);
    pcbc_watch_query_indexes_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_watch_query_indexes_options_ce, ZEND_STRL("watch_primary"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
