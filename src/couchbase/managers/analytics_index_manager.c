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
#include <stdlib.h>
#include <string.h>

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/analytics_index_manager", __FILE__, __LINE__

zend_class_entry *pcbc_analytics_index_manager_ce;
zend_class_entry *pcbc_analytics_dataset_ce;
zend_class_entry *pcbc_analytics_index_ce;
zend_class_entry *pcbc_create_analytics_dataverse_options_ce;
zend_class_entry *pcbc_create_analytics_dataset_options_ce;
zend_class_entry *pcbc_create_analytics_index_options_ce;
zend_class_entry *pcbc_drop_analytics_dataverse_options_ce;
zend_class_entry *pcbc_drop_analytics_dataset_options_ce;
zend_class_entry *pcbc_drop_analytics_index_options_ce;
zend_class_entry *pcbc_connect_analytics_link_options_ce;
zend_class_entry *pcbc_disconnect_analytics_link_options_ce;
extern zend_class_entry *pcbc_default_exception_ce;

static char *uncompoundDataverseName(const char *name, size_t name_len)
{
    const size_t slash_len = 1; /* strlen("/") */
    const size_t dot_len = 3;   /* strlen("`.`") */

    int slash_count = 0;
    for (size_t i = 0; i < name_len; i++) {
        if (name[i] == '/') {
            slash_count++;
        }
    }

    size_t result_len = name_len + slash_count * (dot_len - slash_len) + 2;
    char *result = (char *)calloc(result_len + 1, sizeof(char));
    result[0] = '`';
    result[result_len - 1] = '`';

    for (size_t i = name_len; i != 0; --i) {
        if (name[i - 1] == '/') {
            result[i - 1 + slash_count * (dot_len - slash_len) + 1] = '`';
            result[i - 1 + slash_count * (dot_len - slash_len)] = '.';
            result[i - 1 + slash_count * (dot_len - slash_len) - 1] = '`';
            --slash_count;
        } else {
            result[i - 1 + slash_count * (dot_len - slash_len) + 1] = name[i - 1];
        }
    }

    return result;
}

PHP_METHOD(AnalyticsIndexManager, createDataverse)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;
    zend_string *dataverse;
    zval *options = NULL;
    zend_bool ignore_exists_error = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S|O!", &dataverse, &options,
                                         pcbc_create_analytics_dataverse_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    if (options) {
        zval ret;
        prop = pcbc_read_property(pcbc_create_analytics_dataverse_options_ce, options, ("ignore_if_exists"), 0, &ret);
        if (prop && Z_TYPE_P(prop) == IS_TRUE) {
            ignore_exists_error = 1;
        }
    }

    smart_str payload = {0};

    char *uncompound = uncompoundDataverseName(ZSTR_VAL(dataverse), ZSTR_LEN(dataverse));
    smart_str_append_printf(&payload, "{\"statement\":\"CREATE DATAVERSE %.*s", (int)strlen(uncompound), uncompound);
    free(uncompound);

    if (ignore_exists_error) {
        smart_str_append_printf(&payload, " IF NOT EXISTS");
    }
    smart_str_appends(&payload, "\"}");

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);
    lcb_cmdhttp_path(cmd, ZEND_STRL("/query/service"));
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, ZSTR_VAL(payload.s), ZSTR_LEN(payload.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
    smart_str_free(&payload);
}

PHP_METHOD(AnalyticsIndexManager, dropDataverse)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;
    zend_string *dataverse;
    zval *options = NULL;
    zend_bool ignore_not_exists_error = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S|O!", &dataverse, &options,
                                         pcbc_drop_analytics_dataverse_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    if (options) {
        zval ret;
        prop = pcbc_read_property(pcbc_drop_analytics_dataverse_options_ce, options, ("ignore_if_not_exists"), 0, &ret);
        if (prop && Z_TYPE_P(prop) == IS_TRUE) {
            ignore_not_exists_error = 1;
        }
    }

    smart_str payload = {0};

    char *uncompound = uncompoundDataverseName(ZSTR_VAL(dataverse), ZSTR_LEN(dataverse));
    smart_str_append_printf(&payload, "{\"statement\":\"DROP DATAVERSE %.*s", (int)strlen(uncompound), uncompound);
    free(uncompound);

    if (ignore_not_exists_error) {
        smart_str_append_printf(&payload, " IF EXISTS");
    }
    smart_str_appends(&payload, "\"}");

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, ZEND_STRL("/query/service"));
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, ZSTR_VAL(payload.s), ZSTR_LEN(payload.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
    smart_str_free(&payload);
}

PHP_METHOD(AnalyticsIndexManager, createDataset)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;
    zval val2;
    zend_string *bucket;
    zend_string *dataset;
    const zval *dataverse = NULL;
    zval *options = NULL;
    zval *where = NULL;
    zend_bool ignore_exists_error = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "SS|O!", &dataset, &bucket, &options,
                                         pcbc_create_analytics_dataset_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    if (options) {
        zval ret;
        zval ret2;
        prop = pcbc_read_property(pcbc_create_analytics_dataset_options_ce, options, ("ignore_if_exists"), 0, &ret);
        if (prop && Z_TYPE_P(prop) == IS_TRUE) {
            ignore_exists_error = 1;
        }
        prop = pcbc_read_property(pcbc_create_analytics_dataset_options_ce, options, ("dataverse_name"), 0, &val2);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            dataverse = prop;
        }
        prop = pcbc_read_property(pcbc_create_analytics_dataset_options_ce, options, ("condition"), 0, &ret2);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            where = prop;
        }
    }

    smart_str fq_dataset = {0};
    if (dataverse) {
        char *uncompound = uncompoundDataverseName(Z_STRVAL_P(dataverse), Z_STRLEN_P(dataverse));
        smart_str_append_printf(&fq_dataset, "%.*s.", (int)strlen(uncompound), uncompound);
        free(uncompound);
    }
    smart_str_append_printf(&fq_dataset, "`%.*s`", (int)ZSTR_LEN(dataset), ZSTR_VAL(dataset));

    smart_str payload = {0};

    smart_str_append_printf(&payload, "{\"statement\":\"CREATE DATASET");
    if (ignore_exists_error) {
        smart_str_append_printf(&payload, " IF NOT EXISTS");
    }

    smart_str_append_printf(&payload, " %.*s ON `%.*s`", (int)ZSTR_LEN(fq_dataset.s), ZSTR_VAL(fq_dataset.s),
                            (int)ZSTR_LEN(bucket), ZSTR_VAL(bucket));
    if (where) {
        smart_str_append_printf(&payload, " WHERE %.*s", (int)Z_STRLEN_P(where), Z_STRVAL_P(where));
    }
    smart_str_appends(&payload, "\"}");

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, ZEND_STRL("/query/service"));
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, ZSTR_VAL(payload.s), ZSTR_LEN(payload.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
    smart_str_free(&payload);
    smart_str_free(&fq_dataset);
}

PHP_METHOD(AnalyticsIndexManager, dropDataset)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;
    zval val2;
    zend_string *dataset;
    zval *options = NULL;
    zend_bool ignore_not_exists_error = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S|O!", &dataset, &options,
                                         pcbc_drop_analytics_dataset_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    const zval *dataverse = NULL;
    if (options) {
        zval ret;
        prop = pcbc_read_property(pcbc_drop_analytics_dataset_options_ce, options, ("ignore_if_not_exists"), 0, &ret);
        if (prop && Z_TYPE_P(prop) == IS_TRUE) {
            ignore_not_exists_error = 1;
        }
        prop = pcbc_read_property(pcbc_drop_analytics_dataset_options_ce, options, ("dataverse_name"), 0, &val2);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            dataverse = prop;
        }
    }

    smart_str fq_dataset = {0};
    if (dataverse) {
        char *uncompound = uncompoundDataverseName(Z_STRVAL_P(dataverse), Z_STRLEN_P(dataverse));
        smart_str_append_printf(&fq_dataset, "%.*s.", (int)strlen(uncompound), uncompound);
        free(uncompound);
    }
    smart_str_append_printf(&fq_dataset, "`%.*s`", (int)ZSTR_LEN(dataset), ZSTR_VAL(dataset));

    smart_str payload = {0};

    smart_str_append_printf(&payload, "{\"statement\":\"DROP DATASET %.*s", (int)ZSTR_LEN(fq_dataset.s),
                            ZSTR_VAL(fq_dataset.s));
    if (ignore_not_exists_error) {
        smart_str_append_printf(&payload, " IF EXISTS");
    }
    smart_str_appends(&payload, "\"}");

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, ZEND_STRL("/query/service"));
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, ZSTR_VAL(payload.s), ZSTR_LEN(payload.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
    smart_str_free(&payload);
    smart_str_free(&fq_dataset);
}

static void httpcb_getAllDatasets(void *ctx, zval *return_value, zval *response)
{
    (void)ctx;
    array_init(return_value);

    if (!response || Z_TYPE_P(response) != IS_ARRAY) {
        return;
    }
    zval *rows = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("results"));
    if (rows && Z_TYPE_P(rows) == IS_ARRAY) {
        zval *entry;
        ZEND_HASH_FOREACH_VAL(HASH_OF(rows), entry)
        {
            zval dataset;
            zval *val;
            object_init_ex(&dataset, pcbc_analytics_dataset_ce);
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("DatasetName"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                pcbc_update_property(pcbc_analytics_dataset_ce, &dataset, ("name"), val);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("DataverseName"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                pcbc_update_property(pcbc_analytics_dataset_ce, &dataset, ("dataverse_name"), val);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("LinkName"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                pcbc_update_property(pcbc_analytics_dataset_ce, &dataset, ("link_name"), val);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("BucketName"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                pcbc_update_property(pcbc_analytics_dataset_ce, &dataset, ("bucket_name"), val);
            }
            add_next_index_zval(return_value, &dataset);
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_METHOD(AnalyticsIndexManager, getAllDatasets)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;

    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, ZEND_STRL("/query/service"));
    char *payload = NULL;
    size_t payload_len;
    payload_len =
        spprintf(&payload, 0,
                 "{\"statement\":\"SELECT d.* FROM Metadata.`Dataset` d WHERE d.DataverseName <> \\\"Metadata\\\"\"}");
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, payload, payload_len);
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getAllDatasets, NULL);
    efree(payload);
}

PHP_METHOD(AnalyticsIndexManager, createIndex)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;
    zval val2;
    zend_string *index;
    zend_string *dataset;
    zval *fields;
    const zval *dataverse = NULL;
    zval *options = NULL;
    zend_bool ignore_exists_error = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "SSa|O!", &dataset, &index, &fields, &options,
                                         pcbc_create_analytics_index_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    if (options) {
        zval ret;
        prop = pcbc_read_property(pcbc_create_analytics_index_options_ce, options, ("ignore_if_exists"), 0, &ret);
        if (prop && Z_TYPE_P(prop) == IS_TRUE) {
            ignore_exists_error = 1;
        }
        prop = pcbc_read_property(pcbc_create_analytics_index_options_ce, options, ("dataverse_name"), 0, &val2);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            dataverse = prop;
        }
    }

    smart_str fq_dataset = {0};
    if (dataverse) {
        char *uncompound = uncompoundDataverseName(Z_STRVAL_P(dataverse), Z_STRLEN_P(dataverse));
        smart_str_append_printf(&fq_dataset, "%.*s.", (int)strlen(uncompound), uncompound);
        free(uncompound);
    }
    smart_str_append_printf(&fq_dataset, "`%.*s`", (int)ZSTR_LEN(dataset), ZSTR_VAL(dataset));

    smart_str payload = {0};

    smart_str_append_printf(&payload, "{\"statement\":\"CREATE INDEX %.*s", (int)ZSTR_LEN(index), ZSTR_VAL(index));

    if (ignore_exists_error) {
        smart_str_append_printf(&payload, " IF NOT EXISTS");
    }
    smart_str_append_printf(&payload, " ON %.*s (", (int)ZSTR_LEN(fq_dataset.s), ZSTR_VAL(fq_dataset.s));

    zval *ent;
    zend_string *key;
    zend_ulong h;
    size_t num_fields = 0;
    ZEND_HASH_FOREACH_KEY_VAL(HASH_OF(fields), h, key, ent)
    {
        if (Z_TYPE_P(ent) == IS_STRING) {
            smart_str_append_printf(&payload, "%.*s:%.*s,", (int)ZSTR_LEN(key), ZSTR_VAL(key), (int)Z_STRLEN_P(ent),
                                    Z_STRVAL_P(ent));
            num_fields++;
        }
        (void)h;
    }
    ZEND_HASH_FOREACH_END();
    if (num_fields) {
        ZSTR_LEN(payload.s)--;
    }
    smart_str_appendc(&payload, ')');
    smart_str_appends(&payload, "\"}");

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, ZEND_STRL("/query/service"));
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, ZSTR_VAL(payload.s), ZSTR_LEN(payload.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
    smart_str_free(&payload);
    smart_str_free(&fq_dataset);
}

PHP_METHOD(AnalyticsIndexManager, dropIndex)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;
    zval val2;
    zend_string *dataset;
    zend_string *index;
    const zval *dataverse = NULL;
    zval *options = NULL;
    zend_bool ignore_not_exists_error = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "SS|O!", &dataset, &index, &options,
                                         pcbc_drop_analytics_index_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    if (options) {
        zval ret;
        prop = pcbc_read_property(pcbc_drop_analytics_index_options_ce, options, ("ignore_if_not_exists"), 0, &ret);
        if (prop && Z_TYPE_P(prop) == IS_TRUE) {
            ignore_not_exists_error = 1;
        }
        prop = pcbc_read_property(pcbc_drop_analytics_index_options_ce, options, ("dataverse_name"), 0, &val2);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            dataverse = prop;
        }
    }

    smart_str fq_dataset = {0};
    if (dataverse) {
        char *uncompound = uncompoundDataverseName(Z_STRVAL_P(dataverse), Z_STRLEN_P(dataverse));
        smart_str_append_printf(&fq_dataset, "%.*s.", (int)strlen(uncompound), uncompound);
        free(uncompound);
    }
    smart_str_append_printf(&fq_dataset, "`%.*s`", (int)ZSTR_LEN(dataset), ZSTR_VAL(dataset));

    smart_str payload = {0};
    smart_str_append_printf(&payload, "{\"statement\":\"DROP INDEX %.*s.`%.*s`", (int)ZSTR_LEN(fq_dataset.s),
                            ZSTR_VAL(fq_dataset.s), (int)ZSTR_LEN(index), ZSTR_VAL(index));
    if (ignore_not_exists_error) {
        smart_str_append_printf(&payload, " IF EXISTS");
    }
    smart_str_appends(&payload, "\"}");

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, ZEND_STRL("/query/service"));
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, ZSTR_VAL(payload.s), ZSTR_LEN(payload.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
    smart_str_free(&payload);
    smart_str_free(&fq_dataset);
}

static void httpcb_getAllAnalyticsIndexes(void *ctx, zval *return_value, zval *response)
{
    (void)ctx;
    array_init(return_value);

    if (!response || Z_TYPE_P(response) != IS_ARRAY) {
        return;
    }
    zval *rows = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("results"));
    if (rows && Z_TYPE_P(rows) == IS_ARRAY) {
        zval *entry;
        ZEND_HASH_FOREACH_VAL(HASH_OF(rows), entry)
        {
            zval index;
            zval *val;
            object_init_ex(&index, pcbc_analytics_index_ce);
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("IndexName"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                pcbc_update_property(pcbc_analytics_index_ce, &index, ("name"), val);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("DatasetName"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                pcbc_update_property(pcbc_analytics_index_ce, &index, ("dataset_name"), val);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("DataverseName"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                pcbc_update_property(pcbc_analytics_index_ce, &index, ("dataverse_name"), val);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("IsPrimary"));
            if (val && (Z_TYPE_P(val) == IS_FALSE || Z_TYPE_P(val) == IS_TRUE)) {
                pcbc_update_property(pcbc_analytics_index_ce, &index, ("is_primary"), val);
            } else {
                pcbc_update_property_bool(pcbc_analytics_index_ce, &index, ("is_primary"), 0);
            }
            add_next_index_zval(return_value, &index);
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_METHOD(AnalyticsIndexManager, getAllIndexes)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;

    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, ZEND_STRL("/query/service"));
    char *payload = NULL;
    size_t payload_len;
    payload_len =
        spprintf(&payload, 0,
                 "{\"statement\":\"SELECT d.* FROM Metadata.`Index` d WHERE d.DataverseName <> \\\"Metadata\\\"\"}");
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, payload, payload_len);
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getAllAnalyticsIndexes, NULL);
    efree(payload);
}

PHP_METHOD(AnalyticsIndexManager, connectLink)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;
    zval val2;
    zval *options = NULL;
    const zval *dataverse = NULL;
    zval *link = NULL;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "|O!", &options, pcbc_connect_analytics_link_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    if (options) {
        prop = pcbc_read_property(pcbc_connect_analytics_link_options_ce, options, ("link_name"), 0, &val2);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            link = prop;
        }
        prop = pcbc_read_property(pcbc_connect_analytics_link_options_ce, options, ("dataverse_name"), 0, &val2);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            dataverse = prop;
        }
    }

    smart_str fq_link = {0};
    if (dataverse) {
        char *uncompound = uncompoundDataverseName(Z_STRVAL_P(dataverse), Z_STRLEN_P(dataverse));
        smart_str_append_printf(&fq_link, "%.*s.", (int)strlen(uncompound), uncompound);
        free(uncompound);
    }
    if (link) {
        smart_str_append_printf(&fq_link, "`%.*s`", (int)Z_STRLEN_P(link), Z_STRVAL_P(link));
    } else {
        smart_str_appends(&fq_link, "`Local`");
    }

    smart_str payload = {0};

    smart_str_append_printf(&payload, "{\"statement\":\"CONNECT LINK %.*s", (int)ZSTR_LEN(fq_link.s),
                            ZSTR_VAL(fq_link.s));
    smart_str_appends(&payload, "\"}");

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, ZEND_STRL("/query/service"));
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, ZSTR_VAL(payload.s), ZSTR_LEN(payload.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
    smart_str_free(&payload);
    smart_str_free(&fq_link);
}

PHP_METHOD(AnalyticsIndexManager, disconnectLink)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;
    zval val2;
    zval *options = NULL;
    const zval *dataverse = NULL;
    zval *link = NULL;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "|O!", &options, pcbc_disconnect_analytics_link_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    if (options) {
        prop = pcbc_read_property(pcbc_disconnect_analytics_link_options_ce, options, ("link_name"), 0, &val2);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            link = prop;
        }
        prop = pcbc_read_property(pcbc_disconnect_analytics_link_options_ce, options, ("dataverse_name"), 0, &val2);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            dataverse = prop;
        }
    }

    smart_str fq_link = {0};
    if (dataverse) {
        char *uncompound = uncompoundDataverseName(Z_STRVAL_P(dataverse), Z_STRLEN_P(dataverse));
        smart_str_append_printf(&fq_link, "%.*s.", (int)strlen(uncompound), uncompound);
        free(uncompound);
    }
    if (link) {
        smart_str_append_printf(&fq_link, "`%.*s`", (int)Z_STRLEN_P(link), Z_STRVAL_P(link));
    } else {
        smart_str_appends(&fq_link, "`Local`");
    }

    smart_str payload = {0};

    smart_str_append_printf(&payload, "{\"statement\":\"DISCONNECT LINK %.*s", (int)ZSTR_LEN(fq_link.s),
                            ZSTR_VAL(fq_link.s));
    smart_str_appends(&payload, "\"}");

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, ZEND_STRL("/query/service"));
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    lcb_cmdhttp_body(cmd, ZSTR_VAL(payload.s), ZSTR_LEN(payload.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
    smart_str_free(&payload);
    smart_str_free(&fq_link);
}

PHP_METHOD(AnalyticsIndexManager, getPendingMutations)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;

    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    lcb_cmdhttp_path(cmd, ZEND_STRL("analytics/node/agg/stats/remaining"));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
}

PHP_METHOD(AnalyticsDataset, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval rv;
    const zval *prop = pcbc_read_property(pcbc_analytics_dataset_ce, getThis(), ("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(AnalyticsDataset, dataverseName)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval rv;
    const zval *prop = pcbc_read_property(pcbc_analytics_dataset_ce, getThis(), ("dataverse_name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(AnalyticsDataset, linkName)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval rv;
    const zval *prop = pcbc_read_property(pcbc_analytics_dataset_ce, getThis(), ("link_name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(AnalyticsDataset, bucketName)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval rv;
    const zval *prop = pcbc_read_property(pcbc_analytics_dataset_ce, getThis(), ("bucket_name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_AnalyticsDataset_name, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_AnalyticsDataset_dataverseName, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_AnalyticsDataset_linkName, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_AnalyticsDataset_bucketName, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry analytics_dataset_methods[] = {
    PHP_ME(AnalyticsDataset, name, ai_AnalyticsDataset_name, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsDataset, dataverseName, ai_AnalyticsDataset_dataverseName, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsDataset, linkName, ai_AnalyticsDataset_linkName, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsDataset, bucketName, ai_AnalyticsDataset_bucketName, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(AnalyticsIndex, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval rv;
    const zval *prop = pcbc_read_property(pcbc_analytics_index_ce, getThis(), ("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(AnalyticsIndex, datasetName)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval rv;
    const zval *prop = pcbc_read_property(pcbc_analytics_index_ce, getThis(), ("dataset_name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(AnalyticsIndex, dataverseName)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval rv;
    const zval *prop = pcbc_read_property(pcbc_analytics_index_ce, getThis(), ("dataverse_name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(AnalyticsIndex, isPrimary)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval rv;
    const zval *prop = pcbc_read_property(pcbc_analytics_index_ce, getThis(), ("is_primary"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_AnalyticsIndex_name, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_AnalyticsIndex_datasetName, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_AnalyticsIndex_dataverseName, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_AnalyticsIndex_isPrimary, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry analytics_index_methods[] = {
    PHP_ME(AnalyticsIndex, name, ai_AnalyticsIndex_name, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndex, datasetName, ai_AnalyticsIndex_datasetName, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndex, dataverseName, ai_AnalyticsIndex_dataverseName, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndex, isPrimary, ai_AnalyticsIndex_isPrimary, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsIndexManager_createDataverse, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, dataverseName, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\CreateAnalyticsDataverseOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsIndexManager_dropDataverse, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, dataverseName, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\DropAnalyticsDataverseOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsIndexManager_createDataset, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, datasetName, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, bucketName, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\CreateAnalyticsDatasetOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsIndexManager_dropDataset, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, datasetName, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\DropAnalyticsDatasetOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_AnalyticsIndexManager_getAllDatasets, 0, 1, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsIndexManager_createIndex, 0, 0, 3)
ZEND_ARG_TYPE_INFO(0, datasetName, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, indexName, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, fields, IS_ARRAY, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\CreateAnalyticsIndexOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsIndexManager_dropIndex, 0, 0, 3)
ZEND_ARG_TYPE_INFO(0, datasetName, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, indexName, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\DropAnalyticsIndexOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsIndexManager_connectLink, 0, 0, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\ConnectAnalyticsLinkOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsIndexManager_disconnectLink, 0, 0, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\DisconnectAnalyticsLinkOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_AnalyticsIndexManager_getAllIndexes, 0, 1, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_AnalyticsIndexManager_getPendingMutations, 0, 1, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry analytics_index_manager_methods[] = {
    PHP_ME(AnalyticsIndexManager, createDataverse, ai_AnalyticsIndexManager_createDataverse, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndexManager, dropDataverse, ai_AnalyticsIndexManager_dropDataverse, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndexManager, createDataset, ai_AnalyticsIndexManager_createDataset, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndexManager, dropDataset, ai_AnalyticsIndexManager_dropDataset, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndexManager, getAllDatasets, ai_AnalyticsIndexManager_getAllDatasets, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndexManager, createIndex, ai_AnalyticsIndexManager_createIndex, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndexManager, dropIndex, ai_AnalyticsIndexManager_dropIndex, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndexManager, getAllIndexes, ai_AnalyticsIndexManager_getAllIndexes, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndexManager, connectLink, ai_AnalyticsIndexManager_connectLink, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndexManager, disconnectLink, ai_AnalyticsIndexManager_disconnectLink, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndexManager, getPendingMutations, ai_AnalyticsIndexManager_getPendingMutations, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(CreateAnalyticsDataverseOptions, ignoreIfExists)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_bool(pcbc_create_analytics_dataverse_options_ce, getThis(), ("ignore_if_exists"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateAnalyticsDataverseOptions_ignoreIfExists, 0, 1,
                                       Couchbase\\CreateAnalyticsDataverseOptions, 0)
ZEND_ARG_TYPE_INFO(0, shouldIgnore, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry create_analytics_dataverse_options_methods[] = {
    PHP_ME(CreateAnalyticsDataverseOptions, ignoreIfExists, ai_CreateAnalyticsDataverseOptions_ignoreIfExists, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(DropAnalyticsDataverseOptions, ignoreIfNotExists)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_bool(pcbc_drop_analytics_dataverse_options_ce, getThis(), ("ignore_if_not_exists"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DropAnalyticsDataverseOptions_ignoreIfNotExists, 0, 1,
                                       Couchbase\\DropAnalyticsDataverseOptions, 0)
ZEND_ARG_TYPE_INFO(0, shouldIgnore, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry drop_analytics_dataverse_options_methods[] = {
    PHP_ME(DropAnalyticsDataverseOptions, ignoreIfNotExists, ai_DropAnalyticsDataverseOptions_ignoreIfNotExists, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(CreateAnalyticsDatasetOptions, ignoreIfExists)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_bool(pcbc_create_analytics_dataset_options_ce, getThis(), ("ignore_if_exists"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CreateAnalyticsDatasetOptions, condition)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_create_analytics_dataset_options_ce, getThis(), ("condition"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CreateAnalyticsDatasetOptions, dataverseName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_create_analytics_dataset_options_ce, getThis(), ("dataverse_name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateAnalyticsDatasetOptions_ignoreIfExists, 0, 1,
                                       Couchbase\\CreateAnalyticsDatasetOptions, 0)
ZEND_ARG_TYPE_INFO(0, shouldIgnore, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateAnalyticsDatasetOptions_condition, 0, 1,
                                       Couchbase\\CreateAnalyticsDatasetOptions, 0)
ZEND_ARG_TYPE_INFO(0, condition, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateAnalyticsDatasetOptions_dataverseName, 0, 1,
                                       Couchbase\\CreateAnalyticsDatasetOptions, 0)
ZEND_ARG_TYPE_INFO(0, dataverseName, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry create_analytics_dataset_options_methods[] = {
    PHP_ME(CreateAnalyticsDatasetOptions, ignoreIfExists, ai_CreateAnalyticsDatasetOptions_ignoreIfExists, ZEND_ACC_PUBLIC)
    PHP_ME(CreateAnalyticsDatasetOptions, condition, ai_CreateAnalyticsDatasetOptions_condition, ZEND_ACC_PUBLIC)
    PHP_ME(CreateAnalyticsDatasetOptions, dataverseName, ai_CreateAnalyticsDatasetOptions_dataverseName, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(DropAnalyticsDatasetOptions, ignoreIfNotExists)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_bool(pcbc_drop_analytics_dataset_options_ce, getThis(), ("ignore_if_not_exists"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(DropAnalyticsDatasetOptions, dataverseName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_drop_analytics_dataset_options_ce, getThis(), ("dataverse_name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DropAnalyticsDatasetOptions_ignoreIfNotExists, 0, 1,
                                       Couchbase\\DropAnalyticsDatasetOptions, 0)
ZEND_ARG_TYPE_INFO(0, shouldIgnore, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DropAnalyticsDatasetOptions_dataverseName, 0, 1,
                                       Couchbase\\DropAnalyticsDatasetOptions, 0)
ZEND_ARG_TYPE_INFO(0, dataverseName, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry drop_analytics_dataset_options_methods[] = {
    PHP_ME(DropAnalyticsDatasetOptions, ignoreIfNotExists, ai_DropAnalyticsDatasetOptions_ignoreIfNotExists, ZEND_ACC_PUBLIC)
    PHP_ME(DropAnalyticsDatasetOptions, dataverseName, ai_DropAnalyticsDatasetOptions_dataverseName, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(CreateAnalyticsIndexOptions, ignoreIfExists)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_bool(pcbc_create_analytics_index_options_ce, getThis(), ("ignore_if_exists"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CreateAnalyticsIndexOptions, dataverseName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_create_analytics_index_options_ce, getThis(), ("dataverse_name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateAnalyticsIndexOptions_ignoreIfExists, 0, 1,
                                       Couchbase\\CreateAnalyticsIndexOptions, 0)
ZEND_ARG_TYPE_INFO(0, shouldIgnore, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateAnalyticsIndexOptions_dataverseName, 0, 1,
                                       Couchbase\\CreateAnalyticsIndexOptions, 0)
ZEND_ARG_TYPE_INFO(0, dataverseName, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry create_analytics_index_options_methods[] = {
    PHP_ME(CreateAnalyticsIndexOptions, ignoreIfExists, ai_CreateAnalyticsIndexOptions_ignoreIfExists, ZEND_ACC_PUBLIC)
    PHP_ME(CreateAnalyticsIndexOptions, dataverseName, ai_CreateAnalyticsIndexOptions_dataverseName, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(DropAnalyticsIndexOptions, ignoreIfNotExists)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_bool(pcbc_drop_analytics_index_options_ce, getThis(), ("ignore_if_not_exists"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(DropAnalyticsIndexOptions, dataverseName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_drop_analytics_index_options_ce, getThis(), ("dataverse_name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DropAnalyticsIndexOptions_ignoreIfNotExists, 0, 1,
                                       Couchbase\\DropAnalyticsIndexOptions, 0)
ZEND_ARG_TYPE_INFO(0, shouldIgnore, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DropAnalyticsIndexOptions_dataverseName, 0, 1,
                                       Couchbase\\DropAnalyticsIndexOptions, 0)
ZEND_ARG_TYPE_INFO(0, dataverseName, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry drop_analytics_index_options_methods[] = {
    PHP_ME(DropAnalyticsIndexOptions, ignoreIfNotExists, ai_DropAnalyticsIndexOptions_ignoreIfNotExists, ZEND_ACC_PUBLIC)
    PHP_ME(DropAnalyticsIndexOptions, dataverseName, ai_DropAnalyticsIndexOptions_dataverseName, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(ConnectAnalyticsLinkOptions, dataverseName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_connect_analytics_link_options_ce, getThis(), ("dataverse_name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ConnectAnalyticsLinkOptions, linkName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_connect_analytics_link_options_ce, getThis(), ("link_name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ConnectAnalyticsLinkOptions_dataverseName, 0, 1,
                                       Couchbase\\ConnectAnalyticsLinkOptions, 0)
ZEND_ARG_TYPE_INFO(0, dataverseName, IS_STRING, 0)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ConnectAnalyticsLinkOptions_linkName, 0, 1,
                                       Couchbase\\ConnectAnalyticsLinkOptions, 0)
ZEND_ARG_TYPE_INFO(0, linkName, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry connect_analytics_link_options_methods[] = {
    PHP_ME(ConnectAnalyticsLinkOptions, dataverseName, ai_ConnectAnalyticsLinkOptions_dataverseName, ZEND_ACC_PUBLIC)
    PHP_ME(ConnectAnalyticsLinkOptions, linkName, ai_ConnectAnalyticsLinkOptions_linkName, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(DisconnectAnalyticsLinkOptions, dataverseName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_disconnect_analytics_link_options_ce, getThis(), ("dataverse_name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(DisconnectAnalyticsLinkOptions, linkName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_disconnect_analytics_link_options_ce, getThis(), ("link_name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DisconnectAnalyticsLinkOptions_dataverseName, 0, 1,
                                       Couchbase\\DisconnectAnalyticsLinkOptions, 0)
ZEND_ARG_TYPE_INFO(0, dataverseName, IS_STRING, 0)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DisconnectAnalyticsLinkOptions_linkName, 0, 1,
                                       Couchbase\\DisconnectAnalyticsLinkOptions, 0)
ZEND_ARG_TYPE_INFO(0, linkName, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry disconnect_analytics_link_options_methods[] = {
    PHP_ME(DisconnectAnalyticsLinkOptions, dataverseName, ai_DisconnectAnalyticsLinkOptions_dataverseName, ZEND_ACC_PUBLIC)
    PHP_ME(DisconnectAnalyticsLinkOptions, linkName, ai_DisconnectAnalyticsLinkOptions_linkName, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(AnalyticsIndexManager)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "AnalyticsIndexManager", analytics_index_manager_methods)
    pcbc_analytics_index_manager_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_analytics_index_manager_ce, ZEND_STRL("cluster"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "AnalyticsDataset", analytics_dataset_methods)
    pcbc_analytics_dataset_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_analytics_dataset_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_analytics_dataset_ce, ZEND_STRL("dataverse_name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_analytics_dataset_ce, ZEND_STRL("link_name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_analytics_dataset_ce, ZEND_STRL("bucket_name"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "AnalyticsIndex", analytics_index_methods)
    pcbc_analytics_index_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_analytics_dataset_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_analytics_dataset_ce, ZEND_STRL("dataverse_name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_analytics_dataset_ce, ZEND_STRL("link_name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_analytics_dataset_ce, ZEND_STRL("is_primary"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "CreateAnalyticsDataverseOptions", create_analytics_dataverse_options_methods)
    pcbc_create_analytics_dataverse_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_create_analytics_dataverse_options_ce, ZEND_STRL("ignore_if_exists"),
                               ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DropAnalyticsDataverseOptions", drop_analytics_dataverse_options_methods)
    pcbc_drop_analytics_dataverse_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_drop_analytics_dataverse_options_ce, ZEND_STRL("ignore_if_not_exists"),
                               ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "CreateAnalyticsDatasetOptions", create_analytics_dataset_options_methods)
    pcbc_create_analytics_dataset_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_create_analytics_dataset_options_ce, ZEND_STRL("ignore_if_exists"),
                               ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_create_analytics_dataset_options_ce, ZEND_STRL("condition"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_create_analytics_dataset_options_ce, ZEND_STRL("dataverse_name"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DropAnalyticsDatasetOptions", drop_analytics_dataset_options_methods)
    pcbc_drop_analytics_dataset_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_drop_analytics_dataset_options_ce, ZEND_STRL("ignore_if_not_exists"),
                               ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_drop_analytics_dataset_options_ce, ZEND_STRL("dataverse_name"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "CreateAnalyticsIndexOptions", create_analytics_index_options_methods)
    pcbc_create_analytics_index_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_create_analytics_index_options_ce, ZEND_STRL("ignore_if_exists"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_create_analytics_index_options_ce, ZEND_STRL("dataverse_name"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DropAnalyticsIndexOptions", drop_analytics_index_options_methods)
    pcbc_drop_analytics_index_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_drop_analytics_index_options_ce, ZEND_STRL("ignore_if_not_exists"),
                               ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_drop_analytics_index_options_ce, ZEND_STRL("dataverse_name"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ConnectAnalyticsLinkOptions", connect_analytics_link_options_methods)
    pcbc_connect_analytics_link_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_connect_analytics_link_options_ce, ZEND_STRL("link_name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_connect_analytics_link_options_ce, ZEND_STRL("dataverse_name"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DisconnectAnalyticsLinkOptions", disconnect_analytics_link_options_methods)
    pcbc_disconnect_analytics_link_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_disconnect_analytics_link_options_ce, ZEND_STRL("link_name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_disconnect_analytics_link_options_ce, ZEND_STRL("dataverse_name"),
                               ZEND_ACC_PRIVATE);

    return SUCCESS;
}
