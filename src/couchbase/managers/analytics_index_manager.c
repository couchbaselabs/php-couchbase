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
#include <ext/standard/url.h>
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
zend_class_entry *pcbc_create_analytics_link_options_ce;
zend_class_entry *pcbc_replace_analytics_link_options_ce;
zend_class_entry *pcbc_drop_analytics_link_options_ce;
zend_class_entry *pcbc_get_analytics_links_options_ce;
zend_class_entry *pcbc_encryption_settings_ce;
zend_class_entry *pcbc_analytics_link_interface;
zend_class_entry *pcbc_couchbase_remote_analytics_link_ce;
zend_class_entry *pcbc_azure_blob_external_analytics_link_ce;
zend_class_entry *pcbc_s3_external_analytics_link_ce;
zend_class_entry *pcbc_analytics_link_type_interface;
zend_class_entry *pcbc_analytics_encryption_level_interface;

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

static void encode_couchbase_remote_analytics_link(zval *link, smart_str *path, smart_str *body)
{
    zval payload;
    array_init(&payload);
    add_assoc_string(&payload, "type", "couchbase");
    add_assoc_string(&payload, "encryption", "none");

    zval val;
    zval *prop;
    prop = pcbc_read_property(pcbc_couchbase_remote_analytics_link_ce, link, ("dataverse"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "type", prop);

        if (strchr(Z_STRVAL_P(prop), '/') == NULL) {
            add_assoc_zval(&payload, "dataverse", prop);
            prop = pcbc_read_property(pcbc_couchbase_remote_analytics_link_ce, link, ("name"), 0, &val);
            if (prop && Z_TYPE_P(prop) == IS_STRING) {
                add_assoc_zval(&payload, "name", prop);
            }
        } else {
            smart_str_appendc(path, '/');
            zend_string *encoded_dataverse = php_url_encode(Z_STRVAL_P(prop), Z_STRLEN_P(prop));
            smart_str_append(path, encoded_dataverse);
            efree(encoded_dataverse);

            smart_str_appendc(path, '/');
            prop = pcbc_read_property(pcbc_couchbase_remote_analytics_link_ce, link, ("name"), 0, &val);
            if (prop && Z_TYPE_P(prop) == IS_STRING) {
                zend_string *encoded_name = php_url_encode(Z_STRVAL_P(prop), Z_STRLEN_P(prop));
                smart_str_append(path, encoded_name);
                efree(encoded_name);
            }
        }
    }
    prop = pcbc_read_property(pcbc_couchbase_remote_analytics_link_ce, link, ("hostname"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "hostname", prop);
    }
    prop = pcbc_read_property(pcbc_couchbase_remote_analytics_link_ce, link, ("username"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "username", prop);
    }
    prop = pcbc_read_property(pcbc_couchbase_remote_analytics_link_ce, link, ("password"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "password", prop);
    }
    prop = pcbc_read_property(pcbc_couchbase_remote_analytics_link_ce, link, ("encryption"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_OBJECT && instanceof_function(Z_OBJCE_P(prop), pcbc_encryption_settings_ce)) {
        zval val2;
        zval *prop2;

        prop2 = pcbc_read_property(pcbc_encryption_settings_ce, prop, ("level"), 0, &val2);
        if (prop2 && Z_TYPE_P(prop2) == IS_STRING) {
            add_assoc_zval(&payload, "encryption", prop2);
        }
        prop2 = pcbc_read_property(pcbc_encryption_settings_ce, prop, ("certificate"), 0, &val2);
        if (prop2 && Z_TYPE_P(prop2) == IS_STRING) {
            add_assoc_zval(&payload, "certificate", prop2);
        }
        prop2 = pcbc_read_property(pcbc_encryption_settings_ce, prop, ("client_certificate"), 0, &val2);
        if (prop2 && Z_TYPE_P(prop2) == IS_STRING) {
            add_assoc_zval(&payload, "clientCertificate", prop2);
        }
        prop2 = pcbc_read_property(pcbc_encryption_settings_ce, prop, ("client_key"), 0, &val2);
        if (prop2 && Z_TYPE_P(prop2) == IS_STRING) {
            add_assoc_zval(&payload, "clientKey", prop2);
        }
    }

    int last_error;
    PCBC_JSON_ENCODE(body, &payload, 0, last_error);
    zval_ptr_dtor(&payload);
    if (last_error == 0) {
        smart_str_0(body);
    }
}

static void encode_azure_blob_external_analytics_link(zval *link, smart_str *path, smart_str *body)
{
    zval payload;
    array_init(&payload);
    add_assoc_string(&payload, "type", "azureblob");

    zval val;
    zval *prop;
    prop = pcbc_read_property(pcbc_azure_blob_external_analytics_link_ce, link, ("dataverse"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "type", prop);

        if (strchr(Z_STRVAL_P(prop), '/') == NULL) {
            add_assoc_zval(&payload, "dataverse", prop);
            prop = pcbc_read_property(pcbc_azure_blob_external_analytics_link_ce, link, ("name"), 0, &val);
            if (prop && Z_TYPE_P(prop) == IS_STRING) {
                add_assoc_zval(&payload, "name", prop);
            }
        } else {
            smart_str_appendc(path, '/');
            zend_string *encoded_dataverse = php_url_encode(Z_STRVAL_P(prop), Z_STRLEN_P(prop));
            smart_str_append(path, encoded_dataverse);
            efree(encoded_dataverse);

            smart_str_appendc(path, '/');
            prop = pcbc_read_property(pcbc_azure_blob_external_analytics_link_ce, link, ("name"), 0, &val);
            if (prop && Z_TYPE_P(prop) == IS_STRING) {
                zend_string *encoded_name = php_url_encode(Z_STRVAL_P(prop), Z_STRLEN_P(prop));
                smart_str_append(path, encoded_name);
                efree(encoded_name);
            }
        }
    }
    prop = pcbc_read_property(pcbc_azure_blob_external_analytics_link_ce, link, ("connection_string"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "connectionString", prop);
    } else {
        prop = pcbc_read_property(pcbc_azure_blob_external_analytics_link_ce, link, ("account_name"), 0, &val);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            add_assoc_zval(&payload, "accountName", prop);
        }
        prop = pcbc_read_property(pcbc_azure_blob_external_analytics_link_ce, link, ("account_key"), 0, &val);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            add_assoc_zval(&payload, "accountKey", prop);
        } else {
            prop = pcbc_read_property(pcbc_azure_blob_external_analytics_link_ce, link, ("shared_access_signature"), 0,
                                      &val);
            if (prop && Z_TYPE_P(prop) == IS_STRING) {
                add_assoc_zval(&payload, "sharedAccessSignature", prop);
            }
        }
    }
    prop = pcbc_read_property(pcbc_azure_blob_external_analytics_link_ce, link, ("blob_endpoint"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "blobEndpoint", prop);
    }
    prop = pcbc_read_property(pcbc_azure_blob_external_analytics_link_ce, link, ("endpoint_suffix"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "endpointSuffix", prop);
    }

    int last_error;
    PCBC_JSON_ENCODE(body, &payload, 0, last_error);
    zval_ptr_dtor(&payload);
    if (last_error == 0) {
        smart_str_0(body);
    }
}

static void encode_s3_external_analytics_link(zval *link, smart_str *path, smart_str *body)
{
    zval payload;
    array_init(&payload);
    add_assoc_string(&payload, "type", "s3");

    zval val;
    zval *prop;
    prop = pcbc_read_property(pcbc_s3_external_analytics_link_ce, link, ("dataverse"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "type", prop);

        if (strchr(Z_STRVAL_P(prop), '/') == NULL) {
            add_assoc_zval(&payload, "dataverse", prop);
            prop = pcbc_read_property(pcbc_s3_external_analytics_link_ce, link, ("name"), 0, &val);
            if (prop && Z_TYPE_P(prop) == IS_STRING) {
                add_assoc_zval(&payload, "name", prop);
            }
        } else {
            smart_str_appendc(path, '/');
            zend_string *encoded_dataverse = php_url_encode(Z_STRVAL_P(prop), Z_STRLEN_P(prop));
            smart_str_append(path, encoded_dataverse);
            efree(encoded_dataverse);

            smart_str_appendc(path, '/');
            prop = pcbc_read_property(pcbc_s3_external_analytics_link_ce, link, ("name"), 0, &val);
            if (prop && Z_TYPE_P(prop) == IS_STRING) {
                zend_string *encoded_name = php_url_encode(Z_STRVAL_P(prop), Z_STRLEN_P(prop));
                smart_str_append(path, encoded_name);
                efree(encoded_name);
            }
        }
    }
    prop = pcbc_read_property(pcbc_s3_external_analytics_link_ce, link, ("access_key_id"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "accessKeyId", prop);
    }
    prop = pcbc_read_property(pcbc_s3_external_analytics_link_ce, link, ("secret_access_key"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "secretAccessKey", prop);
    }
    prop = pcbc_read_property(pcbc_s3_external_analytics_link_ce, link, ("region"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "region", prop);
    }
    prop = pcbc_read_property(pcbc_s3_external_analytics_link_ce, link, ("session_token"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "sessionToken", prop);
    }
    prop = pcbc_read_property(pcbc_s3_external_analytics_link_ce, link, ("service_endpoint"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "serviceEndpoint", prop);
    }

    int last_error;
    PCBC_JSON_ENCODE(body, &payload, 0, last_error);
    zval_ptr_dtor(&payload);
    if (last_error == 0) {
        smart_str_0(body);
    }
}

PHP_METHOD(AnalyticsIndexManager, createLink)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;

    zval *link = NULL;
    zval *options = NULL;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "O|O!", &link, pcbc_analytics_link_interface, &options,
                                         pcbc_create_analytics_link_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    smart_str body = {0};
    smart_str path = {0};
    smart_str_appends(&path, "/analytics/link");

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));

    if (instanceof_function(Z_OBJCE_P(link), pcbc_couchbase_remote_analytics_link_ce)) {
        encode_couchbase_remote_analytics_link(link, &path, &body);
    } else if (instanceof_function(Z_OBJCE_P(link), pcbc_azure_blob_external_analytics_link_ce)) {
        encode_azure_blob_external_analytics_link(link, &path, &body);
    } else if (instanceof_function(Z_OBJCE_P(link), pcbc_s3_external_analytics_link_ce)) {
        encode_s3_external_analytics_link(link, &path, &body);
    } else {
        lcb_cmdhttp_destroy(cmd);
        zend_type_error("Unexpected implementation of AnalyticsLink interface");
        RETURN_NULL();
    }

    lcb_cmdhttp_path(cmd, ZSTR_VAL(path.s), ZSTR_LEN(path.s));
    lcb_cmdhttp_body(cmd, ZSTR_VAL(body.s), ZSTR_LEN(body.s));

    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
    smart_str_free(&path);
    smart_str_free(&body);
}

PHP_METHOD(AnalyticsIndexManager, replaceLink)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;

    zval *link = NULL;
    zval *options = NULL;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "O|O!", &link, pcbc_analytics_link_interface, &options,
                                         pcbc_replace_analytics_link_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    smart_str body = {0};
    smart_str path = {0};
    smart_str_appends(&path, "/analytics/link");

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_PUT);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));

    if (instanceof_function(Z_OBJCE_P(link), pcbc_couchbase_remote_analytics_link_ce)) {
        encode_couchbase_remote_analytics_link(link, &path, &body);
    } else if (instanceof_function(Z_OBJCE_P(link), pcbc_azure_blob_external_analytics_link_ce)) {
        encode_azure_blob_external_analytics_link(link, &path, &body);
    } else if (instanceof_function(Z_OBJCE_P(link), pcbc_s3_external_analytics_link_ce)) {
        encode_s3_external_analytics_link(link, &path, &body);
    } else {
        lcb_cmdhttp_destroy(cmd);
        zend_type_error("Unexpected implementation of AnalyticsLink interface");
        RETURN_NULL();
    }

    lcb_cmdhttp_path(cmd, ZSTR_VAL(path.s), ZSTR_LEN(path.s));
    lcb_cmdhttp_body(cmd, ZSTR_VAL(body.s), ZSTR_LEN(body.s));

    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
    smart_str_free(&path);
    smart_str_free(&body);
}

PHP_METHOD(AnalyticsIndexManager, dropLink)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;

    zend_string *link_name = NULL;
    zend_string *dataverse_name = NULL;
    zval *options = NULL;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "SS|O!", &link_name, &dataverse_name, &options,
                                         pcbc_drop_analytics_link_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    smart_str body = {0};
    smart_str path = {0};
    smart_str_appends(&path, "/analytics/link");

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);

    if (strchr(ZSTR_VAL(dataverse_name), '/') != NULL) {
        smart_str_appendc(&path, '/');
        zend_string *encoded_dataverse = php_url_encode(ZSTR_VAL(dataverse_name), ZSTR_LEN(dataverse_name));
        smart_str_append(&path, encoded_dataverse);
        efree(encoded_dataverse);

        smart_str_appendc(&path, '/');
        zend_string *encoded_name = php_url_encode(ZSTR_VAL(link_name), ZSTR_LEN(link_name));
        smart_str_append(&path, encoded_name);
        efree(encoded_name);
    } else {
        zval payload;
        array_init(&payload);

        add_assoc_str(&payload, "dataverse", dataverse_name);
        add_assoc_str(&payload, "name", link_name);

        php_url_encode_hash_ex(HASH_OF(&payload), &body, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, PHP_QUERY_RFC1738);
        zval_ptr_dtor(&payload);
        smart_str_0(&body);

        lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
        lcb_cmdhttp_body(cmd, ZSTR_VAL(body.s), ZSTR_LEN(body.s));
    }
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_DELETE);
    lcb_cmdhttp_path(cmd, ZSTR_VAL(path.s), ZSTR_LEN(path.s));

    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
    smart_str_free(&path);
    smart_str_free(&body);
}

static void httpcb_getAllLinks(void *ctx, zval *return_value, zval *response)
{
    (void)ctx;
    array_init(return_value);

    if (response && Z_TYPE_P(response) == IS_ARRAY) {
        zval *entry;
        ZEND_HASH_FOREACH_VAL(HASH_OF(response), entry)
        {
            zval *val;
            zval link;

            ZVAL_NULL(&link);
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("type"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                if (zend_binary_strcmp(Z_STRVAL_P(val), Z_STRLEN_P(val), ZEND_STRL("s3")) == 0) {
                    object_init_ex(&link, pcbc_s3_external_analytics_link_ce);
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("name"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_s3_external_analytics_link_ce, &link, ("name"), val);
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("dataverse"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_s3_external_analytics_link_ce, &link, ("dataverse"), val);
                    } else {
                        val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("scope"));
                        if (val && Z_TYPE_P(val) == IS_STRING) {
                            pcbc_update_property(pcbc_s3_external_analytics_link_ce, &link, ("dataverse"), val);
                        }
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("accessKeyId"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_s3_external_analytics_link_ce, &link, ("access_key_id"), val);
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("region"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_s3_external_analytics_link_ce, &link, ("region"), val);
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("serviceEndpoint"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_s3_external_analytics_link_ce, &link, ("service_endpoint"), val);
                    }

                } else if (zend_binary_strcmp(Z_STRVAL_P(val), Z_STRLEN_P(val), ZEND_STRL("couchbase")) == 0) {
                    object_init_ex(&link, pcbc_couchbase_remote_analytics_link_ce);
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("name"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_couchbase_remote_analytics_link_ce, &link, ("name"), val);
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("dataverse"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_couchbase_remote_analytics_link_ce, &link, ("dataverse"), val);
                    } else {
                        val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("scope"));
                        if (val && Z_TYPE_P(val) == IS_STRING) {
                            pcbc_update_property(pcbc_couchbase_remote_analytics_link_ce, &link, ("dataverse"), val);
                        }
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("activeHostname"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_couchbase_remote_analytics_link_ce, &link, ("hostname"), val);
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("username"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_couchbase_remote_analytics_link_ce, &link, ("username"), val);
                    }

                    zval settings;
                    object_init_ex(&settings, pcbc_encryption_settings_ce);
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("certificate"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_encryption_settings_ce, &settings, ("certificate"), val);
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("clientCertificate"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_encryption_settings_ce, &settings, ("client_certificate"), val);
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("encryption"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_encryption_settings_ce, &settings, ("level"), val);
                    }
                    pcbc_update_property(pcbc_couchbase_remote_analytics_link_ce, &link, ("encryption"), &settings);

                } else if (zend_binary_strcmp(Z_STRVAL_P(val), Z_STRLEN_P(val), ZEND_STRL("azureblob")) == 0) {
                    object_init_ex(&link, pcbc_azure_blob_external_analytics_link_ce);
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("name"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_azure_blob_external_analytics_link_ce, &link, ("name"), val);
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("dataverse"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_azure_blob_external_analytics_link_ce, &link, ("dataverse"), val);
                    } else {
                        val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("scope"));
                        if (val && Z_TYPE_P(val) == IS_STRING) {
                            pcbc_update_property(pcbc_azure_blob_external_analytics_link_ce, &link, ("dataverse"), val);
                        }
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("accountName"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_azure_blob_external_analytics_link_ce, &link, ("account_name"), val);
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("blobEndpoint"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_azure_blob_external_analytics_link_ce, &link, ("blob_endpoint"), val);
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("endpointSuffix"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        pcbc_update_property(pcbc_azure_blob_external_analytics_link_ce, &link, ("endpoint_suffix"),
                                             val);
                    }
                }
            }
            if (Z_TYPE(link) != IS_NULL) {
                add_next_index_zval(return_value, &link);
            }
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_METHOD(AnalyticsIndexManager, getLinks)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop;
    zval val;
    zval val2;
    zval *options = NULL;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "|O!", &options, pcbc_get_analytics_links_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_analytics_index_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    smart_str path = {0};
    smart_str_appends(&path, "/analytics/link");

    zval payload;
    array_init(&payload);

    if (options) {
        prop = pcbc_read_property(pcbc_get_analytics_links_options_ce, options, ("link_type"), 0, &val2);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            add_assoc_zval(&payload, "type", prop);
        }

        prop = pcbc_read_property(pcbc_get_analytics_links_options_ce, options, ("dataverse"), 0, &val2);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            if (strchr(Z_STRVAL_P(prop), '/') != NULL) {
                smart_str_appendc(&path, '/');
                zend_string *encoded_dataverse = php_url_encode(Z_STRVAL_P(prop), Z_STRLEN_P(prop));
                smart_str_append(&path, encoded_dataverse);
                efree(encoded_dataverse);

                prop = pcbc_read_property(pcbc_get_analytics_links_options_ce, options, ("link_name"), 0, &val2);
                if (prop && Z_TYPE_P(prop) == IS_STRING) {
                    smart_str_appendc(&path, '/');
                    zend_string *encoded_name = php_url_encode(Z_STRVAL_P(prop), Z_STRLEN_P(prop));
                    smart_str_append(&path, encoded_name);
                    efree(encoded_name);
                }
            } else {
                add_assoc_zval(&payload, "dataverse", prop);

                prop = pcbc_read_property(pcbc_get_analytics_links_options_ce, options, ("link_name"), 0, &val2);
                if (prop && Z_TYPE_P(prop) == IS_STRING) {
                    add_assoc_zval(&payload, "name", prop);
                }
            }
        }
    }

    smart_str buf = {0};
    php_url_encode_hash_ex(HASH_OF(&payload), &buf, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, PHP_QUERY_RFC1738);
    zval_ptr_dtor(&payload);
    smart_str_0(&buf);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_ANALYTICS);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    lcb_cmdhttp_path(cmd, ZSTR_VAL(path.s), ZSTR_LEN(path.s));
    if (buf.s) {
        lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
        lcb_cmdhttp_body(cmd, ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
    }
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getAllLinks, NULL);
    smart_str_free(&path);
    smart_str_free(&buf);
}

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

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsIndexManager_createLink, 0, 0, 1)
ZEND_ARG_OBJ_INFO(0, link, Couchbase\\AnalyticsLink, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\CreateAnalyticsLinkOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsIndexManager_replaceLink, 0, 0, 1)
ZEND_ARG_OBJ_INFO(0, link, Couchbase\\AnalyticsLink, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\ReplaceAnalyticsLinkOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsIndexManager_dropLink, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, linkName, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, dataverseName, Couchbase\\AnalyticsLink, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\DropAnalyticsLinkOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_AnalyticsIndexManager_getLinks, 0, 0, 1)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\GetAnalyticsLinksOptions, 1)
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
    PHP_ME(AnalyticsIndexManager, createLink, ai_AnalyticsIndexManager_createLink, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndexManager, replaceLink, ai_AnalyticsIndexManager_replaceLink, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndexManager, dropLink, ai_AnalyticsIndexManager_dropLink, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsIndexManager, getLinks, ai_AnalyticsIndexManager_getLinks, ZEND_ACC_PUBLIC)
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

PHP_METHOD(EncryptionSettings, level)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_encryption_settings_ce, getThis(), ("level"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(EncryptionSettings, certificate)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_encryption_settings_ce, getThis(), ("certificate"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(EncryptionSettings, clientCertificate)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_encryption_settings_ce, getThis(), ("client_certificate"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(EncryptionSettings, clientKey)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_encryption_settings_ce, getThis(), ("client_key"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_EncryptionSettings_level, 0, 1, Couchbase\\EncryptionSettings, 0)
ZEND_ARG_TYPE_INFO(0, level, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_EncryptionSettings_certificate, 0, 1, Couchbase\\EncryptionSettings, 0)
ZEND_ARG_TYPE_INFO(0, certificate, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_EncryptionSettings_clientCertificate, 0, 1, Couchbase\\EncryptionSettings, 0)
ZEND_ARG_TYPE_INFO(0, certificate, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_EncryptionSettings_clientKey, 0, 1, Couchbase\\EncryptionSettings, 0)
ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry encryption_settings_methods[] = {
    PHP_ME(EncryptionSettings, level, ai_EncryptionSettings_level, ZEND_ACC_PUBLIC)
    PHP_ME(EncryptionSettings, certificate, ai_EncryptionSettings_certificate, ZEND_ACC_PUBLIC)
    PHP_ME(EncryptionSettings, clientCertificate, ai_EncryptionSettings_clientCertificate, ZEND_ACC_PUBLIC)
    PHP_ME(EncryptionSettings, clientKey, ai_EncryptionSettings_clientKey, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(CouchbaseRemoteAnalyticsLink, name)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_couchbase_remote_analytics_link_ce, getThis(), ("name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CouchbaseRemoteAnalyticsLink, dataverse)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_couchbase_remote_analytics_link_ce, getThis(), ("dataverse"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CouchbaseRemoteAnalyticsLink, hostname)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_couchbase_remote_analytics_link_ce, getThis(), ("hostname"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CouchbaseRemoteAnalyticsLink, username)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_couchbase_remote_analytics_link_ce, getThis(), ("username"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CouchbaseRemoteAnalyticsLink, password)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_couchbase_remote_analytics_link_ce, getThis(), ("password"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CouchbaseRemoteAnalyticsLink, encryption)
{
    zval *settings = NULL;

    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "O", &settings, pcbc_encryption_settings_ce) == FAILURE) {
        return;
    }

    pcbc_update_property(pcbc_couchbase_remote_analytics_link_ce, getThis(), ("encryption"), settings);

    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CouchbaseRemoteAnalyticsLink_name, 0, 1,
                                       Couchbase\\CouchbaseRemoteAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CouchbaseRemoteAnalyticsLink_dataverse, 0, 1,
                                       Couchbase\\CouchbaseRemoteAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, dataverse, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CouchbaseRemoteAnalyticsLink_hostname, 0, 1,
                                       Couchbase\\CouchbaseRemoteAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, hostname, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CouchbaseRemoteAnalyticsLink_username, 0, 1,
                                       Couchbase\\CouchbaseRemoteAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, username, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CouchbaseRemoteAnalyticsLink_password, 0, 1,
                                       Couchbase\\CouchbaseRemoteAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CouchbaseRemoteAnalyticsLink_encryption, 0, 1,
                                       Couchbase\\CouchbaseRemoteAnalyticsLink, 0)
ZEND_ARG_OBJ_INFO(0, settings, Couchbase\\EncryptionSettings, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry couchbase_remote_analytics_link_methods[] = {
    PHP_ME(CouchbaseRemoteAnalyticsLink, name, ai_CouchbaseRemoteAnalyticsLink_name, ZEND_ACC_PUBLIC)
    PHP_ME(CouchbaseRemoteAnalyticsLink, dataverse, ai_CouchbaseRemoteAnalyticsLink_dataverse, ZEND_ACC_PUBLIC)
    PHP_ME(CouchbaseRemoteAnalyticsLink, hostname, ai_CouchbaseRemoteAnalyticsLink_hostname, ZEND_ACC_PUBLIC)
    PHP_ME(CouchbaseRemoteAnalyticsLink, username, ai_CouchbaseRemoteAnalyticsLink_username, ZEND_ACC_PUBLIC)
    PHP_ME(CouchbaseRemoteAnalyticsLink, password, ai_CouchbaseRemoteAnalyticsLink_password, ZEND_ACC_PUBLIC)
    PHP_ME(CouchbaseRemoteAnalyticsLink, encryption, ai_CouchbaseRemoteAnalyticsLink_encryption, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(AzureBlobExternalAnalyticsLink, name)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AzureBlobExternalAnalyticsLink, dataverse)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("dataverse"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AzureBlobExternalAnalyticsLink, connectionString)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("connection_string"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AzureBlobExternalAnalyticsLink, accountName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("account_name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AzureBlobExternalAnalyticsLink, accountKey)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("account_key"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AzureBlobExternalAnalyticsLink, sharedAccessSignature)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("shared_access_signature"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AzureBlobExternalAnalyticsLink, blobEndpoint)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("blob_endpoint"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(AzureBlobExternalAnalyticsLink, endpointSuffix)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("endoint_suffix"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AzureBlobExternalAnalyticsLink_name, 0, 1,
                                       Couchbase\\AzureBlobExternalAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AzureBlobExternalAnalyticsLink_dataverse, 0, 1,
                                       Couchbase\\AzureBlobExternalAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, dataverse, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AzureBlobExternalAnalyticsLink_connectionString, 0, 1,
                                       Couchbase\\AzureBlobExternalAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, connectionString, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AzureBlobExternalAnalyticsLink_accountName, 0, 1,
                                       Couchbase\\AzureBlobExternalAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, accountName, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AzureBlobExternalAnalyticsLink_accountKey, 0, 1,
                                       Couchbase\\AzureBlobExternalAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, accountKey, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AzureBlobExternalAnalyticsLink_sharedAccessSignature, 0, 1,
                                       Couchbase\\AzureBlobExternalAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, signature, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AzureBlobExternalAnalyticsLink_blobEndpoint, 0, 1,
                                       Couchbase\\AzureBlobExternalAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, blobEndpoint, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_AzureBlobExternalAnalyticsLink_endpointSuffix, 0, 1,
                                       Couchbase\\AzureBlobExternalAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, endpointSuffix, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry azure_blob_external_analytics_link_methods[] = {
    PHP_ME(AzureBlobExternalAnalyticsLink, name, ai_AzureBlobExternalAnalyticsLink_name, ZEND_ACC_PUBLIC)
    PHP_ME(AzureBlobExternalAnalyticsLink, dataverse, ai_AzureBlobExternalAnalyticsLink_dataverse, ZEND_ACC_PUBLIC)
    PHP_ME(AzureBlobExternalAnalyticsLink, connectionString, ai_AzureBlobExternalAnalyticsLink_connectionString, ZEND_ACC_PUBLIC)
    PHP_ME(AzureBlobExternalAnalyticsLink, accountName, ai_AzureBlobExternalAnalyticsLink_accountName, ZEND_ACC_PUBLIC)
    PHP_ME(AzureBlobExternalAnalyticsLink, accountKey, ai_AzureBlobExternalAnalyticsLink_accountKey, ZEND_ACC_PUBLIC)
    PHP_ME(AzureBlobExternalAnalyticsLink, sharedAccessSignature, ai_AzureBlobExternalAnalyticsLink_sharedAccessSignature, ZEND_ACC_PUBLIC)
    PHP_ME(AzureBlobExternalAnalyticsLink, blobEndpoint, ai_AzureBlobExternalAnalyticsLink_blobEndpoint, ZEND_ACC_PUBLIC)
    PHP_ME(AzureBlobExternalAnalyticsLink, endpointSuffix, ai_AzureBlobExternalAnalyticsLink_endpointSuffix, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_S3ExternalAnalyticsLink_name, 0, 1, Couchbase\\S3ExternalAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_S3ExternalAnalyticsLink_dataverse, 0, 1, Couchbase\\S3ExternalAnalyticsLink,
                                       0)
ZEND_ARG_TYPE_INFO(0, dataverse, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_S3ExternalAnalyticsLink_accessKeyId, 0, 1, Couchbase\\S3ExternalAnalyticsLink,
                                       0)
ZEND_ARG_TYPE_INFO(0, accessKeyId, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_S3ExternalAnalyticsLink_secretAccessKey, 0, 1,
                                       Couchbase\\S3ExternalAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, secretAccessKey, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_S3ExternalAnalyticsLink_region, 0, 1, Couchbase\\S3ExternalAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, region, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_S3ExternalAnalyticsLink_sessionToken, 0, 1,
                                       Couchbase\\S3ExternalAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, sessionToken, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_S3ExternalAnalyticsLink_serviceEndpoint, 0, 1,
                                       Couchbase\\S3ExternalAnalyticsLink, 0)
ZEND_ARG_TYPE_INFO(0, serviceEndpoint, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(S3ExternalAnalyticsLink, name)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(S3ExternalAnalyticsLink, dataverse)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("dataverse"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(S3ExternalAnalyticsLink, accessKeyId)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("access_key_id"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(S3ExternalAnalyticsLink, secretAccessKey)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("secret_access_key"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(S3ExternalAnalyticsLink, region)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("region"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(S3ExternalAnalyticsLink, sessionToken)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("session_token"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(S3ExternalAnalyticsLink, serviceEndpoint)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_azure_blob_external_analytics_link_ce, getThis(), ("service_endpoint"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

// clang-format off
zend_function_entry s3_external_analytics_link_methods[] = {
    PHP_ME(S3ExternalAnalyticsLink, name, ai_S3ExternalAnalyticsLink_name, ZEND_ACC_PUBLIC)
    PHP_ME(S3ExternalAnalyticsLink, dataverse, ai_S3ExternalAnalyticsLink_dataverse, ZEND_ACC_PUBLIC)
    PHP_ME(S3ExternalAnalyticsLink, accessKeyId, ai_S3ExternalAnalyticsLink_accessKeyId, ZEND_ACC_PUBLIC)
    PHP_ME(S3ExternalAnalyticsLink, secretAccessKey, ai_S3ExternalAnalyticsLink_secretAccessKey, ZEND_ACC_PUBLIC)
    PHP_ME(S3ExternalAnalyticsLink, region, ai_S3ExternalAnalyticsLink_region, ZEND_ACC_PUBLIC)
    PHP_ME(S3ExternalAnalyticsLink, sessionToken, ai_S3ExternalAnalyticsLink_sessionToken, ZEND_ACC_PUBLIC)
    PHP_ME(S3ExternalAnalyticsLink, serviceEndpoint, ai_S3ExternalAnalyticsLink_serviceEndpoint, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(CreateAnalyticsLinkOptions, timeout)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_create_analytics_link_options_ce, getThis(), ("timeout"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CreateAnalyticsLinkOptions_timeout, 0, 1,
                                       Couchbase\\CreateAnalyticsLinkOptions, 0)
ZEND_ARG_TYPE_INFO(0, timeout, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry create_analytics_link_options_methods[] = {
    PHP_ME(CreateAnalyticsLinkOptions, timeout, ai_CreateAnalyticsLinkOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(ReplaceAnalyticsLinkOptions, timeout)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_replace_analytics_link_options_ce, getThis(), ("timeout"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ReplaceAnalyticsLinkOptions_timeout, 0, 1,
                                       Couchbase\\ReplaceAnalyticsLinkOptions, 0)
ZEND_ARG_TYPE_INFO(0, timeout, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry replace_analytics_link_options_methods[] = {
    PHP_ME(ReplaceAnalyticsLinkOptions, timeout, ai_ReplaceAnalyticsLinkOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(DropAnalyticsLinkOptions, timeout)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_drop_analytics_link_options_ce, getThis(), ("timeout"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DropAnalyticsLinkOptions_timeout, 0, 1, Couchbase\\DropAnalyticsLinkOptions,
                                       0)
ZEND_ARG_TYPE_INFO(0, timeout, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry drop_analytics_link_options_methods[] = {
    PHP_ME(DropAnalyticsLinkOptions, timeout, ai_DropAnalyticsLinkOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(GetAnalyticsLinksOptions, timeout)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_get_analytics_links_options_ce, getThis(), ("timeout"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(GetAnalyticsLinksOptions, linkType)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_get_analytics_links_options_ce, getThis(), ("link_type"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(GetAnalyticsLinksOptions, dataverse)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_get_analytics_links_options_ce, getThis(), ("dataverse"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(GetAnalyticsLinksOptions, name)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_get_analytics_links_options_ce, getThis(), ("name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetAnalyticsLinksOptions_timeout, 0, 1, Couchbase\\GetAnalyticsLinksOptions,
                                       0)
ZEND_ARG_TYPE_INFO(0, timeout, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetAnalyticsLinksOptions_linkType, 0, 1, Couchbase\\GetAnalyticsLinksOptions,
                                       0)
ZEND_ARG_TYPE_INFO(0, type, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetAnalyticsLinksOptions_dataverse, 0, 1, Couchbase\\GetAnalyticsLinksOptions,
                                       0)
ZEND_ARG_TYPE_INFO(0, dataverse, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetAnalyticsLinksOptions_name, 0, 1, Couchbase\\GetAnalyticsLinksOptions, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry get_analytics_links_options_methods[] = {
    PHP_ME(GetAnalyticsLinksOptions, timeout, ai_GetAnalyticsLinksOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(GetAnalyticsLinksOptions, linkType, ai_GetAnalyticsLinksOptions_linkType, ZEND_ACC_PUBLIC)
    PHP_ME(GetAnalyticsLinksOptions, dataverse, ai_GetAnalyticsLinksOptions_dataverse, ZEND_ACC_PUBLIC)
    PHP_ME(GetAnalyticsLinksOptions, name, ai_GetAnalyticsLinksOptions_name, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

static const zend_function_entry pcbc_analytics_link_methods[] = {PHP_FE_END};
static const zend_function_entry pcbc_analytics_link_type_methods[] = {PHP_FE_END};
static const zend_function_entry pcbc_analytics_encryption_level_methods[] = {PHP_FE_END};

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
    zend_declare_property_null(pcbc_analytics_index_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_analytics_index_ce, ZEND_STRL("dataverse_name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_analytics_index_ce, ZEND_STRL("link_name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_analytics_index_ce, ZEND_STRL("is_primary"), ZEND_ACC_PRIVATE);

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

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "EncryptionSettings", encryption_settings_methods)
    pcbc_encryption_settings_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_encryption_settings_ce, ZEND_STRL("level"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_encryption_settings_ce, ZEND_STRL("certificate"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_encryption_settings_ce, ZEND_STRL("client_certificate"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_encryption_settings_ce, ZEND_STRL("client_key"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "AnalyticsLink", pcbc_analytics_link_methods);
    pcbc_analytics_link_interface = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "CouchbaseRemoteAnalyticsLink", couchbase_remote_analytics_link_methods)
    pcbc_couchbase_remote_analytics_link_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_couchbase_remote_analytics_link_ce, 1, pcbc_analytics_link_interface);
    zend_declare_property_null(pcbc_couchbase_remote_analytics_link_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_couchbase_remote_analytics_link_ce, ZEND_STRL("dataverse"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_couchbase_remote_analytics_link_ce, ZEND_STRL("hostname"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_couchbase_remote_analytics_link_ce, ZEND_STRL("username"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_couchbase_remote_analytics_link_ce, ZEND_STRL("password"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_couchbase_remote_analytics_link_ce, ZEND_STRL("encryption"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "AzureBlobExternalAnalyticsLink", azure_blob_external_analytics_link_methods)
    pcbc_azure_blob_external_analytics_link_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_azure_blob_external_analytics_link_ce, 1, pcbc_analytics_link_interface);
    zend_declare_property_null(pcbc_azure_blob_external_analytics_link_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_azure_blob_external_analytics_link_ce, ZEND_STRL("dataverse"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_azure_blob_external_analytics_link_ce, ZEND_STRL("connection_string"),
                               ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_azure_blob_external_analytics_link_ce, ZEND_STRL("account_name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_azure_blob_external_analytics_link_ce, ZEND_STRL("account_key"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_azure_blob_external_analytics_link_ce, ZEND_STRL("shared_access_signature"),
                               ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_azure_blob_external_analytics_link_ce, ZEND_STRL("blob_endpoint"),
                               ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_azure_blob_external_analytics_link_ce, ZEND_STRL("endpoint_suffix"),
                               ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "S3ExternalAnalyticsLink", s3_external_analytics_link_methods)
    pcbc_s3_external_analytics_link_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_s3_external_analytics_link_ce, 1, pcbc_analytics_link_interface);
    zend_declare_property_null(pcbc_s3_external_analytics_link_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_s3_external_analytics_link_ce, ZEND_STRL("dataverse"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_s3_external_analytics_link_ce, ZEND_STRL("access_key_id"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_s3_external_analytics_link_ce, ZEND_STRL("secret_access_key"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_s3_external_analytics_link_ce, ZEND_STRL("region"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_s3_external_analytics_link_ce, ZEND_STRL("session_token"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_s3_external_analytics_link_ce, ZEND_STRL("service_endpoint"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "CreateAnalyticsLinkOptions", create_analytics_link_options_methods)
    pcbc_create_analytics_link_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_create_analytics_link_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ReplaceAnalyticLinkOptions", replace_analytics_link_options_methods)
    pcbc_replace_analytics_link_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_replace_analytics_link_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DropAnalyticsLinkOptions", drop_analytics_link_options_methods)
    pcbc_drop_analytics_link_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_drop_analytics_link_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GetAnalyticsLinksOptions", get_analytics_links_options_methods)
    pcbc_get_analytics_links_options_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_get_analytics_links_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_analytics_links_options_ce, ZEND_STRL("link_type"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_analytics_links_options_ce, ZEND_STRL("dataverse"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_analytics_links_options_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "AnalyticsLinkType", pcbc_analytics_link_type_methods);
    pcbc_analytics_link_type_interface = zend_register_internal_interface(&ce);
    zend_declare_class_constant_string(pcbc_analytics_link_type_interface, ZEND_STRL("COUCHBASE"), "couchbase");
    zend_declare_class_constant_string(pcbc_analytics_link_type_interface, ZEND_STRL("S3"), "s3");
    zend_declare_class_constant_string(pcbc_analytics_link_type_interface, ZEND_STRL("AZURE_BLOB"), "azureblob");

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "AnalyticsEncryptionLevel", pcbc_analytics_encryption_level_methods);
    pcbc_analytics_encryption_level_interface = zend_register_internal_interface(&ce);
    zend_declare_class_constant_string(pcbc_analytics_encryption_level_interface, ZEND_STRL("NONE"), "none");
    zend_declare_class_constant_string(pcbc_analytics_encryption_level_interface, ZEND_STRL("HALF"), "half");
    zend_declare_class_constant_string(pcbc_analytics_encryption_level_interface, ZEND_STRL("FULL"), "full");

    return SUCCESS;
}
