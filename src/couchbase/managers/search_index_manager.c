/**
 *     Copyright 2018-2019 Couchbase, Inc.
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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/search_index_manager", __FILE__, __LINE__

zend_class_entry *pcbc_search_index_manager_ce;
zend_class_entry *pcbc_search_index_ce;

static void parse_index_entry(zval *return_value, zval *response)
{
    object_init_ex(return_value, pcbc_search_index_ce);
    zval *val;
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("name"));
    if (val && Z_TYPE_P(val) == IS_STRING) {
        zend_update_property(pcbc_search_index_ce, return_value, ZEND_STRL("name"), val TSRMLS_CC);
    }
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("uuid"));
    if (val && Z_TYPE_P(val) == IS_STRING) {
        zend_update_property(pcbc_search_index_ce, return_value, ZEND_STRL("uuid"), val TSRMLS_CC);
    }
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("type"));
    if (val && Z_TYPE_P(val) == IS_STRING) {
        zend_update_property(pcbc_search_index_ce, return_value, ZEND_STRL("type"), val TSRMLS_CC);
    }
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("params"));
    if (val) {
        zend_update_property(pcbc_search_index_ce, return_value, ZEND_STRL("params"), val TSRMLS_CC);
    }
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("sourceName"));
    if (val && Z_TYPE_P(val) == IS_STRING) {
        zend_update_property(pcbc_search_index_ce, return_value, ZEND_STRL("source_name"), val TSRMLS_CC);
    }
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("sourceUUID"));
    if (val && Z_TYPE_P(val) == IS_STRING) {
        zend_update_property(pcbc_search_index_ce, return_value, ZEND_STRL("source_uuid"), val TSRMLS_CC);
    }
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("sourceType"));
    if (val && Z_TYPE_P(val) == IS_STRING) {
        zend_update_property(pcbc_search_index_ce, return_value, ZEND_STRL("source_type"), val TSRMLS_CC);
    }
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("sourceParams"));
    if (val) {
        zend_update_property(pcbc_search_index_ce, return_value, ZEND_STRL("source_params"), val TSRMLS_CC);
    }
}

static void httpcb_getAllIndexes(void *ctx, zval *return_value, zval *response)
{
    array_init(return_value);

    zval *toplevel = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("indexDefs"));
    if (!toplevel || Z_TYPE_P(toplevel) != IS_ARRAY) {
        return;
    }
    zval *defs = zend_symtable_str_find(Z_ARRVAL_P(toplevel), ZEND_STRL("indexDefs"));
    if (defs && Z_TYPE_P(defs) == IS_ARRAY) {
        zend_string *string_key = NULL;
        zval *entry;
        ZEND_HASH_FOREACH_STR_KEY_VAL(HASH_OF(defs), string_key, entry)
        {
            zval index;
            parse_index_entry(&index, entry);
            add_assoc_zval_ex(return_value, ZSTR_VAL(string_key), ZSTR_LEN(string_key), &index);
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_METHOD(SearchIndexManager, getAllIndexes)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    const char *path = "/api/index";

    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_search_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_SEARCH);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    lcb_cmdhttp_path(cmd, path, strlen(path));
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getAllIndexes, NULL TSRMLS_CC);
}

static void httpcb_getIndex(void *ctx, zval *return_value, zval *response)
{
    zval *def = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("indexDef"));
    if (def && Z_TYPE_P(def) == IS_ARRAY) {
        parse_index_entry(return_value, def);
    }
}

PHP_METHOD(SearchIndexManager, getIndex)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    int path_len, rv;
    char *path;
    zend_string *name;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_search_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    path_len = spprintf(&path, 0, "/api/index/%.*s", (int)ZSTR_LEN(name), ZSTR_VAL(name));

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_SEARCH);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getIndex, NULL TSRMLS_CC);
    efree(path);
}

PHP_METHOD(SearchIndexManager, dropIndex)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    int rv, path_len;
    char *path;
    zend_string *name;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_search_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    path_len = spprintf(&path, 0, "/api/index/%.*s", (int)ZSTR_LEN(name), ZSTR_VAL(name));

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_SEARCH);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_DELETE);
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(path);
}

PHP_METHOD(SearchIndexManager, upsertIndex)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val, *index, *name, val2;
    int rv, path_len;
    char *path = NULL;
    smart_str buf = {0};
    int last_error;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "O", &index, pcbc_search_index_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_search_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    name = zend_read_property(pcbc_search_index_ce, index, ZEND_STRL("name"), 0, &val2);
    if (!name || Z_TYPE_P(name) != IS_STRING) {
        RETURN_NULL();
    }
    path_len = spprintf(&path, 0, "/api/index/%.*s", (int)Z_STRLEN_P(name), Z_STRVAL_P(name));

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_SEARCH);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_PUT);
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    PCBC_JSON_ENCODE(&buf, index, 0, last_error);
    if (last_error != 0) {
        lcb_cmdhttp_destroy(cmd);
        smart_str_free(&buf);
        efree(path);
        RETURN_NULL();
    } else {
        smart_str_0(&buf);
        lcb_cmdhttp_body(cmd, ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
    }
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(path);
    smart_str_free(&buf);
}

static void httpcb_getIndexedDocumentsCount(void *ctx, zval *return_value, zval *response)
{
    zval *val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("count"));
    if (val && Z_TYPE_P(val) == IS_LONG) {
        ZVAL_LONG(return_value, Z_LVAL_P(val));
    } else {
        ZVAL_LONG(return_value, 0);
    }
}

PHP_METHOD(SearchIndexManager, getIndexedDocumentsCount)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    int rv, path_len;
    char *path;
    zend_string *name;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_search_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    path_len = spprintf(&path, 0, "/api/index/%.*s/count", (int)ZSTR_LEN(name), ZSTR_VAL(name));

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_SEARCH);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getIndexedDocumentsCount, NULL TSRMLS_CC);
    efree(path);
}

PHP_METHOD(SearchIndexManager, pauseIngest)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    int rv, path_len;
    char *path;
    zend_string *name;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_search_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    path_len = spprintf(&path, 0, "/api/index/%.*s/ingestControl/pause", (int)ZSTR_LEN(name), ZSTR_VAL(name));

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_SEARCH);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(path);
}

PHP_METHOD(SearchIndexManager, resumeIngest)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    int rv, path_len;
    char *path;
    zend_string *name;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_search_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    path_len = spprintf(&path, 0, "/api/index/%.*s/ingestControl/resume", (int)ZSTR_LEN(name), ZSTR_VAL(name));

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_SEARCH);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(path);
}

PHP_METHOD(SearchIndexManager, allowQuerying)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    int rv, path_len;
    char *path;
    zend_string *name;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_search_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    path_len = spprintf(&path, 0, "/api/index/%.*s/queryControl/allow", (int)ZSTR_LEN(name), ZSTR_VAL(name));

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_SEARCH);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(path);
}

PHP_METHOD(SearchIndexManager, disallowQuerying)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    int rv, path_len;
    char *path;
    zend_string *name;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_search_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    path_len = spprintf(&path, 0, "/api/index/%.*s/queryControl/disallow", (int)ZSTR_LEN(name), ZSTR_VAL(name));

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_SEARCH);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(path);
}

PHP_METHOD(SearchIndexManager, freezePlan)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    int rv, path_len;
    char *path;
    zend_string *name;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_search_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    path_len = spprintf(&path, 0, "/api/index/%.*s/planFreezeControl/freeze", (int)ZSTR_LEN(name), ZSTR_VAL(name));

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_SEARCH);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(path);
}

PHP_METHOD(SearchIndexManager, unfreezePlan)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    int rv, path_len;
    char *path;
    zend_string *name;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_search_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    path_len = spprintf(&path, 0, "/api/index/%.*s/planFreezeControl/unfreeze", (int)ZSTR_LEN(name), ZSTR_VAL(name));

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_SEARCH);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(path);
}

static void httpcb_analyzeDocument(void *ctx, zval *return_value, zval *response)
{
    zval *val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("analyzed"));
    ZVAL_ZVAL(return_value, val, 1, 0);
}

PHP_METHOD(SearchIndexManager, analyzeDocument)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val, *doc;
    int rv, path_len;
    char *path;
    zend_string *name;
    smart_str buf = {0};
    int last_error;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "Sz", &name, &doc);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_search_index_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    path_len = spprintf(&path, 0, "/api/index/%.*s/analyzeDoc", (int)ZSTR_LEN(name), ZSTR_VAL(name));

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_SEARCH);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    PCBC_JSON_ENCODE(&buf, doc, 0, last_error);
    if (last_error != 0) {
        lcb_cmdhttp_destroy(cmd);
        smart_str_free(&buf);
        efree(path);
        RETURN_NULL();
    } else {
        smart_str_0(&buf);
        lcb_cmdhttp_body(cmd, ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
    }
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_analyzeDocument, NULL TSRMLS_CC);
    efree(path);
    smart_str_free(&buf);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchIndexManager_getAllIndexes, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchIndexManager_getIndex, 0, 1, Couchbase\\SearchIndex, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SearchIndexManager_dropIndex, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SearchIndexManager_upsertIndex, 0, 0, 2)
ZEND_ARG_OBJ_INFO(0, indexDefinition, Couchbase\\SearchIndex, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_SearchIndexManager_getIndexedDocumentsCount, 0, 1, IS_LONG, 0)
ZEND_ARG_TYPE_INFO(0, indexName, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SearchIndexManager_pauseIngest, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, indexName, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SearchIndexManager_resumeIngest, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, indexName, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SearchIndexManager_allowQuerying, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, indexName, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SearchIndexManager_disallowQuerying, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, indexName, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SearchIndexManager_freezePlan, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, indexName, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SearchIndexManager_unfreezePlan, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, indexName, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SearchIndexManager_analyzeDocument, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, indexName, IS_STRING, 0)
ZEND_ARG_INFO(0, document)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry search_index_manager_methods[] = {
    PHP_ME(SearchIndexManager, getIndex, ai_SearchIndexManager_getIndex, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndexManager, getAllIndexes, ai_SearchIndexManager_getAllIndexes, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndexManager, upsertIndex, ai_SearchIndexManager_upsertIndex, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndexManager, dropIndex, ai_SearchIndexManager_dropIndex, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndexManager, getIndexedDocumentsCount, ai_SearchIndexManager_getIndexedDocumentsCount, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndexManager, pauseIngest, ai_SearchIndexManager_pauseIngest, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndexManager, resumeIngest, ai_SearchIndexManager_resumeIngest, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndexManager, allowQuerying, ai_SearchIndexManager_allowQuerying, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndexManager, disallowQuerying, ai_SearchIndexManager_disallowQuerying, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndexManager, freezePlan, ai_SearchIndexManager_freezePlan, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndexManager, unfreezePlan, ai_SearchIndexManager_unfreezePlan, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndexManager, analyzeDocument, ai_SearchIndexManager_analyzeDocument, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(SearchIndex, type)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("type"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(SearchIndex, uuid)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("uuid"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(SearchIndex, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(SearchIndex, params)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("params"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(SearchIndex, sourceType)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("source_type"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(SearchIndex, sourceUuid)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("source_uuid"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(SearchIndex, sourceName)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("source_name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(SearchIndex, sourceParams)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("source_params"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(SearchIndex, setType)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_search_index_ce, getThis(), ZEND_STRL("type"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchIndex, setUuid)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_search_index_ce, getThis(), ZEND_STRL("uuid"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchIndex, setName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_search_index_ce, getThis(), ZEND_STRL("name"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchIndex, setParams)
{
    zval *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "a", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property(pcbc_search_index_ce, getThis(), ZEND_STRL("params"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchIndex, setSourceType)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_search_index_ce, getThis(), ZEND_STRL("source_type"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchIndex, setSourceUuid)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_search_index_ce, getThis(), ZEND_STRL("source_uuid"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchIndex, setSourceName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_search_index_ce, getThis(), ZEND_STRL("source_name"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchIndex, setSourceParams)
{
    zval *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "a", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property(pcbc_search_index_ce, getThis(), ZEND_STRL("source_params"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchIndex, jsonSerialize)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);

    zval *prop, ret;
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("type"), 0, &ret);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(return_value, "type", prop);
    }
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("name"), 0, &ret);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(return_value, "name", prop);
    }
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("uuid"), 0, &ret);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(return_value, "uuid", prop);
    }
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("params"), 0, &ret);
    if (prop && Z_TYPE_P(prop) == IS_ARRAY) {
        add_assoc_zval(return_value, "params", prop);
    }
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("source_type"), 0, &ret);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(return_value, "sourceType", prop);
    }
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("source_name"), 0, &ret);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(return_value, "sourceName", prop);
    }
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("source_uuid"), 0, &ret);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(return_value, "sourceUUID", prop);
    }
    prop = zend_read_property(pcbc_search_index_ce, getThis(), ZEND_STRL("source_params"), 0, &ret);
    if (prop && Z_TYPE_P(prop) == IS_ARRAY) {
        add_assoc_zval(return_value, "sourceParams", prop);
    }
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchIndex_type, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchIndex_uuid, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchIndex_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchIndex_params, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchIndex_sourceType, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchIndex_sourceUuid, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchIndex_sourceName, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchIndex_sourceParams, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchIndex_setType, 0, 1, Couchbase\\SearchIndex, 0)
ZEND_ARG_TYPE_INFO(0, type, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchIndex_setUuid, 0, 1, Couchbase\\SearchIndex, 0)
ZEND_ARG_TYPE_INFO(0, uuid, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchIndex_setName, 0, 1, Couchbase\\SearchIndex, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchIndex_setParams, 0, 1, Couchbase\\SearchIndex, 0)
ZEND_ARG_TYPE_INFO(0, params, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchIndex_setSourceType, 0, 1, Couchbase\\SearchIndex, 0)
ZEND_ARG_TYPE_INFO(0, type, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchIndex_setSourceUuid, 0, 1, Couchbase\\SearchIndex, 0)
ZEND_ARG_TYPE_INFO(0, uuid, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchIndex_setSourceName, 0, 1, Couchbase\\SearchIndex, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchIndex_setSourceParams, 0, 1, Couchbase\\SearchIndex, 0)
ZEND_ARG_TYPE_INFO(0, params, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SearchIndex_jsonSerialize, 0, 0, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry search_index_methods[] = {
    PHP_ME(SearchIndex, type, ai_SearchIndex_type, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, uuid, ai_SearchIndex_uuid, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, name, ai_SearchIndex_name, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, params, ai_SearchIndex_params, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, sourceType, ai_SearchIndex_sourceType, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, sourceUuid, ai_SearchIndex_sourceUuid, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, sourceName, ai_SearchIndex_sourceName, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, sourceParams, ai_SearchIndex_sourceParams, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, setType, ai_SearchIndex_setType, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, setUuid, ai_SearchIndex_setUuid, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, setName, ai_SearchIndex_setName, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, setParams, ai_SearchIndex_setParams, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, setSourceType, ai_SearchIndex_setSourceType, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, setSourceUuid, ai_SearchIndex_setSourceUuid, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, setSourceName, ai_SearchIndex_setSourceName, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, setSourceParams, ai_SearchIndex_setSourceParams, ZEND_ACC_PUBLIC)
    PHP_ME(SearchIndex, jsonSerialize, ai_SearchIndex_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(SearchIndexManager)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchIndexManager", search_index_manager_methods);
    pcbc_search_index_manager_ce = zend_register_internal_class(&ce TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchIndex", search_index_methods);
    pcbc_search_index_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_class_implements(pcbc_search_index_ce TSRMLS_CC, 1, pcbc_json_serializable_ce);
    zend_declare_property_null(pcbc_search_index_ce, ZEND_STRL("type"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_index_ce, ZEND_STRL("uuid"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_index_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_index_ce, ZEND_STRL("params"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_index_ce, ZEND_STRL("source_type"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_index_ce, ZEND_STRL("source_uuid"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_index_ce, ZEND_STRL("source_name"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_index_ce, ZEND_STRL("source_params"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}
