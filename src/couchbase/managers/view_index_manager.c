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

#define LOGARGS(manager, lvl) LCB_LOG_##lvl, manager->conn->lcb, "pcbc/view_index_manager", __FILE__, __LINE__

zend_class_entry *pcbc_view_index_manager_ce;
zend_class_entry *pcbc_design_document_ce;
zend_class_entry *pcbc_view_ce;

static void httpcb_getDesignDocument(void *ctx, zval *return_value, zval *response)
{
    zval view_prop;
    object_init_ex(return_value, pcbc_design_document_ce);
    array_init(&view_prop);
    zend_update_property(pcbc_design_document_ce, return_value, ZEND_STRL("views"), &view_prop TSRMLS_CC);
    zval_delref_p(&view_prop);

    zval *views = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("views"));
    if (views && Z_TYPE_P(views) == IS_ARRAY) {
        zend_string *string_key = NULL;
        zval *entry;
        ZEND_HASH_FOREACH_STR_KEY_VAL(HASH_OF(views), string_key, entry)
        {
            zval view, *val;
            object_init_ex(&view, pcbc_view_ce);
            zend_update_property_str(pcbc_view_ce, &view, ZEND_STRL("name"), string_key TSRMLS_CC);
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("map"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                zend_update_property(pcbc_view_ce, &view, ZEND_STRL("map"), val TSRMLS_CC);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("reduce"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                zend_update_property(pcbc_view_ce, &view, ZEND_STRL("reduce"), val TSRMLS_CC);
            }
            add_assoc_zval_ex(&view_prop, ZSTR_VAL(string_key), ZSTR_LEN(string_key), &view);
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_METHOD(ViewIndexManager, getDesignDocument)
{
    pcbc_bucket_t *bucket = NULL;
    zval *prop, val;
    zend_string *name;
    char *path;
    int rv, path_len;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        return;
    }

    prop = zend_read_property(pcbc_view_index_manager_ce, getThis(), ZEND_STRL("bucket"), 0, &val);
    bucket = Z_BUCKET_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_VIEW);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    path_len = spprintf(&path, 0, "/%.*s", (int)ZSTR_LEN(name), ZSTR_VAL(name));
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, bucket->conn->lcb, cmd, 1, NULL, httpcb_getDesignDocument, NULL TSRMLS_CC);
    efree(path);
    zend_update_property_str(pcbc_design_document_ce, return_value, ZEND_STRL("name"), name TSRMLS_CC);
}

static void parse_ddoc_entry(zval *return_value, zval *response)
{
    zval view_prop;
    object_init_ex(return_value, pcbc_design_document_ce);
    array_init(&view_prop);
    zend_update_property(pcbc_design_document_ce, return_value, ZEND_STRL("views"), &view_prop TSRMLS_CC);
    zval_delref_p(&view_prop);
    zval *doc = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("doc"));
    if (doc && Z_TYPE_P(doc) == IS_ARRAY) {
        {
            zval *meta = zend_symtable_str_find(Z_ARRVAL_P(doc), ZEND_STRL("meta"));
            if (meta && Z_TYPE_P(meta) == IS_ARRAY) {
                zval *val;
                val = zend_symtable_str_find(Z_ARRVAL_P(meta), ZEND_STRL("id"));
                if (val && Z_TYPE_P(val) == IS_STRING) {
                    zend_update_property(pcbc_design_document_ce, return_value, ZEND_STRL("name"), val TSRMLS_CC);
                }
            }
        }
        {
            zval *json = zend_symtable_str_find(Z_ARRVAL_P(doc), ZEND_STRL("json"));
            if (json && Z_TYPE_P(json) == IS_ARRAY) {
                zval *views = zend_symtable_str_find(Z_ARRVAL_P(json), ZEND_STRL("views"));
                if (views && Z_TYPE_P(views) == IS_ARRAY) {
                    zend_string *string_key = NULL;
                    zval *entry;
                    ZEND_HASH_FOREACH_STR_KEY_VAL(HASH_OF(views), string_key, entry)
                    {
                        zval view, *val;
                        object_init_ex(&view, pcbc_view_ce);
                        zend_update_property_str(pcbc_view_ce, &view, ZEND_STRL("name"), string_key TSRMLS_CC);
                        val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("map"));
                        if (val && Z_TYPE_P(val) == IS_STRING) {
                            zend_update_property(pcbc_view_ce, &view, ZEND_STRL("map"), val TSRMLS_CC);
                        }
                        val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("reduce"));
                        if (val && Z_TYPE_P(val) == IS_STRING) {
                            zend_update_property(pcbc_view_ce, &view, ZEND_STRL("reduce"), val TSRMLS_CC);
                        }
                        add_assoc_zval_ex(&view_prop, ZSTR_VAL(string_key), ZSTR_LEN(string_key), &view);
                    }
                    ZEND_HASH_FOREACH_END();
                }
            }
        }
    }
}

static void httpcb_getAllDesignDocuments(void *ctx, zval *return_value, zval *response)
{
    array_init(return_value);

    zval *rows = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("rows"));
    if (rows && Z_TYPE_P(rows) == IS_ARRAY) {
        zval *entry;
        ZEND_HASH_FOREACH_VAL(HASH_OF(rows), entry)
        {
            zval bs;
            parse_ddoc_entry(&bs, entry);
            add_next_index_zval(return_value, &bs);
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_METHOD(ViewIndexManager, getAllDesignDocuments)
{
    pcbc_bucket_t *bucket = NULL;
    zval *prop, val;
    char *path;
    int path_len;

    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    prop = zend_read_property(pcbc_view_index_manager_ce, getThis(), ZEND_STRL("bucket"), 0, &val);
    bucket = Z_BUCKET_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    path_len = spprintf(&path, 0, "/pools/default/buckets/%s/ddocs", bucket->conn->bucketname);
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, bucket->conn->lcb, cmd, 1, NULL, httpcb_getAllDesignDocuments, NULL TSRMLS_CC);
    efree(path);
}

PHP_METHOD(ViewIndexManager, upsertDesignDocument)
{
    pcbc_bucket_t *bucket = NULL;
    zval *prop, val, rv;
    char *path;
    int path_len = 0;
    zval *document;
    smart_str buf = {0};
    int last_error;

    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "O", &document, pcbc_design_document_ce) == FAILURE) {
        return;
    }

    prop = zend_read_property(pcbc_view_index_manager_ce, getThis(), ZEND_STRL("bucket"), 0, &val);
    bucket = Z_BUCKET_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_VIEW);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_PUT);
    prop = zend_read_property(pcbc_design_document_ce, document, ZEND_STRL("name"), 0, &rv);
    path_len = spprintf(&path, 0, "/%.*s", (int)Z_STRLEN_P(prop), Z_STRVAL_P(prop));
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_JSON, strlen(PCBC_CONTENT_TYPE_JSON));
    PCBC_JSON_ENCODE(&buf, document, 0, last_error);
    if (last_error != 0) {
        pcbc_log(LOGARGS(bucket, WARN), "Failed to encode design document as JSON: json_last_error=%d", last_error);
        lcb_cmdhttp_destroy(cmd);
        smart_str_free(&buf);
        efree(path);
        RETURN_NULL();
    } else {
        smart_str_0(&buf);
        lcb_cmdhttp_body(cmd, ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
    }
    pcbc_http_request(return_value, bucket->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(path);
    smart_str_free(&buf);
}

PHP_METHOD(ViewIndexManager, dropDesignDocument)
{
    pcbc_bucket_t *bucket = NULL;
    zval *prop, val;
    char *path;
    zend_string *name;
    int rv, path_len;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        return;
    }

    prop = zend_read_property(pcbc_view_index_manager_ce, getThis(), ZEND_STRL("bucket"), 0, &val);
    bucket = Z_BUCKET_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_VIEW);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_DELETE);
    path_len = spprintf(&path, 0, "/%*s", (int)ZSTR_LEN(name), ZSTR_VAL(name));
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, bucket->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(path);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_ViewIndexManager_getAllDesignDocuments, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewIndexManager_dropDesignDocument, 0, 0, 1)
ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ViewIndexManager_upsertDesignDocument, 0, 0, 1)
ZEND_ARG_OBJ_INFO(0, document, Couchbase\\DesignDocument, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ViewIndexManager_getDesignDocument, 0, 1, Couchbase\\DesignDocument, 0)
ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry view_index_manager_methods[] = {
    PHP_ME(ViewIndexManager, getAllDesignDocuments, ai_ViewIndexManager_getAllDesignDocuments, ZEND_ACC_PUBLIC)
    PHP_ME(ViewIndexManager, getDesignDocument, ai_ViewIndexManager_getDesignDocument, ZEND_ACC_PUBLIC)
    PHP_ME(ViewIndexManager, dropDesignDocument, ai_ViewIndexManager_dropDesignDocument, ZEND_ACC_PUBLIC)
    PHP_ME(ViewIndexManager, upsertDesignDocument, ai_ViewIndexManager_upsertDesignDocument, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(DesignDocument, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);

    zval views;
    array_init(&views);
    add_assoc_zval(return_value, "views", &views);
    zval_delref_p(&views);

    zval *prop, ret;
    prop = zend_read_property(pcbc_design_document_ce, getThis(), ZEND_STRL("views"), 0, &ret);
    if (prop && Z_TYPE_P(prop) == IS_ARRAY) {
        zend_string *string_key = NULL;
        zval *entry;
        ZEND_HASH_FOREACH_STR_KEY_VAL(HASH_OF(prop), string_key, entry)
        {
            zval view, *val, ret;
            array_init(&view);
            val = zend_read_property(pcbc_view_ce, entry, ZEND_STRL("map"), 0, &ret);
            if (val && Z_TYPE_P(val)) {
                add_assoc_zval(&view, "map", val);
            }
            val = zend_read_property(pcbc_view_ce, entry, ZEND_STRL("reduce"), 0, &ret);
            if (val && Z_TYPE_P(val)) {
                add_assoc_zval(&view, "reduce", val);
            }
            zval_addref_p(&views);
            add_assoc_zval_ex(&views, ZSTR_VAL(string_key), ZSTR_LEN(string_key), &view);
        }
        ZEND_HASH_FOREACH_END();
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_DesignDocument_jsonSerialize, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_DesignDocument_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_DesignDocument_views, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DesignDocument_setName, 0, 1, Couchbase\\DesignDocument, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DesignDocument_setViews, 0, 1, Couchbase\\DesignDocument, 0)
ZEND_ARG_TYPE_INFO(0, views, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(DesignDocument, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_design_document_ce, getThis(), ZEND_STRL("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(DesignDocument, views)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_design_document_ce, getThis(), ZEND_STRL("views"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(DesignDocument, setName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_design_document_ce, getThis(), ZEND_STRL("name"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(DesignDocument, setViews)
{
    zval *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "a", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property(pcbc_design_document_ce, getThis(), ZEND_STRL("views"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

// clang-format off
zend_function_entry design_document_methods[] = {
    PHP_ME(DesignDocument, name, ai_DesignDocument_name, ZEND_ACC_PUBLIC)
    PHP_ME(DesignDocument, views, ai_DesignDocument_views, ZEND_ACC_PUBLIC)
    PHP_ME(DesignDocument, setName, ai_DesignDocument_setName, ZEND_ACC_PUBLIC)
    PHP_ME(DesignDocument, setViews, ai_DesignDocument_setViews, ZEND_ACC_PUBLIC)
    PHP_ME(DesignDocument, jsonSerialize, ai_DesignDocument_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_View_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_View_map, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_View_reduce, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_View_setName, 0, 1, Couchbase\\View, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_View_setMap, 0, 1, Couchbase\\View, 0)
ZEND_ARG_TYPE_INFO(0, map_js_code, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_View_setReduce, 0, 1, Couchbase\\View, 0)
ZEND_ARG_TYPE_INFO(0, reduce_js_code, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(View, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_view_ce, getThis(), ZEND_STRL("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(View, map)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_view_ce, getThis(), ZEND_STRL("map"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(View, reduce)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_view_ce, getThis(), ZEND_STRL("reduce"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(View, setName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_view_ce, getThis(), ZEND_STRL("name"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(View, setMap)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_view_ce, getThis(), ZEND_STRL("map"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(View, setReduce)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_view_ce, getThis(), ZEND_STRL("reduce"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

// clang-format off
zend_function_entry view_methods[] = {
    PHP_ME(View, name, ai_View_name, ZEND_ACC_PUBLIC)
    PHP_ME(View, map, ai_View_map, ZEND_ACC_PUBLIC)
    PHP_ME(View, reduce, ai_View_reduce, ZEND_ACC_PUBLIC)
    PHP_ME(View, setName, ai_View_setName, ZEND_ACC_PUBLIC)
    PHP_ME(View, setMap, ai_View_setMap, ZEND_ACC_PUBLIC)
    PHP_ME(View, setReduce, ai_View_setReduce, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(ViewIndexManager)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ViewIndexManager", view_index_manager_methods);
    pcbc_view_index_manager_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_view_index_manager_ce, ZEND_STRL("bucket"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DesignDocument", design_document_methods);
    pcbc_design_document_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_class_implements(pcbc_design_document_ce TSRMLS_CC, 1, pcbc_json_serializable_ce);
    zend_declare_property_null(pcbc_design_document_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_design_document_ce, ZEND_STRL("views"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "View", view_methods);
    pcbc_view_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_view_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_view_ce, ZEND_STRL("map"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_view_ce, ZEND_STRL("reduce"), ZEND_ACC_PRIVATE TSRMLS_CC);
    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
