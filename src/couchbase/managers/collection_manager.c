/**
 *     Copyright 2020 Couchbase, Inc.
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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/collection_manager", __FILE__, __LINE__

zend_class_entry *pcbc_collection_manager_ce;
zend_class_entry *pcbc_scope_spec_ce;
zend_class_entry *pcbc_collection_spec_ce;

static void httpcb_getScope(void *ctx, zval *return_value, zval *response)
{
    if (!response || ZVAL_IS_NULL(response)) {
        ZVAL_NULL(return_value);
        return;
    }
    object_init_ex(return_value, pcbc_scope_spec_ce);
    zval *val, *scope_name;

    scope_name = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("name"));
    if (!scope_name || Z_TYPE_P(scope_name) != IS_STRING) {
        return;
    }
    pcbc_update_property(pcbc_scope_spec_ce, return_value, ("name"), scope_name);
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("uid"));
    if (val && Z_TYPE_P(val) == IS_STRING) {
        zend_long uid = ZEND_STRTOL(Z_STRVAL_P(val), NULL, 16);
        pcbc_update_property_long(pcbc_scope_spec_ce, return_value, ("uid"), uid);
    }
    zval collections;
    array_init(&collections);
    zval *entries = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("collections"));
    if (entries && Z_TYPE_P(entries) == IS_ARRAY) {
        zval *entry;
        ZEND_HASH_FOREACH_VAL(HASH_OF(entries), entry)
        {
            zval collection;
            object_init_ex(&collection, pcbc_collection_spec_ce);
            pcbc_update_property(pcbc_collection_spec_ce, &collection, ("scope_name"), scope_name);
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("name"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                pcbc_update_property(pcbc_collection_spec_ce, &collection, ("name"), val);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("uid"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                zend_long uid = ZEND_STRTOL(Z_STRVAL_P(val), NULL, 16);
                pcbc_update_property_long(pcbc_scope_spec_ce, return_value, ("uid"), uid);
            }
            add_next_index_zval(&collections, &collection);
        }
        ZEND_HASH_FOREACH_END();
    }
    pcbc_update_property(pcbc_scope_spec_ce, return_value, ("collections"), &collections);
    zval_delref_p(&collections);
}

static void httpcb_getAllScopes(void *ctx, zval *return_value, zval *response)
{
    array_init(return_value);

    if (!response || Z_TYPE_P(response) != IS_ARRAY) {
        return;
    }
    zval *rows = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("scopes"));
    if (rows && Z_TYPE_P(rows) == IS_ARRAY) {
        zval *entry;
        ZEND_HASH_FOREACH_VAL(HASH_OF(rows), entry)
        {
            zval scope;
            httpcb_getScope(ctx, &scope, entry);
            add_next_index_zval(return_value, &scope);
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_METHOD(CollectionManager, getAllScopes)
{
    pcbc_bucket_t *bucket = NULL;
    zval *prop, val;
    char *path;
    size_t path_len;

    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_collection_manager_ce, getThis(), ("bucket"), 0, &val);
    bucket = Z_BUCKET_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    path_len = spprintf(&path, 0, "/pools/default/buckets/%s/collections", bucket->conn->bucketname);
    lcb_cmdhttp_path(cmd, path, path_len);
    pcbc_http_request(return_value, bucket->conn->lcb, cmd, 1, NULL, httpcb_getAllScopes, NULL);
    efree(path);
}

static void httpcb_getSingleScope(void *ctx, zval *return_value, zval *response)
{

    const char *scope_name = Z_STRVAL_P(return_value);
    size_t scope_len = Z_STRLEN_P(return_value);

    if (!response || Z_TYPE_P(response) != IS_ARRAY) {
        return;
    }
    zval *rows = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("scopes"));
    if (rows && Z_TYPE_P(rows) == IS_ARRAY) {
        zval *entry;
        ZEND_HASH_FOREACH_VAL(HASH_OF(rows), entry)
        {
            zval *name = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("name"));
            if (!name || Z_TYPE_P(name) != IS_STRING) {
                continue;
            }
            if (zend_binary_strcmp(Z_STRVAL_P(name), Z_STRLEN_P(name), scope_name, scope_len) == 0) {
                httpcb_getScope(ctx, return_value, entry);
                return;
            }
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_METHOD(CollectionManager, getScope)
{
    pcbc_bucket_t *bucket = NULL;
    zval *prop, val;
    zval *scope;
    char *path;
    size_t path_len;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "z", &scope);
    if (rv == FAILURE || Z_TYPE_P(scope) != IS_STRING) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_collection_manager_ce, getThis(), ("bucket"), 0, &val);
    bucket = Z_BUCKET_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    path_len = spprintf(&path, 0, "/pools/default/buckets/%s/collections", bucket->conn->bucketname);
    lcb_cmdhttp_path(cmd, path, path_len);
    ZVAL_ZVAL(return_value, scope, 0, NULL);
    pcbc_http_request(return_value, bucket->conn->lcb, cmd, 1, NULL, httpcb_getSingleScope, NULL);
    efree(path);
}

PHP_METHOD(CollectionManager, createScope)
{
    pcbc_bucket_t *bucket = NULL;
    zval *prop, val;
    zend_string *scope;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &scope);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_collection_manager_ce, getThis(), ("bucket"), 0, &val);
    bucket = Z_BUCKET_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    char *path;
    size_t path_len;
    path_len = spprintf(&path, 0, "/pools/default/buckets/%s/collections", bucket->conn->bucketname);
    lcb_cmdhttp_path(cmd, path, path_len);
    char *payload;
    size_t payload_len;
    zend_string *str = php_url_encode(ZSTR_VAL(scope), ZSTR_LEN(scope));
    payload_len = spprintf(&payload, 0, "name=%.*s", (int)ZSTR_LEN(str), ZSTR_VAL(str));
    zend_string_free(str);
    lcb_cmdhttp_body(cmd, payload, payload_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, bucket->conn->lcb, cmd, 1, NULL, NULL, NULL);
    efree(payload);
    efree(path);
}

PHP_METHOD(CollectionManager, dropScope)
{
    pcbc_bucket_t *bucket = NULL;
    zval *prop, val;
    zend_string *scope;
    char *path;
    size_t path_len;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &scope);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_collection_manager_ce, getThis(), ("bucket"), 0, &val);
    bucket = Z_BUCKET_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_DELETE);
    path_len = spprintf(&path, 0, "/pools/default/buckets/%s/collections/%.*s", bucket->conn->bucketname,
                        (int)ZSTR_LEN(scope), ZSTR_VAL(scope));
    lcb_cmdhttp_path(cmd, path, path_len);
    pcbc_http_request(return_value, bucket->conn->lcb, cmd, 1, NULL, NULL, NULL);
    efree(path);
}

PHP_METHOD(CollectionManager, createCollection)
{
    pcbc_bucket_t *bucket = NULL;
    zval *prop, val, val1, val2, val3;
    zval *collection, *name, *scope_name, *max_expiry;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "O", &collection, pcbc_collection_spec_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_collection_manager_ce, getThis(), ("bucket"), 0, &val);
    bucket = Z_BUCKET_OBJ_P(prop);

    name = pcbc_read_property(pcbc_collection_spec_ce, collection, ("name"), 0, &val1);
    scope_name = pcbc_read_property(pcbc_collection_spec_ce, collection, ("scope_name"), 0, &val2);
    if (name == NULL || Z_TYPE_P(name) != IS_STRING || scope_name == NULL || Z_TYPE_P(scope_name) != IS_STRING) {
        RETURN_NULL();
    }
    max_expiry = pcbc_read_property(pcbc_collection_spec_ce, collection, ("max_expiry"), 0, &val3);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    char *path;
    size_t path_len;
    path_len = spprintf(&path, 0, "/pools/default/buckets/%s/collections/%.*s", bucket->conn->bucketname,
                        (int)Z_STRLEN_P(scope_name), Z_STRVAL_P(scope_name));
    lcb_cmdhttp_path(cmd, path, path_len);
    char *payload;
    size_t payload_len;
    zend_string *str = php_url_encode(Z_STRVAL_P(name), Z_STRLEN_P(name));
    payload_len = spprintf(&payload, 0, "name=%.*s", (int)ZSTR_LEN(str), ZSTR_VAL(str));
    zend_string_free(str);
    if (Z_TYPE_P(max_expiry) == IS_LONG) {
        payload_len = spprintf(&payload, 0, "&maxTTL=%d", (int)Z_LVAL_P(max_expiry));
    }
    lcb_cmdhttp_body(cmd, payload, payload_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, bucket->conn->lcb, cmd, 1, NULL, NULL, NULL);
    efree(payload);
    efree(path);
}

PHP_METHOD(CollectionManager, dropCollection)
{

    pcbc_bucket_t *bucket = NULL;
    zval *prop, val, *collection, *name, *scope_name, val1, val2;
    char *path;
    size_t path_len;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "O", &collection, pcbc_collection_spec_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = pcbc_read_property(pcbc_collection_manager_ce, getThis(), ("bucket"), 0, &val);
    bucket = Z_BUCKET_OBJ_P(prop);

    name = pcbc_read_property(pcbc_collection_spec_ce, collection, ("name"), 0, &val1);
    scope_name = pcbc_read_property(pcbc_collection_spec_ce, collection, ("scope_name"), 0, &val2);
    if (name == NULL || Z_TYPE_P(name) != IS_STRING || scope_name == NULL || Z_TYPE_P(scope_name) != IS_STRING) {
        RETURN_NULL();
    }

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_DELETE);
    path_len = spprintf(&path, 0, "/pools/default/buckets/%s/collections/%.*s/%.*s", bucket->conn->bucketname,
                        (int)Z_STRLEN_P(scope_name), Z_STRVAL_P(scope_name), (int)Z_STRLEN_P(name), Z_STRVAL_P(name));
    lcb_cmdhttp_path(cmd, path, path_len);
    pcbc_http_request(return_value, bucket->conn->lcb, cmd, 1, NULL, NULL, NULL);
    efree(path);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CollectionManager_getScope, 0, 1, Couchbase\\ScopeSpec, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_CollectionManager_getAllScopes, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_CollectionManager_createScope, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_CollectionManager_dropScope, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_CollectionManager_createCollection, 0, 0, 1)
ZEND_ARG_OBJ_INFO(0, collection, Couchbase\\CollectionSpec, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_CollectionManager_dropCollection, 0, 0, 1)
ZEND_ARG_OBJ_INFO(0, collection, Couchbase\\CollectionSpec, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry collection_manager_methods[] = {
    PHP_ME(CollectionManager, getScope, ai_CollectionManager_getScope, ZEND_ACC_PUBLIC)
    PHP_ME(CollectionManager, getAllScopes, ai_CollectionManager_getAllScopes, ZEND_ACC_PUBLIC)
    PHP_ME(CollectionManager, createScope, ai_CollectionManager_createScope, ZEND_ACC_PUBLIC)
    PHP_ME(CollectionManager, dropScope, ai_CollectionManager_dropScope, ZEND_ACC_PUBLIC)
    PHP_ME(CollectionManager, createCollection, ai_CollectionManager_createCollection, ZEND_ACC_PUBLIC)
    PHP_ME(CollectionManager, dropCollection, ai_CollectionManager_dropCollection, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(ScopeSpec, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_scope_spec_ce, getThis(), ("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(ScopeSpec, collections)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_scope_spec_ce, getThis(), ("collections"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_ScopeSpec_name, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_ScopeSpec_collections, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry scope_spec_methods[] = {
    PHP_ME(ScopeSpec, name, ai_ScopeSpec_name, ZEND_ACC_PUBLIC)
    PHP_ME(ScopeSpec, collections, ai_ScopeSpec_collections, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(CollectionSpec, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_collection_spec_ce, getThis(), ("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(CollectionSpec, scopeName)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_collection_spec_ce, getThis(), ("scope_name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(CollectionSpec, setName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_collection_spec_ce, getThis(), ("name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CollectionSpec, setScopeName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_collection_spec_ce, getThis(), ("scope_name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(CollectionSpec, setMaxExpiry)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_collection_spec_ce, getThis(), ("max_expiry"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_CollectionSpec_name, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_CollectionSpec_scopeName, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CollectionSpec_setName, 0, 1, Couchbase\\CollectionSpec, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_CollectionSpec_setScopeName, 0, 1, Couchbase\\CollectionSpec, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry collection_spec_methods[] = {
    PHP_ME(CollectionSpec, name, ai_CollectionSpec_name, ZEND_ACC_PUBLIC)
    PHP_ME(CollectionSpec, scopeName, ai_CollectionSpec_scopeName, ZEND_ACC_PUBLIC)
    PHP_ME(CollectionSpec, setName, ai_CollectionSpec_setName, ZEND_ACC_PUBLIC)
    PHP_ME(CollectionSpec, setScopeName, ai_CollectionSpec_setScopeName, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(CollectionManager)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "CollectionManager", collection_manager_methods);
    pcbc_collection_manager_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_collection_manager_ce, ZEND_STRL("bucket"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ScopeSpec", scope_spec_methods);
    pcbc_scope_spec_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_scope_spec_ce, ZEND_STRL("uid"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_scope_spec_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_scope_spec_ce, ZEND_STRL("collections"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "CollectionSpec", collection_spec_methods);
    pcbc_collection_spec_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_collection_spec_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_collection_spec_ce, ZEND_STRL("scope_name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_collection_spec_ce, ZEND_STRL("max_expiry"), ZEND_ACC_PRIVATE);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
