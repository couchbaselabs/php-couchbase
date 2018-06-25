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

#define LOGARGS(manager, lvl) LCB_LOG_##lvl, manager->conn->lcb, "pcbc/bucket_manager", __FILE__, __LINE__

zend_class_entry *pcbc_bucket_manager_ce;

/* {{{ proto void BucketManager::__construct() Should not be called directly */
PHP_METHOD(BucketManager, __construct)
{
    throw_pcbc_exception("Accessing private constructor.", LCB_EINVAL);
}
/* }}} */

/* {{{ proto array BucketManager::info() */
PHP_METHOD(BucketManager, info)
{
    pcbc_bucket_manager_t *obj;
    lcb_CMDHTTP cmd = {0};
    char *path;
    int rv, path_len;

    obj = Z_BUCKET_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters_none();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    cmd.type = LCB_HTTP_TYPE_MANAGEMENT;
    cmd.method = LCB_HTTP_METHOD_GET;
    path_len = spprintf(&path, 0, "/pools/default/buckets/%s", obj->conn->bucketname);
    LCB_CMD_SET_KEY(&cmd, path, path_len);
    cmd.content_type = PCBC_CONTENT_TYPE_FORM;
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 1 TSRMLS_CC);
    efree(path);
} /* }}} */

/* {{{ proto array BucketManager::flush() */
PHP_METHOD(BucketManager, flush)
{
    pcbc_bucket_manager_t *obj;
    lcb_CMDHTTP cmd = {0};
    char *path;
    int rv, path_len;

    obj = Z_BUCKET_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters_none();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    cmd.type = LCB_HTTP_TYPE_MANAGEMENT;
    cmd.method = LCB_HTTP_METHOD_POST;
    path_len = spprintf(&path, 0, "/pools/default/buckets/%s/controller/doFlush", obj->conn->bucketname);
    LCB_CMD_SET_KEY(&cmd, path, path_len);
    cmd.content_type = PCBC_CONTENT_TYPE_FORM;
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 1 TSRMLS_CC);
    efree(path);
} /* }}} */

/* {{{ proto array BucketManager::listDesignDocuments() */
PHP_METHOD(BucketManager, listDesignDocuments)
{
    pcbc_bucket_manager_t *obj;
    lcb_CMDHTTP cmd = {0};
    char *path;
    int rv, path_len;

    obj = Z_BUCKET_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters_none();
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    cmd.type = LCB_HTTP_TYPE_MANAGEMENT;
    cmd.method = LCB_HTTP_METHOD_GET;
    path_len = spprintf(&path, 0, "/pools/default/buckets/%s/ddocs", obj->conn->bucketname);
    LCB_CMD_SET_KEY(&cmd, path, path_len);
    cmd.content_type = PCBC_CONTENT_TYPE_FORM;
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 1 TSRMLS_CC);
    efree(path);
} /* }}} */

/* {{{ proto array BucketManager::insertDesignDocument(string $name, array $document) */
PHP_METHOD(BucketManager, insertDesignDocument)
{
    pcbc_bucket_manager_t *obj;
    lcb_CMDHTTP cmd = {0};
    char *path, *name = NULL;
    int rv, path_len;
    pcbc_str_arg_size name_len = 0;
    zval *document;
    smart_str buf = {0};
    int last_error;

    obj = Z_BUCKET_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &name, &name_len, &document);
    if (rv == FAILURE) {
        return;
    }

    path_len = spprintf(&path, 0, "/_design/%*s", (int)name_len, name);

    cmd.type = LCB_HTTP_TYPE_VIEW;
    cmd.method = LCB_HTTP_METHOD_GET;
    LCB_CMD_SET_KEY(&cmd, path, path_len);
    cmd.content_type = PCBC_CONTENT_TYPE_FORM;
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 1 TSRMLS_CC);
    if (!php_array_exists(return_value, "error")) {
        efree(path);
        zval_dtor(return_value);
        throw_pcbc_exception("Design document already exists", LCB_KEY_EEXISTS);
        RETURN_NULL();
    }

    zval_dtor(return_value);
    cmd.method = LCB_HTTP_METHOD_PUT;
    cmd.content_type = PCBC_CONTENT_TYPE_JSON;

    PCBC_JSON_ENCODE(&buf, document, 0, last_error);
    if (last_error != 0) {
        pcbc_log(LOGARGS(obj, WARN), "Failed to encode design document as JSON: json_last_error=%d", last_error);
        smart_str_free(&buf);
        efree(path);
        RETURN_NULL();
    } else {
        smart_str_0(&buf);
        PCBC_SMARTSTR_SET(buf, cmd.body, cmd.nbody);
    }
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 1 TSRMLS_CC);
    efree(path);
    smart_str_free(&buf);

    {
        char *error = NULL;
        int error_len = 0;
        zend_bool owned = 0;

        error = php_array_fetch_string(return_value, "error", &error_len, &owned);
        if (error) {
            throw_pcbc_exception(error, LCB_ERROR);
            if (owned) {
                efree(error);
            }
            zval_dtor(return_value);
            RETURN_NULL();
        }
    }
} /* }}} */

/* {{{ proto array BucketManager::upsertDesignDocument(string $name, array $document) */
PHP_METHOD(BucketManager, upsertDesignDocument)
{
    pcbc_bucket_manager_t *obj;
    lcb_CMDHTTP cmd = {0};
    char *path, *name = NULL;
    int rv, path_len = 0;
    pcbc_str_arg_size name_len = 0;
    zval *document;
    smart_str buf = {0};
    int last_error;

    obj = Z_BUCKET_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &name, &name_len, &document);
    if (rv == FAILURE) {
        return;
    }

    cmd.type = LCB_HTTP_TYPE_VIEW;
    cmd.method = LCB_HTTP_METHOD_PUT;
    path_len = spprintf(&path, 0, "/_design/%*s", (int)name_len, name);
    LCB_CMD_SET_KEY(&cmd, path, path_len);
    cmd.content_type = PCBC_CONTENT_TYPE_JSON;

    PCBC_JSON_ENCODE(&buf, document, 0, last_error);
    if (last_error != 0) {
        pcbc_log(LOGARGS(obj, WARN), "Failed to encode design document as JSON: json_last_error=%d", last_error);
        smart_str_free(&buf);
        efree(path);
        RETURN_NULL();
    } else {
        smart_str_0(&buf);
        PCBC_SMARTSTR_SET(buf, cmd.body, cmd.nbody);
    }
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 1 TSRMLS_CC);
    efree(path);
    smart_str_free(&buf);

    {
        char *error = NULL;
        int error_len = 0;
        zend_bool owned = 0;

        error = php_array_fetch_string(return_value, "error", &error_len, &owned);
        if (error) {
            throw_pcbc_exception(error, LCB_ERROR);
            if (owned) {
                efree(error);
            }
            zval_dtor(return_value);
        }
    }
} /* }}} */

/* {{{ proto array BucketManager::removeDesignDocument(string $name) */
PHP_METHOD(BucketManager, removeDesignDocument)
{
    pcbc_bucket_manager_t *obj;
    lcb_CMDHTTP cmd = {0};
    char *path, *name = NULL;
    int rv, path_len;
    pcbc_str_arg_size name_len = 0;

    obj = Z_BUCKET_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &name_len);
    if (rv == FAILURE) {
        return;
    }

    cmd.type = LCB_HTTP_TYPE_VIEW;
    cmd.method = LCB_HTTP_METHOD_DELETE;
    path_len = spprintf(&path, 0, "/_design/%*s", (int)name_len, name);
    LCB_CMD_SET_KEY(&cmd, path, path_len);
    cmd.content_type = PCBC_CONTENT_TYPE_FORM;
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 1 TSRMLS_CC);
    efree(path);
} /* }}} */

/* {{{ proto array BucketManager::getDesignDocument(string $name) */
PHP_METHOD(BucketManager, getDesignDocument)
{
    pcbc_bucket_manager_t *obj;
    lcb_CMDHTTP cmd = {0};
    char *path, *name = NULL;
    int rv, path_len;
    pcbc_str_arg_size name_len = 0;

    obj = Z_BUCKET_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &name_len);
    if (rv == FAILURE) {
        return;
    }

    cmd.type = LCB_HTTP_TYPE_VIEW;
    cmd.method = LCB_HTTP_METHOD_GET;
    path_len = spprintf(&path, 0, "/_design/%*s", (int)name_len, name);
    LCB_CMD_SET_KEY(&cmd, path, path_len);
    cmd.content_type = PCBC_CONTENT_TYPE_FORM;
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 1 TSRMLS_CC);
    efree(path);
    if (php_array_exists(return_value, "error")) {
        zval_dtor(return_value);
        RETURN_BOOL(0);
    }
} /* }}} */

/* {{{ proto array BucketManager::listN1qlIndexes() */
PHP_METHOD(BucketManager, listN1qlIndexes)
{
    pcbc_bucket_manager_t *obj;
    int rv;

    rv = zend_parse_parameters_none();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_BUCKET_MANAGER_OBJ_P(getThis());

    pcbc_n1ix_list(obj, return_value TSRMLS_CC);
} /* }}} */

/* {{{ proto array BucketManager::createN1qlPrimaryIndex(string $customName = '', boolean $ignoreIfExist = false,
                                                         boolean $defer = false) */
PHP_METHOD(BucketManager, createN1qlPrimaryIndex)
{
    pcbc_bucket_manager_t *obj;
    char *name = NULL;
    int rv;
    pcbc_str_arg_size name_len = 0;
    zend_bool ignore_if_exist = 0, defer = 0;
    lcb_CMDN1XMGMT cmd = {0};

    obj = Z_BUCKET_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|sbb", &name, &name_len, &ignore_if_exist, &defer);
    if (rv == FAILURE) {
        return;
    }

    cmd.spec.ixtype = LCB_N1XSPEC_T_GSI;
    cmd.spec.flags = LCB_N1XSPEC_F_PRIMARY;
    if (defer) {
        cmd.spec.flags |= LCB_N1XSPEC_F_DEFER;
    }

    cmd.spec.name = name;
    cmd.spec.nname = name_len;

    cmd.spec.keyspace = obj->conn->bucketname;
    cmd.spec.nkeyspace = strlen(obj->conn->bucketname);

    pcbc_n1ix_create(obj, &cmd, ignore_if_exist, return_value TSRMLS_CC);
} /* }}} */

/* {{{ proto array BucketManager::createN1qlIndex(string $indexName, array $fields, string $whereClause = '',
                                                  boolean $ignoreIfExist = false, boolean $defer = false) */
PHP_METHOD(BucketManager, createN1qlIndex)
{
    pcbc_bucket_manager_t *obj;
    lcb_CMDN1XMGMT cmd = {0};
    char *name = NULL, *where = NULL;
    int rv, last_error;
    pcbc_str_arg_size name_len = 0, where_len = 0;
    zend_bool ignore_if_exist = 0, defer = 0;
    zval *fields;
    smart_str buf = {0};

    obj = Z_BUCKET_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa|sbb", &name, &name_len, &fields, &where, &where_len,
                               &ignore_if_exist, &defer);
    if (rv == FAILURE) {
        return;
    }

    PCBC_JSON_ENCODE(&buf, fields, 0, last_error);
    if (last_error != 0) {
        pcbc_log(LOGARGS(obj, WARN), "Failed to encode index fields as JSON: json_last_error=%d", last_error);
        smart_str_free(&buf);
        RETURN_NULL();
    } else {
        smart_str_0(&buf);
        PCBC_SMARTSTR_SET(buf, cmd.spec.fields, cmd.spec.nfields);
    }
    cmd.spec.ixtype = LCB_N1XSPEC_T_GSI;
    cmd.spec.flags = 0;
    if (defer) {
        cmd.spec.flags |= LCB_N1XSPEC_F_DEFER;
    }

    cmd.spec.name = name;
    cmd.spec.nname = name_len;
    cmd.spec.keyspace = obj->conn->bucketname;
    cmd.spec.nkeyspace = strlen(obj->conn->bucketname);
    cmd.spec.cond = where;
    cmd.spec.ncond = where_len;

    pcbc_n1ix_create(obj, &cmd, ignore_if_exist, return_value TSRMLS_CC);
    smart_str_free(&buf);

} /* }}} */

/* {{{ proto array BucketManager::dropN1qlPrimaryIndex(string $customName = '', boolean $ignoreIfNotExist = false) */
PHP_METHOD(BucketManager, dropN1qlPrimaryIndex)
{
    pcbc_bucket_manager_t *obj;
    lcb_CMDN1XMGMT cmd = {0};
    char *name = NULL;
    int rv;
    pcbc_str_arg_size name_len = 0;
    zend_bool ignore_if_not_exist = 0;

    obj = Z_BUCKET_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|sb", &name, &name_len, &ignore_if_not_exist);
    if (rv == FAILURE) {
        return;
    }
    cmd.spec.name = name;
    cmd.spec.nname = name_len;

    cmd.spec.keyspace = obj->conn->bucketname;
    cmd.spec.nkeyspace = strlen(obj->conn->bucketname);

    cmd.spec.ixtype = LCB_N1XSPEC_T_GSI;
    cmd.spec.flags = LCB_N1XSPEC_F_PRIMARY;
    pcbc_n1ix_drop(obj, &cmd, ignore_if_not_exist, return_value TSRMLS_CC);
} /* }}} */

/* {{{ proto array BucketManager::dropN1qlIndex(string $indexName, $boolean $ignoreIfNotExist = false) */
PHP_METHOD(BucketManager, dropN1qlIndex)
{
    pcbc_bucket_manager_t *obj;
    lcb_CMDN1XMGMT cmd = {0};
    char *name = NULL;
    int rv;
    pcbc_str_arg_size name_len = 0;
    zend_bool ignore_if_not_exist = 0;

    obj = Z_BUCKET_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|bb", &name, &name_len, &ignore_if_not_exist);
    if (rv == FAILURE) {
        return;
    }
    cmd.spec.name = name;
    cmd.spec.nname = name_len;

    cmd.spec.keyspace = obj->conn->bucketname;
    cmd.spec.nkeyspace = strlen(obj->conn->bucketname);

    cmd.spec.ixtype = LCB_N1XSPEC_T_GSI;
    pcbc_n1ix_drop(obj, &cmd, ignore_if_not_exist, return_value TSRMLS_CC);
} /* }}} */

ZEND_BEGIN_ARG_INFO_EX(ai_BucketManager_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_BucketManager_getDesignDocument, 0, 0, 1)
ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_BucketManager_upsertDesignDocument, 0, 0, 2)
ZEND_ARG_INFO(0, name)
ZEND_ARG_INFO(0, document)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_BucketManager_createN1qlPrimaryIndex, 0, 0, 3)
ZEND_ARG_INFO(0, customName)
ZEND_ARG_INFO(0, ignoreIfExist)
ZEND_ARG_INFO(0, defer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_BucketManager_createN1qlIndex, 0, 0, 5)
ZEND_ARG_INFO(0, indexName)
ZEND_ARG_INFO(0, fields)
ZEND_ARG_INFO(0, whereClause)
ZEND_ARG_INFO(0, ignoreIfExist)
ZEND_ARG_INFO(0, defer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_BucketManager_dropN1qlPrimaryIndex, 0, 0, 2)
ZEND_ARG_INFO(0, customName)
ZEND_ARG_INFO(0, ignoreIfNotExist)
ZEND_ARG_INFO(0, defer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_BucketManager_dropN1qlIndex, 0, 0, 2)
ZEND_ARG_INFO(0, indexName)
ZEND_ARG_INFO(0, ignoreIfNotExist)
ZEND_ARG_INFO(0, defer)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry bucket_manager_methods[] = {
    PHP_ME(BucketManager, __construct, ai_BucketManager_none, ZEND_ACC_PRIVATE | ZEND_ACC_FINAL | ZEND_ACC_CTOR)
    PHP_ME(BucketManager, info, ai_BucketManager_none, ZEND_ACC_PUBLIC)
    PHP_ME(BucketManager, flush, ai_BucketManager_none, ZEND_ACC_PUBLIC)
    PHP_ME(BucketManager, listDesignDocuments, ai_BucketManager_none, ZEND_ACC_PUBLIC)
    PHP_MALIAS(BucketManager, getDesignDocuments, listDesignDocuments, ai_BucketManager_none, ZEND_ACC_PUBLIC | ZEND_ACC_DEPRECATED)
    PHP_ME(BucketManager, getDesignDocument, ai_BucketManager_getDesignDocument, ZEND_ACC_PUBLIC)
    PHP_ME(BucketManager, removeDesignDocument, ai_BucketManager_getDesignDocument, ZEND_ACC_PUBLIC)
    PHP_ME(BucketManager, upsertDesignDocument, ai_BucketManager_upsertDesignDocument, ZEND_ACC_PUBLIC)
    PHP_ME(BucketManager, insertDesignDocument, ai_BucketManager_upsertDesignDocument, ZEND_ACC_PUBLIC)
    PHP_ME(BucketManager, listN1qlIndexes, ai_BucketManager_none, ZEND_ACC_PUBLIC)
    PHP_ME(BucketManager, createN1qlPrimaryIndex, ai_BucketManager_createN1qlPrimaryIndex, ZEND_ACC_PUBLIC)
    PHP_ME(BucketManager, createN1qlIndex, ai_BucketManager_createN1qlIndex, ZEND_ACC_PUBLIC)
    PHP_ME(BucketManager, dropN1qlPrimaryIndex, ai_BucketManager_dropN1qlPrimaryIndex, ZEND_ACC_PUBLIC)
    PHP_ME(BucketManager, dropN1qlIndex, ai_BucketManager_dropN1qlIndex, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

zend_object_handlers pcbc_bucket_manager_handlers;

static void pcbc_bucket_manager_free_object(pcbc_free_object_arg *object TSRMLS_DC) /* {{{ */
{
    pcbc_bucket_manager_t *obj = Z_BUCKET_MANAGER_OBJ(object);

    pcbc_connection_delref(obj->conn TSRMLS_CC);
    obj->conn = NULL;
    zend_object_std_dtor(&obj->std TSRMLS_CC);
#if PHP_VERSION_ID < 70000
    efree(obj);
#endif
} /* }}} */

static pcbc_create_object_retval pcbc_bucket_manager_create_object(zend_class_entry *class_type TSRMLS_DC)
{
    pcbc_bucket_manager_t *obj = NULL;

    obj = PCBC_ALLOC_OBJECT_T(pcbc_bucket_manager_t, class_type);

    zend_object_std_init(&obj->std, class_type TSRMLS_CC);
    object_properties_init(&obj->std, class_type);

#if PHP_VERSION_ID >= 70000
    obj->std.handlers = &pcbc_bucket_manager_handlers;
    return &obj->std;
#else
    {
        zend_object_value ret;
        ret.handle = zend_objects_store_put(obj, (zend_objects_store_dtor_t)zend_objects_destroy_object,
                                            pcbc_bucket_manager_free_object, NULL TSRMLS_CC);
        ret.handlers = &pcbc_bucket_manager_handlers;
        return ret;
    }
#endif
}

void pcbc_bucket_manager_init(zval *return_value, zval *bucket TSRMLS_DC)
{
    pcbc_bucket_manager_t *manager;

    object_init_ex(return_value, pcbc_bucket_manager_ce);
    manager = Z_BUCKET_MANAGER_OBJ_P(return_value);
    manager->conn = Z_BUCKET_OBJ_P(bucket)->conn;
    pcbc_connection_addref(manager->conn TSRMLS_CC);
}

static HashTable *pcbc_bucket_manager_get_debug_info(zval *object, int *is_temp TSRMLS_DC) /* {{{ */
{
    pcbc_bucket_manager_t *obj = NULL;
#if PHP_VERSION_ID >= 70000
    zval retval;
#else
    zval retval = zval_used_for_init;
#endif

    *is_temp = 1;
    obj = Z_BUCKET_MANAGER_OBJ_P(object);

    array_init(&retval);
    ADD_ASSOC_STRING(&retval, "bucket", obj->conn->bucketname);

    return Z_ARRVAL(retval);
} /* }}} */

PHP_MINIT_FUNCTION(BucketManager)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "BucketManager", bucket_manager_methods);
    pcbc_bucket_manager_ce = zend_register_internal_class(&ce TSRMLS_CC);
    pcbc_bucket_manager_ce->create_object = pcbc_bucket_manager_create_object;
    PCBC_CE_DISABLE_SERIALIZATION(pcbc_bucket_manager_ce);

    memcpy(&pcbc_bucket_manager_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    pcbc_bucket_manager_handlers.get_debug_info = pcbc_bucket_manager_get_debug_info;
#if PHP_VERSION_ID >= 70000
    pcbc_bucket_manager_handlers.free_obj = pcbc_bucket_manager_free_object;
    pcbc_bucket_manager_handlers.offset = XtOffsetOf(pcbc_bucket_manager_t, std);
#endif

    zend_register_class_alias("\\CouchbaseBucketManager", pcbc_bucket_manager_ce);
    return SUCCESS;
}
