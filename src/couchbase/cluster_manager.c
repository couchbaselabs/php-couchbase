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
#include <ext/standard/php_array.h>
#include <ext/standard/php_http.h>
#include <ext/standard/url.h>

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/cluster_manager", __FILE__, __LINE__

#define PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_LOCAL 1
#define PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_EXTERNAL 2

zend_class_entry *pcbc_cluster_manager_ce;
extern zend_class_entry *pcbc_classic_authenticator_ce;
extern zend_class_entry *pcbc_password_authenticator_ce;

/* {{{ proto void ClusterManager::__construct() Should not be called directly */
PHP_METHOD(ClusterManager, __construct)
{
    throw_pcbc_exception("Accessing private constructor.", LCB_EINVAL);
}
/* }}} */

/* {{{ proto array ClusterManager::listBuckets() */
PHP_METHOD(ClusterManager, listBuckets)
{
    pcbc_cluster_manager_t *obj;
    lcb_CMDHTTP cmd = {0};
    const char *path = "/pools/default/buckets";
    int rv;

    obj = Z_CLUSTER_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters_none();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    cmd.type = LCB_HTTP_TYPE_MANAGEMENT;
    cmd.method = LCB_HTTP_METHOD_GET;
    LCB_CMD_SET_KEY(&cmd, path, strlen(path));
    cmd.content_type = PCBC_CONTENT_TYPE_FORM;
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 1 TSRMLS_CC);
} /* }}} */

/* {{{ proto array ClusterManager::createBucket(string $name, array $options = array()) */
PHP_METHOD(ClusterManager, createBucket)
{
    pcbc_cluster_manager_t *obj;
    const char *name = NULL;
    pcbc_str_arg_size name_len = 0;
    zval *options = NULL;
    int rv;
    lcb_CMDHTTP cmd = {0};
    const char *path = "/pools/default/buckets";
    PCBC_ZVAL default_options;
    smart_str buf = {0};

    obj = Z_CLUSTER_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|z", &name, &name_len, &options);
    if (rv == FAILURE) {
        return;
    }

    PCBC_ZVAL_ALLOC(default_options);
    array_init_size(PCBC_P(default_options), 5);
    ADD_ASSOC_STRING(PCBC_P(default_options), "name", name);
    ADD_ASSOC_STRING(PCBC_P(default_options), "authType", "sasl");
    ADD_ASSOC_STRING(PCBC_P(default_options), "bucketType", "couchbase");
    ADD_ASSOC_LONG_EX(PCBC_P(default_options), "ramQuotaMB", 100);
    ADD_ASSOC_LONG_EX(PCBC_P(default_options), "replicaNumber", 1);
    if (options && Z_TYPE_P(options) == IS_ARRAY) {
        PCBC_ARRAY_MERGE(Z_ARRVAL_P(PCBC_P(default_options)), Z_ARRVAL_P(options));
    }

    rv = php_url_encode_hash_ex(HASH_OF(PCBC_P(default_options)), &buf, NULL, 0, NULL, 0, NULL, 0, NULL, NULL,
                                PHP_QUERY_RFC1738 TSRMLS_CC);
    zval_ptr_dtor(&default_options);
    if (rv == FAILURE) {
        pcbc_log(LOGARGS(obj->conn->lcb, WARN), "Failed to encode options as RFC1738 query");
        smart_str_free(&buf);
        RETURN_NULL();
    } else {
        smart_str_0(&buf);
        PCBC_SMARTSTR_SET(buf, cmd.body, cmd.nbody);
    }

    cmd.type = LCB_HTTP_TYPE_MANAGEMENT;
    cmd.method = LCB_HTTP_METHOD_POST;
    LCB_CMD_SET_KEY(&cmd, path, strlen(path));
    cmd.content_type = PCBC_CONTENT_TYPE_FORM;
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 1 TSRMLS_CC);
    smart_str_free(&buf);
} /* }}} */

/* {{{ proto array ClusterManager::removeBucket(string $name) */
PHP_METHOD(ClusterManager, removeBucket)
{
    pcbc_cluster_manager_t *obj;
    const char *name = NULL;
    pcbc_str_arg_size name_len = 0;
    lcb_CMDHTTP cmd = {0};
    char *path;
    int rv, path_len;

    obj = Z_CLUSTER_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &name_len);
    if (rv == FAILURE) {
        return;
    }
    path_len = spprintf(&path, 0, "/pools/default/buckets/%*s", (int)name_len, name);
    cmd.type = LCB_HTTP_TYPE_MANAGEMENT;
    cmd.method = LCB_HTTP_METHOD_DELETE;
    LCB_CMD_SET_KEY(&cmd, path, path_len);
    cmd.content_type = PCBC_CONTENT_TYPE_FORM;
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 1 TSRMLS_CC);
    efree(path);
} /* }}} */

/* {{{ proto array ClusterManager::info() */
PHP_METHOD(ClusterManager, info)
{
    pcbc_cluster_manager_t *obj;
    lcb_CMDHTTP cmd = {0};
    const char *path = "/pools/default";
    int rv;

    obj = Z_CLUSTER_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters_none();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    cmd.type = LCB_HTTP_TYPE_MANAGEMENT;
    cmd.method = LCB_HTTP_METHOD_GET;
    LCB_CMD_SET_KEY(&cmd, path, strlen(path));
    cmd.content_type = PCBC_CONTENT_TYPE_FORM;
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 1 TSRMLS_CC);
} /* }}} */

/* {{{ proto array ClusterManager::listUsers($domain = ClusterManager::RBAC_DOMAIN_LOCAL) */
PHP_METHOD(ClusterManager, listUsers)
{
    pcbc_cluster_manager_t *obj;
    lcb_CMDHTTP cmd = {0};
    long domain = PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_LOCAL;
    char *path;
    int rv;

    obj = Z_CLUSTER_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &domain);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    switch (domain) {
    case PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_LOCAL:
        path = "/settings/rbac/users/local";
        break;
    case PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_EXTERNAL:
        path = "/settings/rbac/users/external";
        break;
    default:
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }
    cmd.type = LCB_HTTP_TYPE_MANAGEMENT;
    cmd.method = LCB_HTTP_METHOD_GET;
    LCB_CMD_SET_KEY(&cmd, path, strlen(path));
    cmd.content_type = PCBC_CONTENT_TYPE_FORM;
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 1 TSRMLS_CC);
} /* }}} */

/* {{{ proto array ClusterManager::getUser(string $name, $domain = ClusterManager::RBAC_DOMAIN_LOCAL) */
PHP_METHOD(ClusterManager, getUser)
{
    pcbc_cluster_manager_t *obj;
    const char *name = NULL;
    pcbc_str_arg_size name_len = 0;
    lcb_CMDHTTP cmd = {0};
    char *path;
    int rv, path_len;
    long domain = PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_LOCAL;

    obj = Z_CLUSTER_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &name, &name_len, &domain);
    if (rv == FAILURE) {
        return;
    }
    switch (domain) {
    case PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_LOCAL:
        path_len = spprintf(&path, 0, "/settings/rbac/users/local/%*s", (int)name_len, name);
        break;
    case PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_EXTERNAL:
        path_len = spprintf(&path, 0, "/settings/rbac/users/external/%*s", (int)name_len, name);
        break;
    default:
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    cmd.type = LCB_HTTP_TYPE_MANAGEMENT;
    cmd.method = LCB_HTTP_METHOD_GET;
    LCB_CMD_SET_KEY(&cmd, path, path_len);
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 1 TSRMLS_CC);
    efree(path);
} /* }}} */

/* {{{ proto array ClusterManager::removeUser(string $name, $domain = ClusterManager::RBAC_DOMAIN_LOCAL) */
PHP_METHOD(ClusterManager, removeUser)
{
    pcbc_cluster_manager_t *obj;
    const char *name = NULL;
    pcbc_str_arg_size name_len = 0;
    lcb_CMDHTTP cmd = {0};
    char *path;
    int rv, path_len;
    long domain = PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_LOCAL;

    obj = Z_CLUSTER_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &name, &name_len, &domain);
    if (rv == FAILURE) {
        return;
    }
    switch (domain) {
    case PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_LOCAL:
        path_len = spprintf(&path, 0, "/settings/rbac/users/local/%*s", (int)name_len, name);
        break;
    case PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_EXTERNAL:
        path_len = spprintf(&path, 0, "/settings/rbac/users/external/%*s", (int)name_len, name);
        break;
    default:
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    cmd.type = LCB_HTTP_TYPE_MANAGEMENT;
    cmd.method = LCB_HTTP_METHOD_DELETE;
    LCB_CMD_SET_KEY(&cmd, path, path_len);
    cmd.content_type = PCBC_CONTENT_TYPE_FORM;
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 0 TSRMLS_CC);
    efree(path);
    if (Z_STRLEN_P(return_value) == 0 || (Z_STRVAL_P(return_value)[0] == '"' && Z_STRVAL_P(return_value)[1] == '"')) {
        RETURN_TRUE;
    } else {
        throw_pcbc_exception(Z_STRVAL_P(return_value), LCB_EINVAL);
        RETURN_NULL();
    }
} /* }}} */

/* {{{ proto array ClusterManager::upsertUser(string $name, \Couchbase\UserSettings $settings, $domain = ClusterManager::RBAC_DOMAIN_LOCAL) */
PHP_METHOD(ClusterManager, upsertUser)
{
    pcbc_cluster_manager_t *obj;
    const char *name = NULL;
    pcbc_str_arg_size name_len = 0;
    zval *settings = NULL;
    char *path;
    int rv, path_len;
    lcb_CMDHTTP cmd = {0};
    smart_str buf = {0};
    PCBC_ZVAL body;
    pcbc_user_settings_t *user;
    long domain = PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_LOCAL;

    obj = Z_CLUSTER_MANAGER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sO|l", &name, &name_len, &settings, pcbc_user_settings_ce, &domain);
    if (rv == FAILURE) {
        return;
    }

    user = Z_USER_SETTINGS_OBJ_P(settings);
    switch (domain) {
    case PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_LOCAL:
        path_len = spprintf(&path, 0, "/settings/rbac/users/local/%*s", (int)name_len, name);
        break;
    case PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_EXTERNAL:
        path_len = spprintf(&path, 0, "/settings/rbac/users/external/%*s", (int)name_len, name);
        break;
    default:
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    cmd.type = LCB_HTTP_TYPE_MANAGEMENT;
    cmd.method = LCB_HTTP_METHOD_PUT;
    LCB_CMD_SET_KEY(&cmd, path, path_len);
    cmd.content_type = PCBC_CONTENT_TYPE_FORM;

    PCBC_ZVAL_ALLOC(body);
    array_init_size(PCBC_P(body), 3);
    if (user->full_name) {
        ADD_ASSOC_STRINGL(PCBC_P(body), "name", user->full_name, user->full_name_len);
    }
    if (user->password) {
        ADD_ASSOC_STRINGL(PCBC_P(body), "password", user->password, user->password_len);
    }
    if (PCBC_SMARTSTR_LEN(user->roles)) {
        ADD_ASSOC_STRINGL(PCBC_P(body), "roles", PCBC_SMARTSTR_VAL(user->roles), PCBC_SMARTSTR_LEN(user->roles));
    }
    rv = php_url_encode_hash_ex(HASH_OF(PCBC_P(body)), &buf, NULL, 0, NULL, 0, NULL, 0, NULL, NULL,
                                PHP_QUERY_RFC1738 TSRMLS_CC);
    zval_ptr_dtor(&body);
    if (rv == FAILURE) {
        pcbc_log(LOGARGS(obj->conn->lcb, WARN), "Failed to encode options as RFC1738 query");
        smart_str_free(&buf);
        RETURN_NULL();
    } else {
        smart_str_0(&buf);
        PCBC_SMARTSTR_SET(buf, cmd.body, cmd.nbody);
    }
    pcbc_http_request(return_value, obj->conn->lcb, &cmd, 0 TSRMLS_CC);
    smart_str_free(&buf);
    efree(path);
    if (Z_STRLEN_P(return_value) == 0 || (Z_STRVAL_P(return_value)[0] == '"' && Z_STRVAL_P(return_value)[1] == '"')) {
        RETURN_TRUE;
    } else {
        throw_pcbc_exception(Z_STRVAL_P(return_value), LCB_EINVAL);
        RETURN_NULL();
    }
} /* }}} */

ZEND_BEGIN_ARG_INFO_EX(ai_ClusterManager_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ClusterManager_removeBucket, 0, 0, 1)
ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ClusterManager_createBucket, 0, 0, 2)
ZEND_ARG_INFO(0, name)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ClusterManager_upsertUser, 0, 0, 3)
ZEND_ARG_INFO(0, name)
ZEND_ARG_INFO(0, settings)
ZEND_ARG_INFO(0, domain)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ClusterManager_removeUser, 0, 0, 2)
ZEND_ARG_INFO(0, name)
ZEND_ARG_INFO(0, domain)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ClusterManager_getUser, 0, 0, 2)
ZEND_ARG_INFO(0, name)
ZEND_ARG_INFO(0, domain)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ClusterManager_listUsers, 0, 0, 1)
ZEND_ARG_INFO(0, domain)
ZEND_END_ARG_INFO()


// clang-format off
zend_function_entry cluster_manager_methods[] = {
    PHP_ME(ClusterManager, __construct, ai_ClusterManager_none, ZEND_ACC_PRIVATE | ZEND_ACC_FINAL | ZEND_ACC_CTOR)
    PHP_ME(ClusterManager, listBuckets, ai_ClusterManager_none, ZEND_ACC_PUBLIC)
    PHP_ME(ClusterManager, createBucket, ai_ClusterManager_createBucket, ZEND_ACC_PUBLIC)
    PHP_ME(ClusterManager, removeBucket, ai_ClusterManager_removeBucket, ZEND_ACC_PUBLIC)
    PHP_ME(ClusterManager, listUsers, ai_ClusterManager_listUsers, ZEND_ACC_PUBLIC)
    PHP_ME(ClusterManager, upsertUser, ai_ClusterManager_upsertUser, ZEND_ACC_PUBLIC)
    PHP_ME(ClusterManager, getUser, ai_ClusterManager_getUser, ZEND_ACC_PUBLIC)
    PHP_ME(ClusterManager, removeUser, ai_ClusterManager_removeUser, ZEND_ACC_PUBLIC)
    PHP_ME(ClusterManager, info, ai_ClusterManager_none, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

zend_object_handlers pcbc_cluster_manager_handlers;

static void pcbc_cluster_manager_free_object(pcbc_free_object_arg *object TSRMLS_DC) /* {{{ */
{
    pcbc_cluster_manager_t *obj = Z_CLUSTER_MANAGER_OBJ(object);
    pcbc_connection_delref(obj->conn TSRMLS_CC);
    obj->conn = NULL;

    zend_object_std_dtor(&obj->std TSRMLS_CC);
#if PHP_VERSION_ID < 70000
    efree(obj);
#endif
} /* }}} */

static pcbc_create_object_retval pcbc_cluster_manager_create_object(zend_class_entry *class_type TSRMLS_DC)
{
    pcbc_cluster_manager_t *obj = NULL;

    obj = PCBC_ALLOC_OBJECT_T(pcbc_cluster_manager_t, class_type);

    zend_object_std_init(&obj->std, class_type TSRMLS_CC);
    object_properties_init(&obj->std, class_type);

#if PHP_VERSION_ID >= 70000
    obj->std.handlers = &pcbc_cluster_manager_handlers;
    return &obj->std;
#else
    {
        zend_object_value ret;
        ret.handle = zend_objects_store_put(obj, (zend_objects_store_dtor_t)zend_objects_destroy_object,
                                            pcbc_cluster_manager_free_object, NULL TSRMLS_CC);
        ret.handlers = &pcbc_cluster_manager_handlers;
        return ret;
    }
#endif
}

void pcbc_cluster_manager_init(zval *return_value, pcbc_cluster_t *cluster, const char *username,
                               const char *password TSRMLS_DC)
{
    pcbc_cluster_manager_t *manager;
    lcb_error_t err;
    pcbc_connection_t *conn;
    pcbc_classic_authenticator_t *authenticator = NULL;
    pcbc_credential_t extra_creds = {0};
    lcb_AUTHENTICATOR *auth = NULL;
    char *auth_hash = NULL;

    if (!Z_ISUNDEF(cluster->auth)) {
        if (instanceof_function(Z_OBJCE_P(PCBC_P(cluster->auth)), pcbc_classic_authenticator_ce TSRMLS_CC)) {
            pcbc_generate_classic_lcb_auth(Z_CLASSIC_AUTHENTICATOR_OBJ_P(PCBC_P(cluster->auth)), &auth,
                                           LCB_TYPE_CLUSTER, username, password, &auth_hash TSRMLS_CC);
        } else if (instanceof_function(Z_OBJCE_P(PCBC_P(cluster->auth)), pcbc_password_authenticator_ce TSRMLS_CC)) {
            pcbc_generate_password_lcb_auth(Z_PASSWORD_AUTHENTICATOR_OBJ_P(PCBC_P(cluster->auth)), &auth,
                                            LCB_TYPE_CLUSTER, username, password, &auth_hash TSRMLS_CC);
        }
    }
    if (!auth) {
        pcbc_generate_classic_lcb_auth(NULL, &auth, LCB_TYPE_CLUSTER, username, password, &auth_hash TSRMLS_CC);
    }
    err = pcbc_connection_get(&conn, LCB_TYPE_CLUSTER, cluster->connstr, NULL, auth, auth_hash TSRMLS_CC);
    efree(auth_hash);
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err);
        return;
    }

    object_init_ex(return_value, pcbc_cluster_manager_ce);
    manager = Z_CLUSTER_MANAGER_OBJ_P(return_value);
    manager->conn = conn;
}

static HashTable *pcbc_cluster_manager_get_debug_info(zval *object, int *is_temp TSRMLS_DC) /* {{{ */
{
/* pcbc_cluster_manager_t *obj = NULL; */
#if PHP_VERSION_ID >= 70000
    zval retval;
#else
    zval retval = zval_used_for_init;
#endif

    *is_temp = 1;
    /* obj = Z_CLUSTER_MANAGER_OBJ_P(object); */

    array_init(&retval);

    return Z_ARRVAL(retval);
} /* }}} */

PHP_MINIT_FUNCTION(ClusterManager)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ClusterManager", cluster_manager_methods);
    pcbc_cluster_manager_ce = zend_register_internal_class(&ce TSRMLS_CC);
    pcbc_cluster_manager_ce->create_object = pcbc_cluster_manager_create_object;
    PCBC_CE_DISABLE_SERIALIZATION(pcbc_cluster_manager_ce);

    memcpy(&pcbc_cluster_manager_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    pcbc_cluster_manager_handlers.get_debug_info = pcbc_cluster_manager_get_debug_info;
#if PHP_VERSION_ID >= 70000
    pcbc_cluster_manager_handlers.free_obj = pcbc_cluster_manager_free_object;
    pcbc_cluster_manager_handlers.offset = XtOffsetOf(pcbc_cluster_manager_t, std);
#endif
    zend_declare_class_constant_long(pcbc_cluster_manager_ce, ZEND_STRL("RBAC_DOMAIN_LOCAL"),
                                     PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_LOCAL TSRMLS_CC);
    zend_declare_class_constant_long(pcbc_cluster_manager_ce, ZEND_STRL("RBAC_DOMAIN_EXTERNAL"),
                                     PCBC_CLUSTER_MANAGER_RBAC_DOMAIN_EXTERNAL TSRMLS_CC);

    zend_register_class_alias("\\CouchbaseClusterManager", pcbc_cluster_manager_ce);
    return SUCCESS;
}
