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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/manager/buckets", __FILE__, __LINE__

extern zend_class_entry *pcbc_cluster_ce;

zend_class_entry *pcbc_bucket_settings_ce;
zend_class_entry *pcbc_bucket_manager_ce;

static void httpcb_getBucket(void *ctx, zval *return_value, zval *response)
{
    HashTable *marr = Z_ARRVAL_P(response);
    object_init_ex(return_value, pcbc_bucket_settings_ce);
    zval *mval;

    mval = zend_symtable_str_find(marr, ZEND_STRL("name"));
    if (mval && Z_TYPE_P(mval) == IS_STRING) {
        zend_update_property(pcbc_bucket_settings_ce, return_value, ZEND_STRL("name"), mval TSRMLS_CC);
    }
    mval = zend_symtable_str_find(marr, ZEND_STRL("replicaNumber"));
    if (mval && Z_TYPE_P(mval) == IS_LONG) {
        zend_update_property(pcbc_bucket_settings_ce, return_value, ZEND_STRL("num_replicas"), mval TSRMLS_CC);
    }
    mval = zend_symtable_str_find(marr, ZEND_STRL("replicaIndex"));
    zend_update_property_bool(pcbc_bucket_settings_ce, return_value, ZEND_STRL("replica_indexes"),
                              mval != NULL TSRMLS_CC);
    mval = zend_symtable_str_find(marr, ZEND_STRL("bucketType"));
    if (mval && Z_TYPE_P(mval) == IS_STRING) {
        zend_update_property(pcbc_bucket_settings_ce, return_value, ZEND_STRL("bucket_type"), mval TSRMLS_CC);
    }
    mval = zend_symtable_str_find(marr, ZEND_STRL("evictionPolicy"));
    if (mval && Z_TYPE_P(mval) == IS_STRING) {
        zend_update_property(pcbc_bucket_settings_ce, return_value, ZEND_STRL("ejection_method"), mval TSRMLS_CC);
    }
    mval = zend_symtable_str_find(marr, ZEND_STRL("maxTTL"));
    if (mval && Z_TYPE_P(mval) == IS_LONG) {
        zend_update_property(pcbc_bucket_settings_ce, return_value, ZEND_STRL("max_ttl"), mval TSRMLS_CC);
    }
    mval = zend_symtable_str_find(marr, ZEND_STRL("compressionMode"));
    if (mval && Z_TYPE_P(mval) == IS_STRING) {
        zend_update_property(pcbc_bucket_settings_ce, return_value, ZEND_STRL("compression_mode"), mval TSRMLS_CC);
    }

    {
        zval *quota = zend_symtable_str_find(marr, ZEND_STRL("quota"));
        if (quota && Z_TYPE_P(quota) == IS_ARRAY) {
            mval = zend_symtable_str_find(Z_ARRVAL_P(quota), ZEND_STRL("ram"));
            if (mval && Z_TYPE_P(mval) == IS_LONG) {
                zend_update_property_long(pcbc_bucket_settings_ce, return_value, ZEND_STRL("ram_quota_mb"),
                                          Z_LVAL_P(mval) / (1024 * 1024) TSRMLS_CC);
            }
        }
    }
    {
        zval *controllers = zend_symtable_str_find(marr, ZEND_STRL("controllers"));
        if (controllers && Z_TYPE_P(controllers) == IS_ARRAY) {
            mval = zend_symtable_str_find(Z_ARRVAL_P(controllers), ZEND_STRL("flush"));
            zend_update_property_bool(pcbc_bucket_settings_ce, return_value, ZEND_STRL("flush_enabled"),
                                      mval && Z_TYPE_P(mval) == IS_STRING TSRMLS_CC);
        }
    }
}

PHP_METHOD(BucketManager, getBucket)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    zend_string *name;
    char *path;
    int rv, path_len;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        return;
    }

    prop = zend_read_property(pcbc_bucket_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    path_len = spprintf(&path, 0, "/pools/default/buckets/%*s", (int)ZSTR_LEN(name), ZSTR_VAL(name));
    lcb_cmdhttp_path(cmd, path, path_len);
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getBucket, NULL TSRMLS_CC);
    efree(path);
}

static void httpcb_getAllBuckets(void *ctx, zval *return_value, zval *response)
{
    array_init(return_value);

    zval *entry;
    ZEND_HASH_FOREACH_VAL(HASH_OF(response), entry)
    {
        zval bs;
        httpcb_getBucket(ctx, &bs, entry);
        add_next_index_zval(return_value, &bs);
    }
    ZEND_HASH_FOREACH_END();
}

PHP_METHOD(BucketManager, getAllBuckets)
{
    const char *path = "/pools/default/buckets";
    int rv;
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    prop = zend_read_property(pcbc_bucket_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    lcb_cmdhttp_path(cmd, path, strlen(path));
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getAllBuckets, NULL TSRMLS_CC);
}

PHP_METHOD(BucketManager, createBucket)
{
    const char *path = "/pools/default/buckets";

    zval *settings = NULL;
    zval *options = NULL;
    int rv;
    smart_str buf = {0};
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "O|z", &settings, pcbc_bucket_settings_ce, &options);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    prop = zend_read_property(pcbc_bucket_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    {
        zval payload;
        zval *prop, ret;
        array_init(&payload);

        add_assoc_string(&payload, "authType", "sasl");
        prop = zend_read_property(pcbc_bucket_settings_ce, settings, ZEND_STRL("name"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            add_assoc_zval(&payload, "name", prop);
        }
        prop = zend_read_property(pcbc_bucket_settings_ce, settings, ZEND_STRL("bucket_type"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            add_assoc_zval(&payload, "bucketType", prop);
        }
        prop = zend_read_property(pcbc_bucket_settings_ce, settings, ZEND_STRL("ram_quota_mb"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            add_assoc_zval(&payload, "ramQuotaMB", prop);
        }
        prop = zend_read_property(pcbc_bucket_settings_ce, settings, ZEND_STRL("num_replicas"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            add_assoc_zval(&payload, "replicaNumber", prop);
        }
        prop = zend_read_property(pcbc_bucket_settings_ce, settings, ZEND_STRL("ejection_method"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            add_assoc_zval(&payload, "evictionPolicy", prop);
        }
        prop = zend_read_property(pcbc_bucket_settings_ce, settings, ZEND_STRL("compression_mode"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            add_assoc_zval(&payload, "compressionMode", prop);
        }
        prop = zend_read_property(pcbc_bucket_settings_ce, settings, ZEND_STRL("max_ttl"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            add_assoc_zval(&payload, "maxTTL", prop);
        }
        prop = zend_read_property(pcbc_bucket_settings_ce, settings, ZEND_STRL("flush_enabled"), 0, &ret);
        add_assoc_bool(&payload, "flushEnabled", Z_TYPE_P(prop) == IS_TRUE);
        prop = zend_read_property(pcbc_bucket_settings_ce, settings, ZEND_STRL("replica_indexes"), 0, &ret);
        add_assoc_bool(&payload, "replicaIndex", Z_TYPE_P(prop) == IS_TRUE);

        rv = php_url_encode_hash_ex(HASH_OF(&payload), &buf, NULL, 0, NULL, 0, NULL, 0, NULL, NULL,
                                    PHP_QUERY_RFC1738 TSRMLS_CC);
        zval_ptr_dtor(&payload);
        if (rv == FAILURE) {
            smart_str_free(&buf);
            throw_pcbc_exception("Failed to encode settings as RFC1738 query", LCB_ERR_INVALID_ARGUMENT);
            RETURN_NULL();
        }
    }

    lcb_CMDHTTP *cmd;
    smart_str_0(&buf);
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_body(cmd, ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_path(cmd, path, strlen(path));
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    smart_str_free(&buf);
}

PHP_METHOD(BucketManager, removeBucket)
{
    zend_string *name = NULL;
    char *path;
    int rv, path_len;
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    prop = zend_read_property(pcbc_bucket_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_DELETE);
    path_len = spprintf(&path, 0, "/pools/default/buckets/%*s", (int)ZSTR_LEN(name), ZSTR_VAL(name));
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(path);
}

PHP_METHOD(BucketManager, flush)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    zend_string *name;
    char *path;
    int rv, path_len;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        return;
    }

    prop = zend_read_property(pcbc_bucket_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    path_len = spprintf(&path, 0, "/pools/default/buckets/%*s/controller/doFlush", (int)ZSTR_LEN(name), ZSTR_VAL(name));
    lcb_cmdhttp_path(cmd, path, path_len);
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(path);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BucketManager_getAllBuckets, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_BucketManager_removeBucket, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_BucketManager_flush, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BucketManager_getBucket, 0, 1, Couchbase\\BucketSettings, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_BucketManager_createBucket, 0, 0, 1)
ZEND_ARG_OBJ_INFO(0, settings, Couchbase\\BucketSettings, 0)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry my_bucket_manager_methods[] = {
    PHP_ME(BucketManager, createBucket, ai_BucketManager_createBucket, ZEND_ACC_PUBLIC)
    PHP_ME(BucketManager, removeBucket, ai_BucketManager_removeBucket, ZEND_ACC_PUBLIC)
    PHP_ME(BucketManager, getBucket, ai_BucketManager_getBucket, ZEND_ACC_PUBLIC)
    PHP_ME(BucketManager, getAllBuckets, ai_BucketManager_getAllBuckets, ZEND_ACC_PUBLIC)
    PHP_ME(BucketManager, flush, ai_BucketManager_flush, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(BucketSettings, name);
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BucketSettings_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, setName);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BucketSettings_setName, 0, 1, Couchbase\\BucketSettings, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, flushEnabled);
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BucketSettings_flushEnabled, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, enableFlush);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BucketSettings_enableFlush, 0, 1, Couchbase\\BucketSettings, 0)
ZEND_ARG_TYPE_INFO(0, enable, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, ramQuotaMb);
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BucketSettings_ramQuotaMb, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, setRamQuotaMb);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BucketSettings_setRamQuotaMb, 0, 1, Couchbase\\BucketSettings, 0)
ZEND_ARG_TYPE_INFO(0, sizeInMb, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, numReplicas);
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BucketSettings_numReplicas, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, setNumReplicas);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BucketSettings_setNumReplicas, 0, 1, Couchbase\\BucketSettings, 0)
ZEND_ARG_TYPE_INFO(0, numberReplicas, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, replicaIndexes);
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BucketSettings_replicaIndexes, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, enableReplicaIndexes);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BucketSettings_enableReplicaIndexes, 0, 1, Couchbase\\BucketSettings, 0)
ZEND_ARG_TYPE_INFO(0, enable, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, bucketType);
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BucketSettings_bucketType, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, setBucketType);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BucketSettings_setBucketType, 0, 1, Couchbase\\BucketSettings, 0)
ZEND_ARG_TYPE_INFO(0, type, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, ejectionMethod);
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BucketSettings_ejectionMethod, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, setEjectionMethod);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BucketSettings_setEjectionMethod, 0, 1, Couchbase\\BucketSettings, 0)
ZEND_ARG_TYPE_INFO(0, method, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, maxTtl);
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BucketSettings_maxTtl, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, setMaxTtl);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BucketSettings_setMaxTtl, 0, 1, Couchbase\\BucketSettings, 0)
ZEND_ARG_TYPE_INFO(0, ttlSeconds, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, compressionMode);
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BucketSettings_compressionMode, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, setCompressionMode);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BucketSettings_setCompressionMode, 0, 1, Couchbase\\BucketSettings, 0)
ZEND_ARG_TYPE_INFO(0, mode, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry bucket_settings_methods[] = {
    PHP_ME(BucketSettings, name, ai_BucketSettings_name, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, setName, ai_BucketSettings_setName, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, flushEnabled, ai_BucketSettings_flushEnabled, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, enableFlush, ai_BucketSettings_enableFlush, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, ramQuotaMb, ai_BucketSettings_ramQuotaMb, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, setRamQuotaMb, ai_BucketSettings_setRamQuotaMb, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, numReplicas, ai_BucketSettings_numReplicas, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, setNumReplicas, ai_BucketSettings_setNumReplicas, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, replicaIndexes, ai_BucketSettings_replicaIndexes, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, enableReplicaIndexes, ai_BucketSettings_enableReplicaIndexes, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, bucketType, ai_BucketSettings_bucketType, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, setBucketType, ai_BucketSettings_setBucketType, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, ejectionMethod, ai_BucketSettings_ejectionMethod, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, setEjectionMethod, ai_BucketSettings_setEjectionMethod, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, maxTtl, ai_BucketSettings_maxTtl, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, setMaxTtl, ai_BucketSettings_setMaxTtl, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, compressionMode, ai_BucketSettings_compressionMode, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, setCompressionMode, ai_BucketSettings_setCompressionMode, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(BucketManager)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "BucketManager", my_bucket_manager_methods);
    pcbc_bucket_manager_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_bucket_manager_ce, ZEND_STRL("cluster"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "BucketSettings", bucket_settings_methods);
    pcbc_bucket_settings_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("flush_enabled"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("ram_quota_mb"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("num_replicas"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("replica_indexes"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("bucket_type"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("ejection_method"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("max_ttl"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("compression_mode"), ZEND_ACC_PRIVATE TSRMLS_CC);
    return SUCCESS;
}

PHP_METHOD(BucketSettings, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("name"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, flushEnabled)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("flush_enabled"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, enableFlush)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_bool(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("flush_enabled"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, ramQuotaMb)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("ram_quota_mb"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setRamQuotaMb)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_long(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("ram_quota_mb"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, numReplicas)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("num_replicas"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setNumReplicas)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_long(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("num_replicas"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, replicaIndexes)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("replica_indexes"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, enableReplicaIndexes)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_bool(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("replica_indexes"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, bucketType)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("bucket_type"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setBucketType)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("bucket_type"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, ejectionMethod)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("ejection_method"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setEjectionMethod)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("ejection_method"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, maxTtl)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("max_ttl"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setMaxTtl)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_long(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("max_ttl"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, compressionMode)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("compression_mode"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setCompressionMode)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_bucket_settings_ce, getThis(), ZEND_STRL("compression_mode"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
