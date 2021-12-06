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
        pcbc_update_property(pcbc_bucket_settings_ce, return_value, ("name"), mval);
    }
    mval = zend_symtable_str_find(marr, ZEND_STRL("replicaNumber"));
    if (mval && Z_TYPE_P(mval) == IS_LONG) {
        pcbc_update_property(pcbc_bucket_settings_ce, return_value, ("num_replicas"), mval);
    }
    mval = zend_symtable_str_find(marr, ZEND_STRL("replicaIndex"));
    pcbc_update_property_bool(pcbc_bucket_settings_ce, return_value, ("replica_indexes"), mval != NULL);
    mval = zend_symtable_str_find(marr, ZEND_STRL("bucketType"));
    if (mval && Z_TYPE_P(mval) == IS_STRING) {
        pcbc_update_property(pcbc_bucket_settings_ce, return_value, ("bucket_type"), mval);
    }
    mval = zend_symtable_str_find(marr, ZEND_STRL("evictionPolicy"));
    if (mval && Z_TYPE_P(mval) == IS_STRING) {
        pcbc_update_property(pcbc_bucket_settings_ce, return_value, ("eviction_policy"), mval);
    }
    mval = zend_symtable_str_find(marr, ZEND_STRL("storageBackend"));
    if (mval && Z_TYPE_P(mval) == IS_STRING) {
        pcbc_update_property(pcbc_bucket_settings_ce, return_value, ("storage_backend"), mval);
    }
    mval = zend_symtable_str_find(marr, ZEND_STRL("maxTTL"));
    if (mval && Z_TYPE_P(mval) == IS_LONG) {
        pcbc_update_property(pcbc_bucket_settings_ce, return_value, ("max_ttl"), mval);
    }
    mval = zend_symtable_str_find(marr, ZEND_STRL("compressionMode"));
    if (mval && Z_TYPE_P(mval) == IS_STRING) {
        pcbc_update_property(pcbc_bucket_settings_ce, return_value, ("compression_mode"), mval);
    }
    mval = zend_symtable_str_find(marr, ZEND_STRL("durabilityMinLevel"));
    if (mval && Z_TYPE_P(mval) == IS_STRING) {
        if (strncmp("none", Z_STRVAL_P(mval), Z_STRLEN_P(mval)) == 0) {
            pcbc_update_property_long(pcbc_bucket_settings_ce, return_value, ("minimal_durability_level"),
                                      LCB_DURABILITYLEVEL_NONE);
        } else if (strncmp("majority", Z_STRVAL_P(mval), Z_STRLEN_P(mval)) == 0) {
            pcbc_update_property_long(pcbc_bucket_settings_ce, return_value, ("minimal_durability_level"),
                                      LCB_DURABILITYLEVEL_MAJORITY);
        } else if (strncmp("majorityAndPersistActive", Z_STRVAL_P(mval), Z_STRLEN_P(mval)) == 0) {
            pcbc_update_property_long(pcbc_bucket_settings_ce, return_value, ("minimal_durability_level"),
                                      LCB_DURABILITYLEVEL_MAJORITY_AND_PERSIST_TO_ACTIVE);
        } else if (strncmp("persistToMajority", Z_STRVAL_P(mval), Z_STRLEN_P(mval)) == 0) {
            pcbc_update_property_long(pcbc_bucket_settings_ce, return_value, ("minimal_durability_level"),
                                      LCB_DURABILITYLEVEL_PERSIST_TO_MAJORITY);
        }
    }

    {
        zval *quota = zend_symtable_str_find(marr, ZEND_STRL("quota"));
        if (quota && Z_TYPE_P(quota) == IS_ARRAY) {
            mval = zend_symtable_str_find(Z_ARRVAL_P(quota), ZEND_STRL("ram"));
            if (mval && Z_TYPE_P(mval) == IS_LONG) {
                pcbc_update_property_long(pcbc_bucket_settings_ce, return_value, ("ram_quota_mb"),
                                          Z_LVAL_P(mval) / (1024 * 1024));
            }
        }
    }
    {
        zval *controllers = zend_symtable_str_find(marr, ZEND_STRL("controllers"));
        if (controllers && Z_TYPE_P(controllers) == IS_ARRAY) {
            mval = zend_symtable_str_find(Z_ARRVAL_P(controllers), ZEND_STRL("flush"));
            pcbc_update_property_bool(pcbc_bucket_settings_ce, return_value, ("flush_enabled"),
                                      mval && Z_TYPE_P(mval) == IS_STRING);
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

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &name);
    if (rv == FAILURE) {
        return;
    }

    prop = pcbc_read_property(pcbc_bucket_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    path_len = spprintf(&path, 0, "/pools/default/buckets/%*s", (int)ZSTR_LEN(name), ZSTR_VAL(name));
    lcb_cmdhttp_path(cmd, path, path_len);
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getBucket, NULL);
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

    prop = pcbc_read_property(pcbc_bucket_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    lcb_cmdhttp_path(cmd, path, strlen(path));
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getAllBuckets, NULL);
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

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "O|z", &settings, pcbc_bucket_settings_ce, &options);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    prop = pcbc_read_property(pcbc_bucket_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    {
        zval payload;
        zval *prop, ret;
        array_init(&payload);

        add_assoc_string(&payload, "authType", "sasl");
        prop = pcbc_read_property(pcbc_bucket_settings_ce, settings, ("name"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            add_assoc_zval(&payload, "name", prop);
        }
        prop = pcbc_read_property(pcbc_bucket_settings_ce, settings, ("bucket_type"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            add_assoc_zval(&payload, "bucketType", prop);
        }
        prop = pcbc_read_property(pcbc_bucket_settings_ce, settings, ("ram_quota_mb"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            add_assoc_zval(&payload, "ramQuotaMB", prop);
        }
        prop = pcbc_read_property(pcbc_bucket_settings_ce, settings, ("num_replicas"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            add_assoc_zval(&payload, "replicaNumber", prop);
        }
        prop = pcbc_read_property(pcbc_bucket_settings_ce, settings, ("eviction_policy"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            add_assoc_zval(&payload, "evictionPolicy", prop);
        }
        prop = pcbc_read_property(pcbc_bucket_settings_ce, settings, ("compression_mode"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            add_assoc_zval(&payload, "compressionMode", prop);
        }
        prop = pcbc_read_property(pcbc_bucket_settings_ce, settings, ("storage_backend"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_STRING) {
            add_assoc_zval(&payload, "storageBackend", prop);
        }
        prop = pcbc_read_property(pcbc_bucket_settings_ce, settings, ("minimal_durability_level"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            switch (Z_LVAL_P(prop)) {
            case LCB_DURABILITYLEVEL_NONE:
                add_assoc_string(&payload, "durabilityMinLevel", "none");
                break;
            case LCB_DURABILITYLEVEL_MAJORITY:
                add_assoc_string(&payload, "durabilityMinLevel", "majority");
                break;
            case LCB_DURABILITYLEVEL_MAJORITY_AND_PERSIST_TO_ACTIVE:
                add_assoc_string(&payload, "durabilityMinLevel", "majorityAndPersistActive");
                break;
            case LCB_DURABILITYLEVEL_PERSIST_TO_MAJORITY:
                add_assoc_string(&payload, "durabilityMinLevel", "persistToMajority");
                break;
            }
        }
        prop = pcbc_read_property(pcbc_bucket_settings_ce, settings, ("max_ttl"), 0, &ret);
        if (Z_TYPE_P(prop) == IS_LONG) {
            add_assoc_zval(&payload, "maxTTL", prop);
        }
        prop = pcbc_read_property(pcbc_bucket_settings_ce, settings, ("flush_enabled"), 0, &ret);
        add_assoc_bool(&payload, "flushEnabled", Z_TYPE_P(prop) == IS_TRUE);
        prop = pcbc_read_property(pcbc_bucket_settings_ce, settings, ("replica_indexes"), 0, &ret);
        add_assoc_bool(&payload, "replicaIndex", Z_TYPE_P(prop) == IS_TRUE);

        php_url_encode_hash_ex(HASH_OF(&payload), &buf, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, PHP_QUERY_RFC1738);
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
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
    smart_str_free(&buf);
}

PHP_METHOD(BucketManager, removeBucket)
{
    zend_string *name = NULL;
    char *path;
    int rv, path_len;
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    prop = pcbc_read_property(pcbc_bucket_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_DELETE);
    path_len = spprintf(&path, 0, "/pools/default/buckets/%*s", (int)ZSTR_LEN(name), ZSTR_VAL(name));
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
    efree(path);
}

PHP_METHOD(BucketManager, flush)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    zend_string *name;
    char *path;
    int rv, path_len;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &name);
    if (rv == FAILURE) {
        return;
    }

    prop = pcbc_read_property(pcbc_bucket_manager_ce, getThis(), ("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_POST);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    path_len = spprintf(&path, 0, "/pools/default/buckets/%*s/controller/doFlush", (int)ZSTR_LEN(name), ZSTR_VAL(name));
    lcb_cmdhttp_path(cmd, path, path_len);
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL);
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

PHP_METHOD(BucketSettings, evictionPolicy);
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BucketSettings_evictionPolicy, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, setEvictionPolicy);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BucketSettings_setEvictionPolicy, 0, 1, Couchbase\\BucketSettings, 0)
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

PHP_METHOD(BucketSettings, minimalDurabilityLevel);
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BucketSettings_minimalDurabilityLevel, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BucketSettings, setMinimalDurabilityLevel);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BucketSettings_setMinimalDurabilityLevel, 0, 1, Couchbase\\BucketSettings, 0)
ZEND_ARG_TYPE_INFO(0, mode, IS_LONG, 0)
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
    PHP_ME(BucketSettings, evictionPolicy, ai_BucketSettings_evictionPolicy, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, setEvictionPolicy, ai_BucketSettings_setEvictionPolicy, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, maxTtl, ai_BucketSettings_maxTtl, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, setMaxTtl, ai_BucketSettings_setMaxTtl, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, compressionMode, ai_BucketSettings_compressionMode, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, setCompressionMode, ai_BucketSettings_setCompressionMode, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, minimalDurabilityLevel, ai_BucketSettings_minimalDurabilityLevel, ZEND_ACC_PUBLIC)
    PHP_ME(BucketSettings, setMinimalDurabilityLevel, ai_BucketSettings_setMinimalDurabilityLevel, ZEND_ACC_PUBLIC)

    PHP_MALIAS(BucketSettings, ejectionMethod, evictionPolicy, ai_BucketSettings_evictionPolicy, ZEND_ACC_PUBLIC|ZEND_ACC_DEPRECATED)
    PHP_MALIAS(BucketSettings, setEjectionMethod, setEvictionPolicy, ai_BucketSettings_setEvictionPolicy, ZEND_ACC_PUBLIC|ZEND_ACC_DEPRECATED)
    PHP_FE_END
};
// clang-format on

zend_class_entry *pcbc_eviction_policy_ce;
static const zend_function_entry pcbc_eviction_policy_methods[] = {PHP_FE_END};

zend_class_entry *pcbc_storage_backend_ce;
static const zend_function_entry pcbc_storage_backend_methods[] = {PHP_FE_END};

PHP_MINIT_FUNCTION(BucketManager)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "BucketManager", my_bucket_manager_methods);
    pcbc_bucket_manager_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_bucket_manager_ce, ZEND_STRL("cluster"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "BucketSettings", bucket_settings_methods);
    pcbc_bucket_settings_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("flush_enabled"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("ram_quota_mb"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("num_replicas"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("replica_indexes"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("bucket_type"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("eviction_policy"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("max_ttl"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("compression_mode"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("storage_backend"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_bucket_settings_ce, ZEND_STRL("minimal_durability_level"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "EvictionPolicy", pcbc_eviction_policy_methods);
    pcbc_eviction_policy_ce = zend_register_internal_interface(&ce);
    zend_declare_class_constant_stringl(pcbc_eviction_policy_ce, ZEND_STRL("FULL"), ZEND_STRL("fullEviction"));
    zend_declare_class_constant_stringl(pcbc_eviction_policy_ce, ZEND_STRL("VALUE_ONLY"), ZEND_STRL("valueOnly"));
    zend_declare_class_constant_stringl(pcbc_eviction_policy_ce, ZEND_STRL("NO_EVICTION"), ZEND_STRL("noEviction"));
    zend_declare_class_constant_stringl(pcbc_eviction_policy_ce, ZEND_STRL("NOT_RECENTLY_USED"),
                                        ZEND_STRL("nruEviction"));

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "StorageBackend", pcbc_storage_backend_methods);
    pcbc_storage_backend_ce = zend_register_internal_interface(&ce);
    zend_declare_class_constant_stringl(pcbc_storage_backend_ce, ZEND_STRL("COUCHSTORE"), ZEND_STRL("couchstore"));
    zend_declare_class_constant_stringl(pcbc_storage_backend_ce, ZEND_STRL("MAGMA"), ZEND_STRL("magma"));
    return SUCCESS;
}

PHP_METHOD(BucketSettings, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_bucket_settings_ce, getThis(), ("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_bucket_settings_ce, getThis(), ("name"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, flushEnabled)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_bucket_settings_ce, getThis(), ("flush_enabled"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, enableFlush)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_bool(pcbc_bucket_settings_ce, getThis(), ("flush_enabled"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, ramQuotaMb)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_bucket_settings_ce, getThis(), ("ram_quota_mb"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setRamQuotaMb)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_bucket_settings_ce, getThis(), ("ram_quota_mb"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, numReplicas)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_bucket_settings_ce, getThis(), ("num_replicas"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setNumReplicas)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_bucket_settings_ce, getThis(), ("num_replicas"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, replicaIndexes)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_bucket_settings_ce, getThis(), ("replica_indexes"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, enableReplicaIndexes)
{
    zend_bool val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "b", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_bool(pcbc_bucket_settings_ce, getThis(), ("replica_indexes"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, bucketType)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_bucket_settings_ce, getThis(), ("bucket_type"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setBucketType)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_bucket_settings_ce, getThis(), ("bucket_type"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, evictionPolicy)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_bucket_settings_ce, getThis(), ("eviction_policy"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setEvictionPolicy)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_bucket_settings_ce, getThis(), ("eviction_policy"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, storageBackend)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_bucket_settings_ce, getThis(), ("storage_backend"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setStorageBackend)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_bucket_settings_ce, getThis(), ("storage_backend"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, maxTtl)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_bucket_settings_ce, getThis(), ("max_ttl"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setMaxTtl)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_bucket_settings_ce, getThis(), ("max_ttl"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, compressionMode)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_bucket_settings_ce, getThis(), ("compression_mode"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setCompressionMode)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_bucket_settings_ce, getThis(), ("compression_mode"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BucketSettings, minimalDurabilityLevel)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_bucket_settings_ce, getThis(), ("minimal_durability_level"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BucketSettings, setMinimalDurabilityLevel)
{
    zend_long val = LCB_DURABILITYLEVEL_NONE;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_bucket_settings_ce, getThis(), ("minimal_durability_level"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
