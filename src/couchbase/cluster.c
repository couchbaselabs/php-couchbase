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
#include <ext/standard/url.h>

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/cluster", __FILE__, __LINE__

zend_class_entry *pcbc_cluster_ce;
extern zend_class_entry *pcbc_user_manager_ce;
extern zend_class_entry *pcbc_cluster_options_ce;
extern zend_class_entry *pcbc_bucket_manager_ce;
extern zend_class_entry *pcbc_search_index_manager_ce;
extern zend_class_entry *pcbc_query_index_manager_ce;
extern zend_class_entry *pcbc_analytics_index_manager_ce;
extern zend_class_entry *pcbc_meter_ce;

PHP_METHOD(Cluster, query);
PHP_METHOD(Cluster, analyticsQuery);
PHP_METHOD(Cluster, searchQuery);

static void pcbc_bucket_init(zval *return_value, pcbc_cluster_t *cluster, const char *bucketname)
{
    pcbc_bucket_t *bucket;
    pcbc_connection_t *conn;
    lcb_STATUS err;

    err = pcbc_connection_get(&conn, LCB_TYPE_BUCKET, cluster->connstr, bucketname, cluster->username,
                              cluster->password, &cluster->meter);
    if (err) {
        throw_lcb_exception(err, NULL);
        return;
    }
    object_init_ex(return_value, pcbc_bucket_ce);
    bucket = Z_BUCKET_OBJ_P(return_value);
    bucket->conn = conn;
    lcb_cntl(conn->lcb, LCB_CNTL_GET, LCB_CNTL_BUCKETTYPE, &bucket->type);
    ZVAL_UNDEF(&bucket->encoder);
    ZVAL_UNDEF(&bucket->decoder);
    PCBC_STRING(bucket->encoder, "\\Couchbase\\defaultEncoder");
    PCBC_STRING(bucket->decoder, "\\Couchbase\\defaultDecoder");
}

static void pcbc_cluster_connection_init(zval *return_value, pcbc_cluster_t *cluster)
{
    pcbc_connection_t *conn;
    lcb_STATUS err;
    const char *bucket = NULL;
    lcb_INSTANCE_TYPE type = LCB_TYPE_CLUSTER;
    php_url *url = NULL;

    if (PCBCG(allow_fallback_to_bucket)) {
        url = php_url_parse(cluster->connstr);
        if (url && url->path) {
            bucket = ZSTR_VAL(url->path);
            while (*bucket == '/') {
                bucket++;
            }
            if (strlen(bucket) > 0) {
                type = LCB_TYPE_BUCKET;
                pcbc_log(
                    LOGARGS(INFO),
                    "Use \"%s\" as bucket name for cluster object to allow cluster-level queries for older servers "
                    "(enabled via INI \"couchbase.allow_fallback_to_bucket_connection\")",
                    bucket);
            }
        }
    }

    err = pcbc_connection_get(&conn, type, cluster->connstr, bucket, cluster->username, cluster->password,
                              &cluster->meter);
    if (url) {
        php_url_free(url);
    }
    if (err) {
        throw_lcb_exception(err, NULL);
        return;
    }
    cluster->conn = conn;
}

PHP_METHOD(Cluster, __construct)
{
    pcbc_cluster_t *obj;
    zend_string *connstr;
    zval *options;
    int rv;

    obj = Z_CLUSTER_OBJ_P(getThis());

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "SO", &connstr, &options, pcbc_cluster_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zval *prop, ret;
    prop = pcbc_read_property(pcbc_cluster_options_ce, options, ("username"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_STRING) {
        zend_type_error("Username option must be specified");
        RETURN_NULL();
    }
    obj->username = estrndup(Z_STRVAL_P(prop), Z_STRLEN_P(prop));
    prop = pcbc_read_property(pcbc_cluster_options_ce, options, ("password"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_STRING) {
        zend_type_error("Password option must be specified");
        RETURN_NULL();
    }
    obj->password = estrndup(Z_STRVAL_P(prop), Z_STRLEN_P(prop));
    obj->connstr = estrndup(ZSTR_VAL(connstr), ZSTR_LEN(connstr));
    obj->conn = NULL;

    prop = pcbc_read_property(pcbc_cluster_options_ce, options, ("meter"), 0, &ret);
    if ((Z_TYPE_P(prop) != IS_OBJECT && Z_TYPE_P(prop) != IS_NULL) ||
        (Z_TYPE_P(prop) == IS_OBJECT && !instanceof_function(Z_OBJCE_P(prop), pcbc_meter_ce))) {
        zend_type_error("Invalid meter specified");
        RETURN_NULL();
    }
    ZVAL_ZVAL(&obj->meter, prop, 1, 0);

    pcbc_cluster_connection_init(return_value, obj);

    pcbc_log(LOGARGS(DEBUG), "Initialize Cluster. C=%p connstr=\"%s\"", (void *)obj, obj->connstr);
}

PHP_METHOD(Cluster, bucket)
{
    pcbc_cluster_t *obj;
    zend_string *bucketname = NULL;
    int rv;

    obj = Z_CLUSTER_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS(), "S", &bucketname);
    if (rv == FAILURE) {
        return;
    }

    pcbc_bucket_init(return_value, obj, ZSTR_VAL(bucketname));
}

PHP_METHOD(Cluster, buckets)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    object_init_ex(return_value, pcbc_bucket_manager_ce);
    pcbc_update_property(pcbc_bucket_manager_ce, return_value, ("cluster"), getThis());
}

PHP_METHOD(Cluster, analyticsIndexes)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    object_init_ex(return_value, pcbc_analytics_index_manager_ce);
    pcbc_update_property(pcbc_analytics_index_manager_ce, return_value, ("cluster"), getThis());
}

PHP_METHOD(Cluster, queryIndexes)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    object_init_ex(return_value, pcbc_query_index_manager_ce);
    pcbc_update_property(pcbc_query_index_manager_ce, return_value, ("cluster"), getThis());
}

PHP_METHOD(Cluster, searchIndexes)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }
    object_init_ex(return_value, pcbc_search_index_manager_ce);
    pcbc_update_property(pcbc_search_index_manager_ce, return_value, ("cluster"), getThis());
}

PHP_METHOD(Cluster, users)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }
    object_init_ex(return_value, pcbc_user_manager_ce);
    pcbc_update_property(pcbc_user_manager_ce, return_value, ("cluster"), getThis());
}

ZEND_BEGIN_ARG_INFO_EX(ai_Cluster_constructor, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, connstr, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\ClusterOptions, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Cluster_bucket, 0, 1, Couchbase\\Bucket, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Cluster_buckets, 0, 0, Couchbase\\BucketManager, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Cluster_users, 0, 0, Couchbase\\UserManager, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Cluster_analyticsIndexes, 0, 0, Couchbase\\AnalyticsIndexManager, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Cluster_queryIndexes, 0, 0, Couchbase\\QueryIndexManager, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Cluster_searchIndexes, 0, 0, Couchbase\\SearchIndexManager, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Cluster_query, 0, 1, Couchbase\\QueryResult, 0)
ZEND_ARG_TYPE_INFO(0, statement, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, queryOptions, Couchbase\\QueryOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Cluster_analyticsQuery, 0, 1, Couchbase\\AnalyticsResult, 0)
ZEND_ARG_TYPE_INFO(0, statement, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, queryOptions, Couchbase\\AnalyticsOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Cluster_searchQuery, 0, 2, Couchbase\\SearchResult, 0)
ZEND_ARG_TYPE_INFO(0, indexName, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, query, Couchbase\\SearchQuery, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\SearchOptions, 1)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry cluster_methods[] = {
    PHP_ME(Cluster, __construct, ai_Cluster_constructor, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(Cluster, bucket, ai_Cluster_bucket, ZEND_ACC_PUBLIC)
    PHP_ME(Cluster, buckets, ai_Cluster_buckets, ZEND_ACC_PUBLIC)
    PHP_ME(Cluster, users, ai_Cluster_users, ZEND_ACC_PUBLIC)
    PHP_ME(Cluster, analyticsIndexes, ai_Cluster_analyticsIndexes, ZEND_ACC_PUBLIC)
    PHP_ME(Cluster, queryIndexes, ai_Cluster_queryIndexes, ZEND_ACC_PUBLIC)
    PHP_ME(Cluster, searchIndexes, ai_Cluster_searchIndexes, ZEND_ACC_PUBLIC)
    PHP_ME(Cluster, query, ai_Cluster_query, ZEND_ACC_PUBLIC)
    PHP_ME(Cluster, analyticsQuery, ai_Cluster_analyticsQuery, ZEND_ACC_PUBLIC)
    PHP_ME(Cluster, searchQuery, ai_Cluster_searchQuery, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

zend_object_handlers pcbc_cluster_handlers;

static void pcbc_cluster_free_object(zend_object *object)
{
    pcbc_cluster_t *obj = Z_CLUSTER_OBJ(object);

    if (obj->connstr != NULL) {
        efree(obj->connstr);
    }
    if (obj->username != NULL) {
        efree(obj->username);
    }
    if (obj->password != NULL) {
        efree(obj->password);
    }
    if (!Z_ISUNDEF(obj->meter)) {
        zval_ptr_dtor(&obj->meter);
        ZVAL_UNDEF(&obj->meter);
    }

    zend_object_std_dtor(&obj->std);
}

static zend_object *pcbc_cluster_create_object(zend_class_entry *class_type)
{
    pcbc_cluster_t *obj = NULL;

    obj = PCBC_ALLOC_OBJECT_T(pcbc_cluster_t, class_type);

    zend_object_std_init(&obj->std, class_type);
    object_properties_init(&obj->std, class_type);

    obj->std.handlers = &pcbc_cluster_handlers;
    ZVAL_UNDEF(&obj->meter);
    return &obj->std;
}

#if PHP_VERSION_ID < 80000
static HashTable *pcbc_cluster_get_debug_info(zval *object, int *is_temp)
{
    pcbc_cluster_t *obj = Z_CLUSTER_OBJ_P(object);
#else
static HashTable *pcbc_cluster_get_debug_info(zend_object *object, int *is_temp)
{
    pcbc_cluster_t *obj = pcbc_cluster_fetch_object(object);
#endif
    zval retval;

    *is_temp = 1;

    array_init(&retval);
    add_assoc_string(&retval, "connstr", obj->connstr);

    return Z_ARRVAL(retval);
}

PHP_MINIT_FUNCTION(Cluster)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "Cluster", cluster_methods);
    pcbc_cluster_ce = zend_register_internal_class(&ce);
    pcbc_cluster_ce->create_object = pcbc_cluster_create_object;
    PCBC_CE_DISABLE_SERIALIZATION(pcbc_cluster_ce);

    memcpy(&pcbc_cluster_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    pcbc_cluster_handlers.get_debug_info = pcbc_cluster_get_debug_info;
    pcbc_cluster_handlers.free_obj = pcbc_cluster_free_object;
    pcbc_cluster_handlers.offset = XtOffsetOf(pcbc_cluster_t, std);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
