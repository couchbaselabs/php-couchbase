/**
 *     Copyright 2017-2019 Couchbase, Inc.
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

#define LOGARGS(obj, lvl) LCB_LOG_##lvl, obj->conn->lcb, "pcbc/collection", __FILE__, __LINE__

zend_class_entry *pcbc_binary_collection_ce;
zend_class_entry *pcbc_collection_ce;
zend_class_entry *pcbc_scope_ce;

PHP_METHOD(Scope, __construct)
{
    zend_string *name = NULL;
    zval *bucket;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "OS!", &bucket, pcbc_bucket_ce, &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property(pcbc_collection_ce, getThis(), ZEND_STRL("bucket"), bucket TSRMLS_CC);
    if (name) {
        zend_update_property_str(pcbc_collection_ce, getThis(), ZEND_STRL("name"), name TSRMLS_CC);
    }
}

PHP_METHOD(Scope, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_scope_ce, getThis(), ZEND_STRL("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(Scope, collection)
{
    int rv;
    zend_string *name;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    object_init_ex(return_value, pcbc_collection_ce);
    zend_update_property_str(pcbc_collection_ce, return_value, ZEND_STRL("name"), name TSRMLS_CC);

    zval *bucket, *scope, rv1, rv2;
    scope = zend_read_property(pcbc_scope_ce, getThis(), ZEND_STRL("name"), 0, &rv1);
    zend_update_property(pcbc_collection_ce, return_value, ZEND_STRL("scope"), scope TSRMLS_CC);
    bucket = zend_read_property(pcbc_scope_ce, getThis(), ZEND_STRL("bucket"), 0, &rv2);
    zend_update_property(pcbc_collection_ce, return_value, ZEND_STRL("bucket"), bucket TSRMLS_CC);
}

ZEND_BEGIN_ARG_INFO_EX(ai_Scope___construct, 0, 0, 1)
ZEND_ARG_OBJ_INFO(0, bucket, \\Couchbase\\Bucket, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_Scope_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Scope_collection, 0, 1, \\Couchbase\\Collection, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry scope_methods[] = {
    PHP_ME(Scope, __construct, ai_Scope___construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(Scope, name, ai_Scope_name, ZEND_ACC_PUBLIC)
    PHP_ME(Scope, collection, ai_Scope_collection, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Collection, __construct)
{
    zend_string *scope = NULL, *name = NULL;
    zval *bucket;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "OS!S!", &bucket, pcbc_bucket_ce, &scope, &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property(pcbc_collection_ce, getThis(), ZEND_STRL("bucket"), bucket TSRMLS_CC);
    if (scope) {
        zend_update_property_str(pcbc_collection_ce, getThis(), ZEND_STRL("scope"), scope TSRMLS_CC);
    }
    if (name) {
        zend_update_property_str(pcbc_collection_ce, getThis(), ZEND_STRL("name"), name TSRMLS_CC);
    }
}

PHP_METHOD(Collection, binary)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }
    object_init_ex(return_value, pcbc_binary_collection_ce);
    zval *bucket, *scope, *collection, rv1, rv2, rv3;
    bucket = zend_read_property(pcbc_collection_ce, getThis(), ZEND_STRL("bucket"), 0, &rv2);
    zend_update_property(pcbc_binary_collection_ce, return_value, ZEND_STRL("bucket"), bucket TSRMLS_CC);
    collection = zend_read_property(pcbc_collection_ce, getThis(), ZEND_STRL("name"), 0, &rv3);
    zend_update_property(pcbc_binary_collection_ce, return_value, ZEND_STRL("name"), collection TSRMLS_CC);
    scope = zend_read_property(pcbc_collection_ce, getThis(), ZEND_STRL("scope"), 0, &rv1);
    zend_update_property(pcbc_binary_collection_ce, return_value, ZEND_STRL("scope"), scope TSRMLS_CC);
}

PHP_METHOD(Collection, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_collection_ce, getThis(), ZEND_STRL("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BinaryCollection, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_binary_collection_ce, getThis(), ZEND_STRL("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_Collection_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Collection___construct, 0, 0, 1)
ZEND_ARG_OBJ_INFO(0, bucket, \\Couchbase\\Bucket, 0)
ZEND_ARG_TYPE_INFO(0, scope, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, get);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Collection_get, 0, 1, \\Couchbase\\GetResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\GetOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, getAndLock);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Collection_getAndLock, 0, 2, \\Couchbase\\GetResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, lockTime, IS_LONG, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\GetAndLockOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, getAndTouch);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Collection_getAndTouch, 0, 2, \\Couchbase\\GetResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, expiry, IS_LONG, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\GetAndTouchOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, exists);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Collection_exists, 0, 1, \\Couchbase\\ExistsResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\ExistsOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, getAnyReplica);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Collection_getAnyReplica, 0, 1, \\Couchbase\\GetReplicaResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\GetAnyReplicaOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, getAllReplicas);
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_Collection_getAllReplicas, IS_ARRAY, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\GetAllReplicasOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, upsert);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Collection_upsert, 0, 2, \\Couchbase\\MutationResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_INFO(0, value)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\UpsertOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, insert);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Collection_insert, 0, 2, \\Couchbase\\MutationResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_INFO(0, value)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\InsertOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, replace);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Collection_replace, 0, 2, \\Couchbase\\MutationResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_INFO(0, value)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\ReplaceOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, remove);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Collection_remove, 0, 1, \\Couchbase\\MutationResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\RemoveOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, unlock);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Collection_unlock, 0, 2, \\Couchbase\\Result, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, cas, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\UnlockOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, touch);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Collection_touch, 0, 2, \\Couchbase\\Result, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, expiry, IS_LONG, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\TouchOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, lookupIn);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Collection_lookupIn, 0, 2, \\Couchbase\\LookupInResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, specs, IS_ARRAY, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\LookupInOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, mutateIn);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Collection_mutateIn, 0, 2, \\Couchbase\\MutateInResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, specs, IS_ARRAY, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\MutateInOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(Collection, binary);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Collection_binary, 0, 0, \\Couchbase\\BinaryCollection, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BinaryCollection_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(BinaryCollection, append);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BinaryCollection_append, 0, 2, \\Couchbase\\MutationResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, value, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\AppendOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(BinaryCollection, prepend);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BinaryCollection_prepend, 0, 2, \\Couchbase\\MutationResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, value, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\PrependOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(BinaryCollection, increment);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BinaryCollection_increment, 0, 1, \\Couchbase\\CounterResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\IncrementOptions, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(BinaryCollection, decrement);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BinaryCollection_decrement, 0, 1, \\Couchbase\\CounterResult, 0)
ZEND_ARG_TYPE_INFO(0, id, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, \\Couchbase\\DecrementOptions, 1)
ZEND_END_ARG_INFO()

// clang-format off
static zend_function_entry binary_collection_methods[] = {
    PHP_ME(BinaryCollection, name, ai_BinaryCollection_name, ZEND_ACC_PUBLIC)
    PHP_ME(BinaryCollection, append, ai_BinaryCollection_append, ZEND_ACC_PUBLIC)
    PHP_ME(BinaryCollection, prepend, ai_BinaryCollection_prepend, ZEND_ACC_PUBLIC)
    PHP_ME(BinaryCollection, increment, ai_BinaryCollection_increment, ZEND_ACC_PUBLIC)
    PHP_ME(BinaryCollection, decrement, ai_BinaryCollection_decrement, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static zend_function_entry collection_methods[] = {
    PHP_ME(Collection, __construct, ai_Collection___construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(Collection, name, ai_Collection_name, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, get, ai_Collection_get, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, exists, ai_Collection_exists, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, getAndLock, ai_Collection_getAndLock, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, getAndTouch, ai_Collection_getAndTouch, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, getAnyReplica, ai_Collection_getAnyReplica, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, getAllReplicas, ai_Collection_getAllReplicas, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, upsert, ai_Collection_upsert, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, insert, ai_Collection_insert, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, replace, ai_Collection_replace, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, remove, ai_Collection_remove, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, unlock, ai_Collection_unlock, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, touch, ai_Collection_touch, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, lookupIn, ai_Collection_lookupIn, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, mutateIn, ai_Collection_mutateIn, ZEND_ACC_PUBLIC)
    PHP_ME(Collection, binary, ai_Collection_binary, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(Collection)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "Collection", collection_methods);
    pcbc_collection_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_declare_property_null(pcbc_collection_ce, ZEND_STRL("bucket"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_collection_ce, ZEND_STRL("scope"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_collection_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "BinaryCollection", binary_collection_methods);
    pcbc_binary_collection_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_declare_property_null(pcbc_binary_collection_ce, ZEND_STRL("bucket"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_binary_collection_ce, ZEND_STRL("scope"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_binary_collection_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "Scope", scope_methods);
    pcbc_scope_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_declare_property_null(pcbc_scope_ce, ZEND_STRL("bucket"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_scope_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
