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

#define LOGARGS(obj, lvl) LCB_LOG_##lvl, obj->conn->lcb, "pcbc/bucket", __FILE__, __LINE__

zend_class_entry *pcbc_bucket_ce;
extern zend_class_entry *pcbc_scope_ce;
extern zend_class_entry *pcbc_view_index_manager_ce;
extern zend_class_entry *pcbc_collection_manager_ce;

PHP_METHOD(Bucket, ping);
PHP_METHOD(Bucket, diagnostics);

PHP_METHOD(Bucket, viewQuery);

PHP_METHOD(Bucket, __construct)
{
    throw_pcbc_exception("Accessing private constructor.", LCB_ERR_INVALID_ARGUMENT);
}

PHP_METHOD(Bucket, setTranscoder)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    zval *encoder, *decoder;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &encoder, &decoder);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    if (!Z_ISUNDEF(obj->encoder)) {
        zval_ptr_dtor(&obj->encoder);
        ZVAL_UNDEF(&obj->encoder);
    }
    ZVAL_ZVAL(&obj->encoder, encoder, 1, 0);

    if (!Z_ISUNDEF(obj->decoder)) {
        zval_ptr_dtor(&obj->decoder);
        ZVAL_UNDEF(&obj->decoder);
    }
    ZVAL_ZVAL(&obj->decoder, decoder, 1, 0);

    RETURN_NULL();
}

PHP_METHOD(Bucket, __set)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    char *name;
    size_t name_len = 0;
    int rv, cmd;
    long val;
    lcb_uint32_t lcbval;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl", &name, &name_len, &val);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    lcbval = val;

    if (strncmp(name, "operationTimeout", name_len) == 0) {
        cmd = LCB_CNTL_OP_TIMEOUT;
    } else if (strncmp(name, "viewTimeout", name_len) == 0) {
        cmd = LCB_CNTL_VIEW_TIMEOUT;
    } else if (strncmp(name, "n1qlTimeout", name_len) == 0) {
        cmd = LCB_CNTL_QUERY_TIMEOUT;
    } else if (strncmp(name, "durabilityInterval", name_len) == 0) {
        cmd = LCB_CNTL_DURABILITY_INTERVAL;
    } else if (strncmp(name, "durabilityTimeout", name_len) == 0) {
        cmd = LCB_CNTL_DURABILITY_TIMEOUT;
    } else if (strncmp(name, "httpTimeout", name_len) == 0) {
        cmd = LCB_CNTL_HTTP_TIMEOUT;
    } else if (strncmp(name, "configTimeout", name_len) == 0) {
        cmd = LCB_CNTL_CONFIGURATION_TIMEOUT;
    } else if (strncmp(name, "configDelay", name_len) == 0) {
        cmd = LCB_CNTL_CONFDELAY_THRESH;
    } else if (strncmp(name, "configNodeTimeout", name_len) == 0) {
        cmd = LCB_CNTL_CONFIG_NODE_TIMEOUT;
    } else if (strncmp(name, "htconfigIdleTimeout", name_len) == 0) {
        cmd = LCB_CNTL_HTCONFIG_IDLE_TIMEOUT;
    } else if (strncmp(name, "configPollInterval", name_len) == 0) {
        cmd = LCB_CNTL_CONFIG_POLL_INTERVAL;
    } else {
        pcbc_log(LOGARGS(obj, WARN), "Undefined property of \\Couchbase\\Bucket via __set(): %s", name);
        RETURN_NULL();
    }
    lcb_cntl(obj->conn->lcb, LCB_CNTL_SET, cmd, &lcbval);

    RETURN_LONG(val);
}

PHP_METHOD(Bucket, __get)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    char *name;
    size_t name_len = 0;
    int rv, cmd;
    lcb_uint32_t lcbval;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &name_len);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    if (strncmp(name, "operationTimeout", name_len) == 0) {
        cmd = LCB_CNTL_OP_TIMEOUT;
    } else if (strncmp(name, "viewTimeout", name_len) == 0) {
        cmd = LCB_CNTL_VIEW_TIMEOUT;
    } else if (strncmp(name, "durabilityInterval", name_len) == 0) {
        cmd = LCB_CNTL_DURABILITY_INTERVAL;
    } else if (strncmp(name, "durabilityTimeout", name_len) == 0) {
        cmd = LCB_CNTL_DURABILITY_TIMEOUT;
    } else if (strncmp(name, "httpTimeout", name_len) == 0) {
        cmd = LCB_CNTL_HTTP_TIMEOUT;
    } else if (strncmp(name, "configTimeout", name_len) == 0) {
        cmd = LCB_CNTL_CONFIGURATION_TIMEOUT;
    } else if (strncmp(name, "configDelay", name_len) == 0) {
        cmd = LCB_CNTL_CONFDELAY_THRESH;
    } else if (strncmp(name, "configNodeTimeout", name_len) == 0) {
        cmd = LCB_CNTL_CONFIG_NODE_TIMEOUT;
    } else if (strncmp(name, "htconfigIdleTimeout", name_len) == 0) {
        cmd = LCB_CNTL_HTCONFIG_IDLE_TIMEOUT;
    } else if (strncmp(name, "configPollInterval", name_len) == 0) {
        cmd = LCB_CNTL_CONFIG_POLL_INTERVAL;
    } else {
        pcbc_log(LOGARGS(obj, WARN), "Undefined property of \\Couchbase\\Bucket via __get(): %s", name);
        RETURN_NULL();
    }
    lcb_cntl(obj->conn->lcb, LCB_CNTL_GET, cmd, &lcbval);

    RETURN_LONG(lcbval);
}

PHP_METHOD(Bucket, name)
{
    int rv;
    pcbc_bucket_t *obj;

    rv = zend_parse_parameters_none();
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    obj = Z_BUCKET_OBJ_P(getThis());

    if (obj->conn && obj->conn->bucketname) {
        RETURN_STRING(obj->conn->bucketname);
    }
    RETURN_NULL();
}

PHP_METHOD(Bucket, collections)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    object_init_ex(return_value, pcbc_collection_manager_ce);
    zend_update_property(pcbc_collection_manager_ce, return_value, ZEND_STRL("bucket"), getThis() TSRMLS_CC);
}

PHP_METHOD(Bucket, viewIndexes)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    object_init_ex(return_value, pcbc_view_index_manager_ce);
    zend_update_property(pcbc_view_index_manager_ce, return_value, ZEND_STRL("bucket"), getThis() TSRMLS_CC);
}

PHP_METHOD(Bucket, defaultCollection)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    object_init_ex(return_value, pcbc_collection_ce);
    zend_update_property(pcbc_collection_ce, return_value, ZEND_STRL("bucket"), getThis() TSRMLS_CC);
}

PHP_METHOD(Bucket, defaultScope)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    object_init_ex(return_value, pcbc_scope_ce);
    zend_update_property(pcbc_scope_ce, return_value, ZEND_STRL("bucket"), getThis() TSRMLS_CC);
}

PHP_METHOD(Bucket, scope)
{
    int rv;
    zend_string *name;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    object_init_ex(return_value, pcbc_scope_ce);
    zend_update_property(pcbc_scope_ce, return_value, ZEND_STRL("bucket"), getThis() TSRMLS_CC);
    zend_update_property_str(pcbc_scope_ce, return_value, ZEND_STRL("name"), name TSRMLS_CC);
}

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_Bucket_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket___get, 0, 0, 1)
ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket___set, 0, 0, 2)
ZEND_ARG_INFO(0, name)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_setTranscoder, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, encoder, IS_CALLABLE, 0)
ZEND_ARG_TYPE_INFO(0, decoder, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Bucket_viewQuery, 0, 2, Couchbase\\ViewResult, 0)
ZEND_ARG_TYPE_INFO(0, designDoc, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, viewName, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, viewOptions, Couchbase\\ViewOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_ping, 0, 0, 2)
ZEND_ARG_INFO(0, services)
ZEND_ARG_INFO(0, reportId)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_diag, 0, 0, 1)
ZEND_ARG_INFO(0, reportId)
ZEND_END_ARG_INFO()

PHP_METHOD(Bucket, defaultCollection);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Bucket_defaultCollection, 0, 0, Couchbase\\Collection, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Bucket, defaultScope);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Bucket_defaultScope, 0, 0, Couchbase\\Scope, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Bucket, scope);
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Bucket_scope, 0, 1, Couchbase\\Scope, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Bucket_collections, 0, 1, Couchbase\\CollectionManager, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Bucket_viewIndexes, 0, 1, Couchbase\\ViewIndexManager, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry bucket_methods[] = {
    PHP_ME(Bucket, __construct, ai_Bucket_none, ZEND_ACC_PRIVATE | ZEND_ACC_FINAL | ZEND_ACC_CTOR)
    PHP_ME(Bucket, __get, ai_Bucket___get, ZEND_ACC_PRIVATE)
    PHP_ME(Bucket, __set, ai_Bucket___set, ZEND_ACC_PRIVATE)
    PHP_ME(Bucket, setTranscoder, ai_Bucket_setTranscoder, ZEND_ACC_PUBLIC)
    PHP_ME(Bucket, name, ai_Bucket_name, ZEND_ACC_PUBLIC)
    PHP_ME(Bucket, viewQuery, ai_Bucket_viewQuery, ZEND_ACC_PUBLIC)
    PHP_ME(Bucket, ping, ai_Bucket_ping, ZEND_ACC_PUBLIC)
    PHP_ME(Bucket, diagnostics, ai_Bucket_diag, ZEND_ACC_PUBLIC)
    PHP_ME(Bucket, defaultCollection, ai_Bucket_defaultCollection, ZEND_ACC_PUBLIC)
    PHP_ME(Bucket, defaultScope, ai_Bucket_defaultScope, ZEND_ACC_PUBLIC)
    PHP_ME(Bucket, scope, ai_Bucket_scope, ZEND_ACC_PUBLIC)
    PHP_ME(Bucket, collections, ai_Bucket_collections, ZEND_ACC_PUBLIC)
    PHP_ME(Bucket, viewIndexes, ai_Bucket_viewIndexes, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

zend_object_handlers pcbc_bucket_handlers;

static void pcbc_bucket_free_object(zend_object *object TSRMLS_DC)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ(object);

    /*
    if (obj->crypto_head) {
        pcbc_crypto_id_t *ptr, *cur;
        for (ptr = obj->crypto_head; ptr;) {
            cur = ptr;
            if (cur->name) {
                pcbc_crypto_unregister(obj, cur->name, cur->name_len TSRMLS_CC);
                efree(cur->name);
            }
            ptr = ptr->next;
            efree(ptr);
        }
    }
    */
    pcbc_connection_delref(obj->conn TSRMLS_CC);
    if (!Z_ISUNDEF(obj->encoder)) {
        zval_ptr_dtor(&obj->encoder);
        ZVAL_UNDEF(&obj->encoder);
    }
    if (!Z_ISUNDEF(obj->decoder)) {
        zval_ptr_dtor(&obj->decoder);
        ZVAL_UNDEF(&obj->decoder);
    }

    zend_object_std_dtor(&obj->std TSRMLS_CC);
}

static zend_object *pcbc_bucket_create_object(zend_class_entry *class_type TSRMLS_DC)
{
    pcbc_bucket_t *obj = NULL;

    obj = PCBC_ALLOC_OBJECT_T(pcbc_bucket_t, class_type);

    zend_object_std_init(&obj->std, class_type TSRMLS_CC);
    object_properties_init(&obj->std, class_type);

    obj->std.handlers = &pcbc_bucket_handlers;
    return &obj->std;
}

static HashTable *pcbc_bucket_get_debug_info(zval *object, int *is_temp TSRMLS_DC)
{
    pcbc_bucket_t *obj = NULL;
    zval retval;

    *is_temp = 1;
    obj = Z_BUCKET_OBJ_P(object);

    array_init(&retval);
    switch (obj->type) {
    case LCB_BTYPE_COUCHBASE:
        add_assoc_string(&retval, "type", "couchbase");
        break;
    case LCB_BTYPE_MEMCACHED:
        add_assoc_string(&retval, "type", "memcached");
        break;
    case LCB_BTYPE_EPHEMERAL:
        add_assoc_string(&retval, "type", "ephemeral");
        break;
    case LCB_BTYPE_UNSPEC:
    default:
        add_assoc_string(&retval, "type", "unknown");
        break;
    }
    add_assoc_string(&retval, "connstr", obj->conn->connstr);
    add_assoc_string(&retval, "bucket", obj->conn->bucketname);
    add_assoc_string(&retval, "username", obj->conn->username);
    if (!Z_ISUNDEF(obj->encoder)) {
        add_assoc_zval(&retval, "encoder", &obj->encoder);
        PCBC_ADDREF_P(&obj->encoder);
    } else {
        add_assoc_null(&retval, "encoder");
    }
    if (!Z_ISUNDEF(obj->decoder)) {
        add_assoc_zval(&retval, "decoder", &obj->decoder);
        PCBC_ADDREF_P(&obj->decoder);
    } else {
        add_assoc_null(&retval, "decoder");
    }

    return Z_ARRVAL(retval);
}

PHP_MINIT_FUNCTION(Bucket)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "Bucket", bucket_methods);
    pcbc_bucket_ce = zend_register_internal_class(&ce TSRMLS_CC);
    pcbc_bucket_ce->create_object = pcbc_bucket_create_object;
    PCBC_CE_DISABLE_SERIALIZATION(pcbc_bucket_ce);

    memcpy(&pcbc_bucket_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    pcbc_bucket_handlers.get_debug_info = pcbc_bucket_get_debug_info;
    pcbc_bucket_handlers.free_obj = pcbc_bucket_free_object;
    pcbc_bucket_handlers.offset = XtOffsetOf(pcbc_bucket_t, std);
    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
