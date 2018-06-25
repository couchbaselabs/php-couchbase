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
#include <Zend/zend_alloc.h>

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/n1ql_query", __FILE__, __LINE__

zend_class_entry *pcbc_n1ql_query_ce;

#define PCBC_N1QL_CONSISTENCY_NOT_BOUNDED 1
#define PCBC_N1QL_CONSISTENCY_REQUEST_PLUS 2
#define PCBC_N1QL_CONSISTENCY_STATEMENT_PLUS 3

#define PCBC_N1QL_PROFILE_NONE "off"
#define PCBC_N1QL_PROFILE_PHASES "phases"
#define PCBC_N1QL_PROFILE_TIMINGS "timings"

/* {{{ proto void N1qlQuery::__construct() Should not be called directly */
PHP_METHOD(N1qlQuery, __construct)
{
    throw_pcbc_exception("Accessing private constructor.", LCB_EINVAL);
}
/* }}} */

/* {{{ proto \Couchbase\N1qlQuery N1qlQuery::fromString(string $statement) */
PHP_METHOD(N1qlQuery, fromString)
{
    char *statement = NULL;
    pcbc_str_arg_size statement_len = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &statement, &statement_len);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_n1ql_query_init(return_value, statement, statement_len TSRMLS_CC);
} /* }}} */

/* {{{ proto \Couchbase\N1qlQuery N1qlQuery::positionalParams(array $params) */
PHP_METHOD(N1qlQuery, positionalParams)
{
    zval *params;
    zval *options;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &params);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    PCBC_READ_PROPERTY(options, pcbc_n1ql_query_ce, getThis(), "options", 0);
    PCBC_ADDREF_P(params);
    add_assoc_zval(options, "args", params);

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\N1qlQuery N1qlQuery::namedParams(array $params) */
PHP_METHOD(N1qlQuery, namedParams)
{
    zval *params;
    zval *options;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &params);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    PCBC_READ_PROPERTY(options, pcbc_n1ql_query_ce, getThis(), "options", 0);
    {
#if PHP_VERSION_ID >= 70000
        HashTable *ht;
        zend_ulong num_key;
        zend_string *string_key = NULL;
        zval *entry;

        ht = HASH_OF(params);
        ZEND_HASH_FOREACH_KEY_VAL(ht, num_key, string_key, entry)
        {
            if (string_key) {
                char *prefixed_key = NULL;
                spprintf(&prefixed_key, 0, "$%s", ZSTR_VAL(string_key));
                add_assoc_zval(options, prefixed_key, entry);
                PCBC_ADDREF_P(entry);
                efree(prefixed_key);
            }
        }
        ZEND_HASH_FOREACH_END();
#else
        HashPosition pos;
        zval **entry;

        zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(params), &pos);
        while (zend_hash_get_current_data_ex(Z_ARRVAL_P(params), (void **)&entry, &pos) == SUCCESS) {
            if (zend_hash_get_current_key_type_ex(Z_ARRVAL_P(params), &pos) == HASH_KEY_IS_STRING) {
                char *key = NULL, *prefixed_key = NULL;
                uint key_len = 0;
                zend_hash_get_current_key_ex(Z_ARRVAL_P(params), &key, &key_len, NULL, 0, &pos);
                spprintf(&prefixed_key, 0, "$%s", key);
                add_assoc_zval(options, prefixed_key, *entry);
                PCBC_ADDREF_P(*entry);
                efree(prefixed_key);
            }
            zend_hash_move_forward_ex(Z_ARRVAL_P(params), &pos);
        }
#endif
    }
    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\N1qlQuery N1qlQuery::adhoc(boolean $adhoc) */
PHP_METHOD(N1qlQuery, adhoc)
{
    zend_bool adhoc = 0;
    pcbc_n1ql_query_t *obj;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &adhoc);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_N1QL_QUERY_OBJ_P(getThis());
    obj->adhoc = adhoc;

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\N1qlQuery N1qlQuery::crossBucket(boolean $crossBucket) */
PHP_METHOD(N1qlQuery, crossBucket)
{
    zend_bool cross_bucket = 0;
    pcbc_n1ql_query_t *obj;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &cross_bucket);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_N1QL_QUERY_OBJ_P(getThis());
    obj->cross_bucket = cross_bucket;

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\N1qlQuery N1qlQuery::scanCap(int $scanCap) */
PHP_METHOD(N1qlQuery, scanCap)
{
    long scan_cap = 0;
    int rv;
    zval *options;
    char *val = NULL;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &scan_cap);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    PCBC_READ_PROPERTY(options, pcbc_n1ql_query_ce, getThis(), "options", 0);
    spprintf(&val, 0, "%ld", scan_cap);
    ADD_ASSOC_STRING(options, "scan_cap", val);
    efree(val);

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\N1qlQuery N1qlQuery::pipelineBatch(int $pipelineBatch) */
PHP_METHOD(N1qlQuery, pipelineBatch)
{
    long pipeline_batch = 0;
    int rv;
    zval *options;
    char *val = NULL;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &pipeline_batch);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    PCBC_READ_PROPERTY(options, pcbc_n1ql_query_ce, getThis(), "options", 0);
    spprintf(&val, 0, "%ld", pipeline_batch);
    ADD_ASSOC_STRING(options, "pipeline_batch", val);
    efree(val);

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\N1qlQuery N1qlQuery::pipelineCap(int $pipelineCap) */
PHP_METHOD(N1qlQuery, pipelineCap)
{
    long pipeline_cap = 0;
    int rv;
    zval *options;
    char *val = NULL;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &pipeline_cap);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    PCBC_READ_PROPERTY(options, pcbc_n1ql_query_ce, getThis(), "options", 0);
    spprintf(&val, 0, "%ld", pipeline_cap);
    ADD_ASSOC_STRING(options, "pipeline_cap", val);
    efree(val);

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\N1qlQuery N1qlQuery::maxParallelism(int $maxParallelism) */
PHP_METHOD(N1qlQuery, maxParallelism)
{
    long max_parallelism = 0;
    int rv;
    zval *options;
    char *val = NULL;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &max_parallelism);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    PCBC_READ_PROPERTY(options, pcbc_n1ql_query_ce, getThis(), "options", 0);
    spprintf(&val, 0, "%ld", max_parallelism);
    ADD_ASSOC_STRING(options, "max_parallelism", val);
    efree(val);

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\N1qlQuery N1qlQuery::readonly(boolean $readonly) */
PHP_METHOD(N1qlQuery, readonly)
{
    zend_bool readonly = 0;
    zval *options;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "b", &readonly);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    PCBC_READ_PROPERTY(options, pcbc_n1ql_query_ce, getThis(), "options", 0);
    ADD_ASSOC_BOOL_EX(options, "readonly", readonly);

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\N1qlQuery N1qlQuery::consistency(int $consistency) */
PHP_METHOD(N1qlQuery, consistency)
{
    long consistency = 0;
    int rv;
    zval *options;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &consistency);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    PCBC_READ_PROPERTY(options, pcbc_n1ql_query_ce, getThis(), "options", 0);
    switch (consistency) {
    case PCBC_N1QL_CONSISTENCY_NOT_BOUNDED:
        ADD_ASSOC_STRING(options, "scan_consistency", "not_bounded");
        break;
    case PCBC_N1QL_CONSISTENCY_REQUEST_PLUS:
        ADD_ASSOC_STRING(options, "scan_consistency", "request_plus");
        break;
    case PCBC_N1QL_CONSISTENCY_STATEMENT_PLUS:
        ADD_ASSOC_STRING(options, "scan_consistency", "statement_plus");
        break;
    default:
        throw_pcbc_exception("Invalid scan consistency value", LCB_EINVAL);
        RETURN_NULL();
    }

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\N1qlQuery N1qlQuery::profile(string $profileType) */
PHP_METHOD(N1qlQuery, profile)
{
    char *profile_type = NULL;
    pcbc_str_arg_size profile_type_len = 0;
    int rv;
    zval *options;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &profile_type, &profile_type_len);
    if (rv == FAILURE || profile_type == NULL) {
        RETURN_NULL();
    }

    PCBC_READ_PROPERTY(options, pcbc_n1ql_query_ce, getThis(), "options", 0);
    ADD_ASSOC_STRING(options, "profile", profile_type);
    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\N1qlQuery N1qlQuery::consistentWith(\Couchbase\MutationState $mutationState) */
PHP_METHOD(N1qlQuery, consistentWith)
{
    int rv;
    zval *options, *mutation_state = NULL;
    PCBC_ZVAL scan_vectors;
    pcbc_mutation_state_t *state;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &mutation_state, pcbc_mutation_state_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    state = Z_MUTATION_STATE_OBJ_P(mutation_state);
    if (state->ntokens == 0) {
        throw_pcbc_exception("Mutation state have to contain at least one token", LCB_EINVAL);
        RETURN_NULL();
    }

    PCBC_ZVAL_ALLOC(scan_vectors);
    pcbc_mutation_state_export_for_n1ql(state, PCBC_P(scan_vectors) TSRMLS_CC);
    PCBC_READ_PROPERTY(options, pcbc_n1ql_query_ce, getThis(), "options", 0);
    ADD_ASSOC_STRING(options, "scan_consistency", "at_plus");
    ADD_ASSOC_ZVAL_EX(options, "scan_vectors", PCBC_P(scan_vectors));

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

ZEND_BEGIN_ARG_INFO_EX(ai_N1qlQuery_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_N1qlQuery_fromString, 0, 0, 1)
ZEND_ARG_INFO(0, statement)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_N1qlQuery_adhoc, 0, 0, 1)
ZEND_ARG_INFO(0, adhoc)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_N1qlQuery_crossBucket, 0, 0, 1)
ZEND_ARG_INFO(0, crossBucket)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_N1qlQuery_consistency, 0, 0, 1)
ZEND_ARG_INFO(0, consistency)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_N1qlQuery_profile, 0, 0, 1)
ZEND_ARG_INFO(0, profileType)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_N1qlQuery_params, 0, 0, 1)
ZEND_ARG_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_N1qlQuery_consistentWith, 0, 0, 1)
ZEND_ARG_INFO(0, mutationState)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_N1qlQuery_scanCap, 0, 0, 1)
ZEND_ARG_INFO(0, scanCap)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_N1qlQuery_pipelineBatch, 0, 0, 1)
ZEND_ARG_INFO(0, pipelineBatch)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_N1qlQuery_pipelineCap, 0, 0, 1)
ZEND_ARG_INFO(0, pipelineCap)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_N1qlQuery_maxParallelism, 0, 0, 1)
ZEND_ARG_INFO(0, maxParallelism)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_N1qlQuery_readonly, 0, 0, 1)
ZEND_ARG_INFO(0, readonly)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry n1ql_query_methods[] = {
    PHP_ME(N1qlQuery, __construct, ai_N1qlQuery_none, ZEND_ACC_PRIVATE | ZEND_ACC_FINAL | ZEND_ACC_CTOR)
    PHP_ME(N1qlQuery, fromString, ai_N1qlQuery_fromString, ZEND_ACC_STATIC | ZEND_ACC_PUBLIC)
    PHP_ME(N1qlQuery, adhoc, ai_N1qlQuery_adhoc, ZEND_ACC_PUBLIC)
    PHP_ME(N1qlQuery, crossBucket, ai_N1qlQuery_crossBucket, ZEND_ACC_PUBLIC)
    PHP_ME(N1qlQuery, positionalParams, ai_N1qlQuery_params, ZEND_ACC_PUBLIC)
    PHP_ME(N1qlQuery, namedParams, ai_N1qlQuery_params, ZEND_ACC_PUBLIC)
    PHP_ME(N1qlQuery, consistency, ai_N1qlQuery_consistency, ZEND_ACC_PUBLIC)
    PHP_ME(N1qlQuery, profile, ai_N1qlQuery_profile, ZEND_ACC_PUBLIC)
    PHP_ME(N1qlQuery, consistentWith, ai_N1qlQuery_consistentWith, ZEND_ACC_PUBLIC)
    PHP_ME(N1qlQuery, scanCap, ai_N1qlQuery_scanCap, ZEND_ACC_PUBLIC)
    PHP_ME(N1qlQuery, pipelineBatch, ai_N1qlQuery_pipelineBatch, ZEND_ACC_PUBLIC)
    PHP_ME(N1qlQuery, pipelineCap, ai_N1qlQuery_pipelineCap, ZEND_ACC_PUBLIC)
    PHP_ME(N1qlQuery, maxParallelism, ai_N1qlQuery_maxParallelism, ZEND_ACC_PUBLIC)
    PHP_ME(N1qlQuery, readonly, ai_N1qlQuery_readonly, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

zend_object_handlers pcbc_n1ql_query_handlers;

void pcbc_n1ql_query_init(zval *return_value, const char *statement, int statement_len TSRMLS_DC)
{
    pcbc_n1ql_query_t *query;
    PCBC_ZVAL options;

    object_init_ex(return_value, pcbc_n1ql_query_ce);
    query = Z_N1QL_QUERY_OBJ_P(return_value);

    PCBC_ZVAL_ALLOC(options);
    array_init(PCBC_P(options));
    ADD_ASSOC_STRINGL(PCBC_P(options), "statement", statement, statement_len);
    zend_update_property(pcbc_n1ql_query_ce, return_value, ZEND_STRL("options"), PCBC_P(options) TSRMLS_CC);
    zval_ptr_dtor(&options);
    query->adhoc = 1;
}

static void n1ql_query_free_object(pcbc_free_object_arg *object TSRMLS_DC) /* {{{ */
{
    pcbc_n1ql_query_t *obj = Z_N1QL_QUERY_OBJ(object);

    zend_object_std_dtor(&obj->std TSRMLS_CC);
#if PHP_VERSION_ID < 70000
    efree(obj);
#endif
} /* }}} */

static pcbc_create_object_retval n1ql_query_create_object(zend_class_entry *class_type TSRMLS_DC)
{
    pcbc_n1ql_query_t *obj = NULL;

    obj = PCBC_ALLOC_OBJECT_T(pcbc_n1ql_query_t, class_type);

    zend_object_std_init(&obj->std, class_type TSRMLS_CC);
    object_properties_init(&obj->std, class_type);

#if PHP_VERSION_ID >= 70000
    obj->std.handlers = &pcbc_n1ql_query_handlers;
    return &obj->std;
#else
    {
        zend_object_value ret;
        ret.handle = zend_objects_store_put(obj, (zend_objects_store_dtor_t)zend_objects_destroy_object,
                                            n1ql_query_free_object, NULL TSRMLS_CC);
        ret.handlers = &pcbc_n1ql_query_handlers;
        return ret;
    }
#endif
}

static HashTable *n1ql_query_get_debug_info(zval *object, int *is_temp TSRMLS_DC) /* {{{ */
{
    pcbc_n1ql_query_t *obj = NULL;
#if PHP_VERSION_ID >= 70000
    zval retval;
#else
    zval retval = zval_used_for_init;
#endif
    zval *options;

    *is_temp = 1;
    obj = Z_N1QL_QUERY_OBJ_P(object);

    array_init(&retval);
    PCBC_READ_PROPERTY(options, pcbc_n1ql_query_ce, object, "options", 0);
    PCBC_ADDREF_P(options);
    add_assoc_zval(&retval, "options", options);
    ADD_ASSOC_BOOL_EX(&retval, "adhoc", obj->adhoc);
    ADD_ASSOC_BOOL_EX(&retval, "crossBucket", obj->cross_bucket);

    return Z_ARRVAL(retval);
} /* }}} */

PHP_MINIT_FUNCTION(N1qlQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "N1qlQuery", n1ql_query_methods);
    pcbc_n1ql_query_ce = zend_register_internal_class(&ce TSRMLS_CC);
    pcbc_n1ql_query_ce->create_object = n1ql_query_create_object;
    PCBC_CE_DISABLE_SERIALIZATION(pcbc_n1ql_query_ce);

    memcpy(&pcbc_n1ql_query_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    pcbc_n1ql_query_handlers.get_debug_info = n1ql_query_get_debug_info;
#if PHP_VERSION_ID >= 70000
    pcbc_n1ql_query_handlers.free_obj = n1ql_query_free_object;
    pcbc_n1ql_query_handlers.offset = XtOffsetOf(pcbc_n1ql_query_t, std);
#endif
    zend_declare_property_null(pcbc_n1ql_query_ce, ZEND_STRL("options"), ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_class_constant_long(pcbc_n1ql_query_ce, ZEND_STRL("NOT_BOUNDED"),
                                     PCBC_N1QL_CONSISTENCY_NOT_BOUNDED TSRMLS_CC);
    zend_declare_class_constant_long(pcbc_n1ql_query_ce, ZEND_STRL("REQUEST_PLUS"),
                                     PCBC_N1QL_CONSISTENCY_REQUEST_PLUS TSRMLS_CC);
    zend_declare_class_constant_long(pcbc_n1ql_query_ce, ZEND_STRL("STATEMENT_PLUS"),
                                     PCBC_N1QL_CONSISTENCY_STATEMENT_PLUS TSRMLS_CC);

    zend_declare_class_constant_string(pcbc_n1ql_query_ce, ZEND_STRL("PROFILE_NONE"), PCBC_N1QL_PROFILE_NONE TSRMLS_CC);
    zend_declare_class_constant_string(pcbc_n1ql_query_ce, ZEND_STRL("PROFILE_PHASES"),
                                       PCBC_N1QL_PROFILE_PHASES TSRMLS_CC);
    zend_declare_class_constant_string(pcbc_n1ql_query_ce, ZEND_STRL("PROFILE_TIMINGS"),
                                       PCBC_N1QL_PROFILE_TIMINGS TSRMLS_CC);

    zend_register_class_alias("\\CouchbaseN1qlQuery", pcbc_n1ql_query_ce);
    return SUCCESS;
}
