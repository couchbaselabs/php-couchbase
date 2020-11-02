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

/**
 * A compound FTS query that allows various combinations of sub-queries.
 */
#include "couchbase.h"

typedef struct {
    PCBC_ZEND_OBJECT_PRE
    double boost;
    PCBC_ZVAL must;
    PCBC_ZVAL must_not;
    PCBC_ZVAL should;
    PCBC_ZEND_OBJECT_POST
} pcbc_boolean_search_query_t;

#if PHP_VERSION_ID >= 70000
static inline pcbc_boolean_search_query_t *pcbc_boolean_search_query_fetch_object(zend_object *obj)
{
    return (pcbc_boolean_search_query_t *)((char *)obj - XtOffsetOf(pcbc_boolean_search_query_t, std));
}
#define Z_BOOLEAN_SEARCH_QUERY_OBJ(zo) (pcbc_boolean_search_query_fetch_object(zo))
#define Z_BOOLEAN_SEARCH_QUERY_OBJ_P(zv) (pcbc_boolean_search_query_fetch_object(Z_OBJ_P(zv)))
#else
#define Z_BOOLEAN_SEARCH_QUERY_OBJ(zo) ((pcbc_boolean_search_query_t *)zo)
#define Z_BOOLEAN_SEARCH_QUERY_OBJ_P(zv) ((pcbc_boolean_search_query_t *)zend_object_store_get_object(zv TSRMLS_CC))
#endif

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/boolean_search_query", __FILE__, __LINE__

zend_class_entry *pcbc_boolean_search_query_ce;
extern zend_class_entry *pcbc_disjunction_search_query_ce;
extern zend_class_entry *pcbc_conjunction_search_query_ce;

/* {{{ proto void BooleanSearchQuery::__construct() */
PHP_METHOD(BooleanSearchQuery, __construct)
{
    throw_pcbc_exception("Accessing private constructor.", LCB_EINVAL);
}
/* }}} */

/* {{{ proto \Couchbase\BooleanSearchQuery BooleanSearchQuery::boost(double $boost)
 */
PHP_METHOD(BooleanSearchQuery, boost)
{
    pcbc_boolean_search_query_t *obj;
    double boost = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_BOOLEAN_SEARCH_QUERY_OBJ_P(getThis());
    obj->boost = boost;

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\BooleanSearchQuery BooleanSearchQuery::must(SearchQueryPart ...$queries)
 */
PHP_METHOD(BooleanSearchQuery, must)
{
    pcbc_boolean_search_query_t *obj;
    zval *conjunct = NULL;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &conjunct, pcbc_conjunction_search_query_ce);
    if (rv == FAILURE) {
        return;
    }

    obj = Z_BOOLEAN_SEARCH_QUERY_OBJ_P(getThis());

#if PHP_VERSION_ID >= 70000
    ZVAL_ZVAL(&obj->must, conjunct, 1, 0);
#else
    PCBC_ADDREF_P(disjunct);
    obj->must = conjunct;
#endif

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\BooleanSearchQuery BooleanSearchQuery::mustNot(SearchQueryPart ...$queries)
 */
PHP_METHOD(BooleanSearchQuery, mustNot)
{
    pcbc_boolean_search_query_t *obj;
    zval *disjunct = NULL;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &disjunct, pcbc_disjunction_search_query_ce);
    if (rv == FAILURE) {
        return;
    }

    obj = Z_BOOLEAN_SEARCH_QUERY_OBJ_P(getThis());

#if PHP_VERSION_ID >= 70000
    ZVAL_ZVAL(&obj->must_not, disjunct, 1, 0);
#else
    PCBC_ADDREF_P(disjunct);
    obj->must_not = disjunct;
#endif

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto \Couchbase\BooleanSearchQuery BooleanSearchQuery::should(SearchQueryPart ...$queries)
 */
PHP_METHOD(BooleanSearchQuery, should)
{
    pcbc_boolean_search_query_t *obj;
    zval *disjunct = NULL;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &disjunct, pcbc_disjunction_search_query_ce);
    if (rv == FAILURE) {
        return;
    }

    obj = Z_BOOLEAN_SEARCH_QUERY_OBJ_P(getThis());

#if PHP_VERSION_ID >= 70000
    ZVAL_ZVAL(&obj->should, disjunct, 1, 0);
#else
    PCBC_ADDREF_P(disjunct);
    obj->should = disjunct;
#endif
    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

/* {{{ proto array BooleanSearchQuery::jsonSerialize()
 */
PHP_METHOD(BooleanSearchQuery, jsonSerialize)
{
    pcbc_boolean_search_query_t *obj;
    int rv;

    rv = zend_parse_parameters_none();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    obj = Z_BOOLEAN_SEARCH_QUERY_OBJ_P(getThis());
    array_init(return_value);
    if (!Z_ISUNDEF(obj->must)) {
        ADD_ASSOC_ZVAL_EX(return_value, "must", PCBC_P(obj->must));
        PCBC_ADDREF_P(PCBC_P(obj->must));
    }
    if (!Z_ISUNDEF(obj->must_not)) {
        ADD_ASSOC_ZVAL_EX(return_value, "must_not", PCBC_P(obj->must_not));
        PCBC_ADDREF_P(PCBC_P(obj->must_not));
    }
    if (!Z_ISUNDEF(obj->should)) {
        ADD_ASSOC_ZVAL_EX(return_value, "should", PCBC_P(obj->should));
        PCBC_ADDREF_P(PCBC_P(obj->should));
    }
    if (obj->boost >= 0) {
        ADD_ASSOC_DOUBLE_EX(return_value, "boost", obj->boost);
    }
} /* }}} */

ZEND_BEGIN_ARG_INFO_EX(ai_BooleanSearchQuery_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_BooleanSearchQuery_boost, 0, 0, 1)
ZEND_ARG_INFO(0, boost)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_BooleanSearchQuery_query, 0, 0, 1)
ZEND_ARG_INFO(0, query)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry boolean_search_query_methods[] = {
    PHP_ME(BooleanSearchQuery, __construct, ai_BooleanSearchQuery_none, ZEND_ACC_PRIVATE | ZEND_ACC_FINAL | ZEND_ACC_CTOR)
    PHP_ME(BooleanSearchQuery, jsonSerialize, ai_BooleanSearchQuery_none, ZEND_ACC_PUBLIC)
    PHP_ME(BooleanSearchQuery, boost, ai_BooleanSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(BooleanSearchQuery, must, ai_BooleanSearchQuery_query, ZEND_ACC_PUBLIC)
    PHP_ME(BooleanSearchQuery, mustNot, ai_BooleanSearchQuery_query, ZEND_ACC_PUBLIC)
    PHP_ME(BooleanSearchQuery, should, ai_BooleanSearchQuery_query, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

void pcbc_boolean_search_query_init(zval *return_value TSRMLS_DC)
{
    pcbc_boolean_search_query_t *obj;

    object_init_ex(return_value, pcbc_boolean_search_query_ce);
    obj = Z_BOOLEAN_SEARCH_QUERY_OBJ_P(return_value);
    obj->boost = -1;
    ZVAL_UNDEF(PCBC_P(obj->must));
    ZVAL_UNDEF(PCBC_P(obj->must_not));
    ZVAL_UNDEF(PCBC_P(obj->should));
}

zend_object_handlers boolean_search_query_handlers;

static void boolean_search_query_free_object(pcbc_free_object_arg *object TSRMLS_DC) /* {{{ */
{
    pcbc_boolean_search_query_t *obj = Z_BOOLEAN_SEARCH_QUERY_OBJ(object);

    if (!Z_ISUNDEF(obj->must)) {
        zval_ptr_dtor(&obj->must);
    }
    if (!Z_ISUNDEF(obj->must_not)) {
        zval_ptr_dtor(&obj->must_not);
    }
    if (!Z_ISUNDEF(obj->should)) {
        zval_ptr_dtor(&obj->should);
    }

    zend_object_std_dtor(&obj->std TSRMLS_CC);
#if PHP_VERSION_ID < 70000
    efree(obj);
#endif
} /* }}} */

static pcbc_create_object_retval boolean_search_query_create_object(zend_class_entry *class_type TSRMLS_DC)
{
    pcbc_boolean_search_query_t *obj = NULL;

    obj = PCBC_ALLOC_OBJECT_T(pcbc_boolean_search_query_t, class_type);

    zend_object_std_init(&obj->std, class_type TSRMLS_CC);
    object_properties_init(&obj->std, class_type);

#if PHP_VERSION_ID >= 70000
    obj->std.handlers = &boolean_search_query_handlers;
    return &obj->std;
#else
    {
        zend_object_value ret;
        ret.handle = zend_objects_store_put(obj, (zend_objects_store_dtor_t)zend_objects_destroy_object,
                                            boolean_search_query_free_object, NULL TSRMLS_CC);
        ret.handlers = &boolean_search_query_handlers;
        return ret;
    }
#endif
}

static HashTable *pcbc_boolean_search_query_get_debug_info(zval *object, int *is_temp TSRMLS_DC) /* {{{ */
{
    pcbc_boolean_search_query_t *obj = NULL;
#if PHP_VERSION_ID >= 70000
    zval retval;
#else
    zval retval = zval_used_for_init;
#endif

    *is_temp = 1;
    obj = Z_BOOLEAN_SEARCH_QUERY_OBJ_P(object);

    array_init(&retval);
    if (!Z_ISUNDEF(obj->must)) {
        ADD_ASSOC_ZVAL_EX(&retval, "must", PCBC_P(obj->must));
        PCBC_ADDREF_P(PCBC_P(obj->must));
    }
    if (!Z_ISUNDEF(obj->must_not)) {
        ADD_ASSOC_ZVAL_EX(&retval, "mustNot", PCBC_P(obj->must_not));
        PCBC_ADDREF_P(PCBC_P(obj->must_not));
    }
    if (!Z_ISUNDEF(obj->should)) {
        ADD_ASSOC_ZVAL_EX(&retval, "should", PCBC_P(obj->should));
        PCBC_ADDREF_P(PCBC_P(obj->should));
    }
    if (obj->boost >= 0) {
        ADD_ASSOC_DOUBLE_EX(&retval, "boost", obj->boost);
    }
    return Z_ARRVAL(retval);
} /* }}} */

PHP_MINIT_FUNCTION(BooleanSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "BooleanSearchQuery", boolean_search_query_methods);
    pcbc_boolean_search_query_ce = zend_register_internal_class(&ce TSRMLS_CC);
    pcbc_boolean_search_query_ce->create_object = boolean_search_query_create_object;
    PCBC_CE_DISABLE_SERIALIZATION(pcbc_boolean_search_query_ce);

    zend_class_implements(pcbc_boolean_search_query_ce TSRMLS_CC, 1, pcbc_json_serializable_ce);
    zend_class_implements(pcbc_boolean_search_query_ce TSRMLS_CC, 1, pcbc_search_query_part_ce);

    memcpy(&boolean_search_query_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    boolean_search_query_handlers.get_debug_info = pcbc_boolean_search_query_get_debug_info;
#if PHP_VERSION_ID >= 70000
    boolean_search_query_handlers.free_obj = boolean_search_query_free_object;
    boolean_search_query_handlers.offset = XtOffsetOf(pcbc_boolean_search_query_t, std);
#endif

    zend_register_class_alias("\\CouchbaseBooleanSearchQuery", pcbc_boolean_search_query_ce);
    return SUCCESS;
}
