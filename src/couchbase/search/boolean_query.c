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

/**
 * A compound FTS query that allows various combinations of sub-queries.
 */
#include "couchbase.h"

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/boolean_query", __FILE__, __LINE__

zend_class_entry *pcbc_boolean_search_query_ce;

PHP_METHOD(BooleanSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_double(pcbc_boolean_search_query_ce, getThis(), ZEND_STRL("boost"), boost TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BooleanSearchQuery, must)
{
    zval *args = NULL;
    int num_args = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "+", &args, &num_args);
    if (rv == FAILURE) {
        return;
    }

    if (num_args && args) {
        zval *container, rv1;
        container = zend_read_property(pcbc_boolean_search_query_ce, getThis(), ZEND_STRL("must"), 0, &rv1);
        if (Z_TYPE_P(container) == IS_NULL) {
            array_init(&rv1);
            container = &rv1;
            zend_update_property(pcbc_boolean_search_query_ce, getThis(), ZEND_STRL("must"), container TSRMLS_CC);
            Z_DELREF_P(container);
        }
        int i;
        for (i = 0; i < num_args; ++i) {
            zval *query;
            query = &args[i];
            if (Z_TYPE_P(query) != IS_OBJECT ||
                !instanceof_function(Z_OBJCE_P(query), pcbc_search_query_ce TSRMLS_CC)) {
                pcbc_log(LOGARGS(WARN), "query has to implement SearchQuery interface (skipping argument #%d)", i);
                continue;
            }
            add_next_index_zval(container, query);
            PCBC_ADDREF_P(query);
        }
    }

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BooleanSearchQuery, mustNot)
{
    zval *args = NULL;
    int num_args = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "+", &args, &num_args);
    if (rv == FAILURE) {
        return;
    }

    if (num_args && args) {
        zval *container, rv1;
        container = zend_read_property(pcbc_boolean_search_query_ce, getThis(), ZEND_STRL("must_not"), 0, &rv1);
        if (Z_TYPE_P(container) == IS_NULL) {
            array_init(&rv1);
            container = &rv1;
            zend_update_property(pcbc_boolean_search_query_ce, getThis(), ZEND_STRL("must_not"), container TSRMLS_CC);
            Z_DELREF_P(container);
        }
        int i;
        for (i = 0; i < num_args; ++i) {
            zval *query;
            query = &args[i];
            if (Z_TYPE_P(query) != IS_OBJECT ||
                !instanceof_function(Z_OBJCE_P(query), pcbc_search_query_ce TSRMLS_CC)) {
                pcbc_log(LOGARGS(WARN), "query has to implement SearchQuery interface (skipping argument #%d)", i);
                continue;
            }
            add_next_index_zval(container, query);
            PCBC_ADDREF_P(query);
        }
    }

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BooleanSearchQuery, should)
{
    zval *args = NULL;
    int num_args = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "+", &args, &num_args);
    if (rv == FAILURE) {
        return;
    }

    if (num_args && args) {
        zval *container, rv1;
        container = zend_read_property(pcbc_boolean_search_query_ce, getThis(), ZEND_STRL("should"), 0, &rv1);
        if (Z_TYPE_P(container) == IS_NULL) {
            array_init(&rv1);
            container = &rv1;
            zend_update_property(pcbc_boolean_search_query_ce, getThis(), ZEND_STRL("should"), container TSRMLS_CC);
            Z_DELREF_P(container);
        }
        int i;
        for (i = 0; i < num_args; ++i) {
            zval *query;
            query = &args[i];
            if (Z_TYPE_P(query) != IS_OBJECT ||
                !instanceof_function(Z_OBJCE_P(query), pcbc_search_query_ce TSRMLS_CC)) {
                pcbc_log(LOGARGS(WARN), "query has to implement SearchQuery interface (skipping argument #%d)", i);
                continue;
            }
            add_next_index_zval(container, query);
            PCBC_ADDREF_P(query);
        }
    }

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BooleanSearchQuery, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    zval *prop, ret;

    prop = zend_read_property(pcbc_boolean_search_query_ce, getThis(), ZEND_STRL("must"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "must", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_boolean_search_query_ce, getThis(), ZEND_STRL("must_not"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "must_not", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_boolean_search_query_ce, getThis(), ZEND_STRL("should"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "should", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_boolean_search_query_ce, getThis(), ZEND_STRL("boost"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "boost", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_BooleanSearchQuery_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BooleanSearchQuery_boost, 0, 1, Couchbase\\BooleanSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, boost, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BooleanSearchQuery_queries, 0, 1, Couchbase\\BooleanSearchQuery, 0)
PCBC_ARG_VARIADIC_INFO(0, queries)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry boolean_search_query_methods[] = {
    PHP_ME(BooleanSearchQuery, jsonSerialize, ai_BooleanSearchQuery_none, ZEND_ACC_PUBLIC)
    PHP_ME(BooleanSearchQuery, boost, ai_BooleanSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(BooleanSearchQuery, must, ai_BooleanSearchQuery_queries, ZEND_ACC_PUBLIC)
    PHP_ME(BooleanSearchQuery, mustNot, ai_BooleanSearchQuery_queries, ZEND_ACC_PUBLIC)
    PHP_ME(BooleanSearchQuery, should, ai_BooleanSearchQuery_queries, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(BooleanSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "BooleanSearchQuery", boolean_search_query_methods);
    pcbc_boolean_search_query_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_class_implements(pcbc_boolean_search_query_ce TSRMLS_CC, 2, pcbc_json_serializable_ce, pcbc_search_query_ce);

    zend_declare_property_null(pcbc_boolean_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_boolean_search_query_ce, ZEND_STRL("must"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_boolean_search_query_ce, ZEND_STRL("must_not"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_boolean_search_query_ce, ZEND_STRL("should"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}
