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
extern zend_class_entry *pcbc_conjunction_search_query_ce;
extern zend_class_entry *pcbc_disjunction_search_query_ce;

PHP_METHOD(BooleanSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_double(pcbc_boolean_search_query_ce, getThis(), ("boost"), boost);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BooleanSearchQuery, must)
{
    zval *conjunct = NULL;

    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "O", &conjunct, pcbc_conjunction_search_query_ce) ==
        FAILURE) {
        return;
    }

    pcbc_update_property(pcbc_boolean_search_query_ce, getThis(), ("must"), conjunct);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BooleanSearchQuery, mustNot)
{
    zval *disjunct = NULL;

    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "O", &disjunct, pcbc_disjunction_search_query_ce) ==
        FAILURE) {
        return;
    }

    pcbc_update_property(pcbc_boolean_search_query_ce, getThis(), ("mustNot"), disjunct);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BooleanSearchQuery, should)
{
    zval *disjunct = NULL;

    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "O", &disjunct, pcbc_disjunction_search_query_ce) ==
        FAILURE) {
        return;
    }

    pcbc_update_property(pcbc_boolean_search_query_ce, getThis(), ("should"), disjunct);

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

    prop = pcbc_read_property(pcbc_boolean_search_query_ce, getThis(), ("must"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "must", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_boolean_search_query_ce, getThis(), ("must_not"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "must_not", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_boolean_search_query_ce, getThis(), ("should"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "should", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_boolean_search_query_ce, getThis(), ("boost"), 0, &ret);
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

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BooleanSearchQuery_must, 0, 1, Couchbase\\BooleanSearchQuery, 0)
ZEND_ARG_OBJ_INFO(0, query, Couchbase\\ConjunctionSearchQuery, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BooleanSearchQuery_mustNot, 0, 1, Couchbase\\BooleanSearchQuery, 0)
ZEND_ARG_OBJ_INFO(0, query, Couchbase\\DisjunctionSearchQuery, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BooleanSearchQuery_should, 0, 1, Couchbase\\BooleanSearchQuery, 0)
ZEND_ARG_OBJ_INFO(0, query, Couchbase\\DisjunctionSearchQuery, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry boolean_search_query_methods[] = {
    PHP_ME(BooleanSearchQuery, jsonSerialize, ai_BooleanSearchQuery_none, ZEND_ACC_PUBLIC)
    PHP_ME(BooleanSearchQuery, boost, ai_BooleanSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(BooleanSearchQuery, must, ai_BooleanSearchQuery_must, ZEND_ACC_PUBLIC)
    PHP_ME(BooleanSearchQuery, mustNot, ai_BooleanSearchQuery_mustNot, ZEND_ACC_PUBLIC)
    PHP_ME(BooleanSearchQuery, should, ai_BooleanSearchQuery_should, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(BooleanSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "BooleanSearchQuery", boolean_search_query_methods);
    pcbc_boolean_search_query_ce = zend_register_internal_class(&ce);

    zend_class_implements(pcbc_boolean_search_query_ce, 2, pcbc_json_serializable_ce, pcbc_search_query_ce);

    zend_declare_property_null(pcbc_boolean_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_boolean_search_query_ce, ZEND_STRL("must"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_boolean_search_query_ce, ZEND_STRL("must_not"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_boolean_search_query_ce, ZEND_STRL("should"), ZEND_ACC_PRIVATE);

    return SUCCESS;
}
