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
 * A FTS query that matches documents on a range of values. At least one bound is required, and the
 * inclusiveness of each bound can be configured.
 */
#include "couchbase.h"

zend_class_entry *pcbc_term_range_search_query_ce;

PHP_METHOD(TermRangeSearchQuery, field)
{
    zend_string *field = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &field);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_str(pcbc_term_range_search_query_ce, getThis(), ("field"), field);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(TermRangeSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_double(pcbc_term_range_search_query_ce, getThis(), ("boost"), boost);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(TermRangeSearchQuery, min)
{
    zend_string *min = NULL;
    zend_bool inclusive = 1, inclusive_null = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S|b!", &min, &inclusive, &inclusive_null);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_term_range_search_query_ce, getThis(), ("min"), min);
    if (!inclusive_null) {
        pcbc_update_property_bool(pcbc_term_range_search_query_ce, getThis(), ("inclusive_min"), inclusive);
    }

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(TermRangeSearchQuery, max)
{
    zend_string *max = NULL;
    zend_bool inclusive = 1, inclusive_null = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S|b!", &max, &inclusive, &inclusive_null);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_term_range_search_query_ce, getThis(), ("max"), max);
    if (!inclusive_null) {
        pcbc_update_property_bool(pcbc_term_range_search_query_ce, getThis(), ("inclusive_max"), inclusive);
    }

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(TermRangeSearchQuery, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    zval *prop, ret;

    prop = pcbc_read_property(pcbc_term_range_search_query_ce, getThis(), ("min"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "min", prop);
        Z_TRY_ADDREF_P(prop);
        prop = pcbc_read_property(pcbc_term_range_search_query_ce, getThis(), ("inclusive_min"), 0, &ret);
        if (Z_TYPE_P(prop) != IS_NULL) {
            add_assoc_zval(return_value, "inclusive_min", prop);
            Z_TRY_ADDREF_P(prop);
        }
    }

    prop = pcbc_read_property(pcbc_term_range_search_query_ce, getThis(), ("max"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "max", prop);
        Z_TRY_ADDREF_P(prop);
        prop = pcbc_read_property(pcbc_term_range_search_query_ce, getThis(), ("inclusive_max"), 0, &ret);
        if (Z_TYPE_P(prop) != IS_NULL) {
            add_assoc_zval(return_value, "inclusive_max", prop);
            Z_TRY_ADDREF_P(prop);
        }
    }

    prop = pcbc_read_property(pcbc_term_range_search_query_ce, getThis(), ("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_term_range_search_query_ce, getThis(), ("boost"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "boost", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

#if PHP_VERSION_ID < 80100
ZEND_BEGIN_ARG_INFO_EX(ai_TermRangeSearchQuery_none, 0, 0, 0)
#else
ZEND_BEGIN_ARG_WITH_TENTATIVE_RETURN_TYPE_INFO_EX(ai_TermRangeSearchQuery_none, 0, 0, IS_MIXED, 0)
#endif
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_TermRangeSearchQuery_field, 0, 1, Couchbase\\TermRangeSearchQuery, 0)
ZEND_ARG_INFO(0, field)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_TermRangeSearchQuery_boost, 0, 1, Couchbase\\TermRangeSearchQuery, 0)
ZEND_ARG_INFO(0, boost)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_TermRangeSearchQuery_min, 0, 1, Couchbase\\TermRangeSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, min, IS_DOUBLE, 0)
ZEND_ARG_TYPE_INFO(0, inclusive, _IS_BOOL, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_TermRangeSearchQuery_max, 0, 1, Couchbase\\TermRangeSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, max, IS_DOUBLE, 0)
ZEND_ARG_TYPE_INFO(0, inclusive, _IS_BOOL, 1)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry term_range_search_query_methods[] = {
    PHP_ME(TermRangeSearchQuery, jsonSerialize, ai_TermRangeSearchQuery_none, ZEND_ACC_PUBLIC)
    PHP_ME(TermRangeSearchQuery, boost, ai_TermRangeSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(TermRangeSearchQuery, field, ai_TermRangeSearchQuery_field, ZEND_ACC_PUBLIC)
    PHP_ME(TermRangeSearchQuery, min, ai_TermRangeSearchQuery_min, ZEND_ACC_PUBLIC)
    PHP_ME(TermRangeSearchQuery, max, ai_TermRangeSearchQuery_max, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(TermRangeSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "TermRangeSearchQuery", term_range_search_query_methods);
    pcbc_term_range_search_query_ce = zend_register_internal_class(&ce);

    zend_class_implements(pcbc_term_range_search_query_ce, 2, pcbc_json_serializable_ce, pcbc_search_query_ce);

    zend_declare_property_null(pcbc_term_range_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_term_range_search_query_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_term_range_search_query_ce, ZEND_STRL("min"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_term_range_search_query_ce, ZEND_STRL("inclusive_min"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_term_range_search_query_ce, ZEND_STRL("max"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_term_range_search_query_ce, ZEND_STRL("inclusive_max"), ZEND_ACC_PRIVATE);
    return SUCCESS;
}
