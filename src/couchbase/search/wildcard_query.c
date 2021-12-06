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
 * A FTS query that allows for simple matching using wildcard characters (* and ?).
 */
#include "couchbase.h"

zend_class_entry *pcbc_wildcard_search_query_ce;

PHP_METHOD(WildcardSearchQuery, __construct)
{
    zend_string *wildcard = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &wildcard);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_wildcard_search_query_ce, getThis(), ("value"), wildcard);
}

PHP_METHOD(WildcardSearchQuery, field)
{
    zend_string *field = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &field);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_wildcard_search_query_ce, getThis(), ("field"), field);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(WildcardSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_wildcard_search_query_ce, getThis(), ("boost"), boost);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(WildcardSearchQuery, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    zval *prop, ret;
    prop = pcbc_read_property(pcbc_wildcard_search_query_ce, getThis(), ("value"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "wildcard", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_wildcard_search_query_ce, getThis(), ("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_wildcard_search_query_ce, getThis(), ("boost"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "boost", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

#if PHP_VERSION_ID < 80100
ZEND_BEGIN_ARG_INFO_EX(ai_WildcardSearchQuery_jsonSerialize, 0, 0, 0)
#else
ZEND_BEGIN_ARG_WITH_TENTATIVE_RETURN_TYPE_INFO_EX(ai_WildcardSearchQuery_jsonSerialize, 0, 0, IS_MIXED, 0)
#endif
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_WildcardSearchQuery_construct, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, wildcard, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_WildcardSearchQuery_field, 0, 1, Couchbase\\WildcardSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, field, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_WildcardSearchQuery_boost, 0, 1, Couchbase\\WildcardSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, boost, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry wildcard_search_query_methods[] = {
    PHP_ME(WildcardSearchQuery, __construct, ai_WildcardSearchQuery_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(WildcardSearchQuery, jsonSerialize, ai_WildcardSearchQuery_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_ME(WildcardSearchQuery, boost, ai_WildcardSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(WildcardSearchQuery, field, ai_WildcardSearchQuery_field, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(WildcardSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "WildcardSearchQuery", wildcard_search_query_methods);
    pcbc_wildcard_search_query_ce = zend_register_internal_class(&ce);

    zend_class_implements(pcbc_wildcard_search_query_ce, 2, pcbc_json_serializable_ce, pcbc_search_query_ce);

    zend_declare_property_null(pcbc_wildcard_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_wildcard_search_query_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_wildcard_search_query_ce, ZEND_STRL("value"), ZEND_ACC_PRIVATE);

    return SUCCESS;
}
