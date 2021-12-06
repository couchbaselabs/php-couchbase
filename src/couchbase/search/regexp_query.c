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
 * A FTS query that allows for simple matching of regular expressions.
 */
#include "couchbase.h"

zend_class_entry *pcbc_regexp_search_query_ce;

PHP_METHOD(RegexpSearchQuery, __construct)
{
    zend_string *regexp = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &regexp);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_regexp_search_query_ce, getThis(), ("value"), regexp);
}

PHP_METHOD(RegexpSearchQuery, field)
{
    zend_string *field = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S", &field);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_str(pcbc_regexp_search_query_ce, getThis(), ("field"), field);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(RegexpSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_regexp_search_query_ce, getThis(), ("boost"), boost);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(RegexpSearchQuery, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    zval *prop, ret;
    prop = pcbc_read_property(pcbc_regexp_search_query_ce, getThis(), ("value"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "regexp", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_regexp_search_query_ce, getThis(), ("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_regexp_search_query_ce, getThis(), ("boost"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "boost", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

#if PHP_VERSION_ID < 80100
ZEND_BEGIN_ARG_INFO_EX(ai_RegexpSearchQuery_jsonSerialize, 0, 0, 0)
#else
ZEND_BEGIN_ARG_WITH_TENTATIVE_RETURN_TYPE_INFO_EX(ai_RegexpSearchQuery_jsonSerialize, 0, 0, IS_MIXED, 0)
#endif
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_RegexpSearchQuery_construct, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, regexp, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_RegexpSearchQuery_field, 0, 1, Couchbase\\RegexpSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, field, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_RegexpSearchQuery_boost, 0, 1, Couchbase\\RegexpSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, boost, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry regexp_search_query_methods[] = {
    PHP_ME(RegexpSearchQuery, __construct, ai_RegexpSearchQuery_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(RegexpSearchQuery, jsonSerialize, ai_RegexpSearchQuery_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_ME(RegexpSearchQuery, boost, ai_RegexpSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(RegexpSearchQuery, field, ai_RegexpSearchQuery_field, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(RegexpSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "RegexpSearchQuery", regexp_search_query_methods);
    pcbc_regexp_search_query_ce = zend_register_internal_class(&ce);

    zend_class_implements(pcbc_regexp_search_query_ce, 2, pcbc_json_serializable_ce, pcbc_search_query_ce);

    zend_declare_property_null(pcbc_regexp_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_regexp_search_query_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_regexp_search_query_ce, ZEND_STRL("value"), ZEND_ACC_PRIVATE);
    return SUCCESS;
}
