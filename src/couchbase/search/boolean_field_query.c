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
 * A FTS query that queries fields explicitly indexed as boolean.
 */
#include "couchbase.h"

zend_class_entry *pcbc_boolean_field_search_query_ce;

PHP_METHOD(BooleanFieldSearchQuery, __construct)
{
    int rv;
    zend_bool value;
    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &value);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_bool(pcbc_boolean_field_search_query_ce, getThis(), ZEND_STRL("value"), value TSRMLS_CC);
}

PHP_METHOD(BooleanFieldSearchQuery, field)
{
    zend_string *field = NULL;
    int rv;
    size_t field_len;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &field, &field_len);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_boolean_field_search_query_ce, getThis(), ZEND_STRL("field"), field TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BooleanFieldSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_double(pcbc_boolean_field_search_query_ce, getThis(), ZEND_STRL("boost"), boost TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(BooleanFieldSearchQuery, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);

    zval *prop, ret;

    prop = zend_read_property(pcbc_boolean_field_search_query_ce, getThis(), ZEND_STRL("value"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "bool", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_boolean_field_search_query_ce, getThis(), ZEND_STRL("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_boolean_field_search_query_ce, getThis(), ZEND_STRL("boost"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "boost", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_BooleanFieldSearchQuery_jsonSerialize, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_BooleanFieldSearchQuery_construct, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, arg, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BooleanFieldSearchQuery_boost, 0, 1, Couchbase\\BooleanFieldSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_BooleanFieldSearchQuery_field, 0, 1, Couchbase\\BooleanFieldSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry boolean_field_search_query_methods[] = {
    PHP_ME(BooleanFieldSearchQuery, __construct, ai_BooleanFieldSearchQuery_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(BooleanFieldSearchQuery, jsonSerialize, ai_BooleanFieldSearchQuery_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_ME(BooleanFieldSearchQuery, boost, ai_BooleanFieldSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(BooleanFieldSearchQuery, field, ai_BooleanFieldSearchQuery_field, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(BooleanFieldSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "BooleanFieldSearchQuery", boolean_field_search_query_methods);
    pcbc_boolean_field_search_query_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_class_implements(pcbc_boolean_field_search_query_ce TSRMLS_CC, 2, pcbc_json_serializable_ce,
                          pcbc_search_query_ce);

    zend_declare_property_null(pcbc_boolean_field_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_boolean_field_search_query_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_boolean_field_search_query_ce, ZEND_STRL("value"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}
