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
 * A FTS query that allows for simple matching on a given prefix.
 */
#include "couchbase.h"

zend_class_entry *pcbc_prefix_search_query_ce;

PHP_METHOD(PrefixSearchQuery, __construct)
{
    zend_string *prefix = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &prefix);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_prefix_search_query_ce, getThis(), ZEND_STRL("value"), prefix TSRMLS_CC);
}

PHP_METHOD(PrefixSearchQuery, field)
{
    zend_string *field = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &field);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_prefix_search_query_ce, getThis(), ZEND_STRL("field"), field TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(PrefixSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_long(pcbc_prefix_search_query_ce, getThis(), ZEND_STRL("boost"), boost TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(PrefixSearchQuery, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    zval *prop, ret;
    prop = zend_read_property(pcbc_prefix_search_query_ce, getThis(), ZEND_STRL("value"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "prefix", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_prefix_search_query_ce, getThis(), ZEND_STRL("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_prefix_search_query_ce, getThis(), ZEND_STRL("boost"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "boost", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_PrefixSearchQuery_jsonSerialize, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_PrefixSearchQuery_construct, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, prefix, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_PrefixSearchQuery_field, 0, 1, Couchbase\\PrefixSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, field, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_PrefixSearchQuery_boost, 0, 1, Couchbase\\PrefixSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, boost, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry prefix_search_query_methods[] = {
    PHP_ME(PrefixSearchQuery, __construct, ai_PrefixSearchQuery_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(PrefixSearchQuery, jsonSerialize, ai_PrefixSearchQuery_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_ME(PrefixSearchQuery, boost, ai_PrefixSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(PrefixSearchQuery, field, ai_PrefixSearchQuery_field, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(PrefixSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "PrefixSearchQuery", prefix_search_query_methods);
    pcbc_prefix_search_query_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_class_implements(pcbc_prefix_search_query_ce TSRMLS_CC, 2, pcbc_json_serializable_ce, pcbc_search_query_ce);

    zend_declare_property_null(pcbc_prefix_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_prefix_search_query_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_prefix_search_query_ce, ZEND_STRL("value"), ZEND_ACC_PRIVATE TSRMLS_CC);
    return SUCCESS;
}
