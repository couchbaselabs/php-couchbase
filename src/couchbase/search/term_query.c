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
 * A FTS query that termes terms (without further analysis). Usually for debugging purposes, prefer using MatchQuery.
 */
#include "couchbase.h"

zend_class_entry *pcbc_term_search_query_ce;

PHP_METHOD(TermSearchQuery, __construct)
{
    zend_string *value = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &value);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_term_search_query_ce, getThis(), ZEND_STRL("term"), value TSRMLS_CC);
}

PHP_METHOD(TermSearchQuery, field)
{
    zend_string *field = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &field);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_term_search_query_ce, getThis(), ZEND_STRL("field"), field TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(TermSearchQuery, prefixLength)
{
    zend_long prefix_length = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "l", &prefix_length);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_long(pcbc_term_search_query_ce, getThis(), ZEND_STRL("prefix_length"),
                              prefix_length TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(TermSearchQuery, fuzziness)
{
    zend_long fuzziness = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "l", &fuzziness);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_long(pcbc_term_search_query_ce, getThis(), ZEND_STRL("fuzziness"), fuzziness TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(TermSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_long(pcbc_term_search_query_ce, getThis(), ZEND_STRL("boost"), boost TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(TermSearchQuery, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    zval *prop, ret;
    prop = zend_read_property(pcbc_term_search_query_ce, getThis(), ZEND_STRL("term"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "term", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_term_search_query_ce, getThis(), ZEND_STRL("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_term_search_query_ce, getThis(), ZEND_STRL("prefix_length"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "prefix_length", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_term_search_query_ce, getThis(), ZEND_STRL("fuzziness"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "fuzziness", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_term_search_query_ce, getThis(), ZEND_STRL("boost"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "boost", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_TermSearchQuery_jsonSerialize, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_TermSearchQuery_construct, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, term, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_TermSearchQuery_field, 0, 1, Couchbase\\TermSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, field, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_TermSearchQuery_prefixLength, 0, 1, Couchbase\\TermSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, prefix_length, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_TermSearchQuery_fuzziness, 0, 1, Couchbase\\TermSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, fuzziness, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_TermSearchQuery_boost, 0, 1, Couchbase\\TermSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, boost, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry term_search_query_methods[] = {
    PHP_ME(TermSearchQuery, __construct, ai_TermSearchQuery_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(TermSearchQuery, jsonSerialize, ai_TermSearchQuery_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_ME(TermSearchQuery, boost, ai_TermSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(TermSearchQuery, field, ai_TermSearchQuery_field, ZEND_ACC_PUBLIC)
    PHP_ME(TermSearchQuery, prefixLength, ai_TermSearchQuery_prefixLength, ZEND_ACC_PUBLIC)
    PHP_ME(TermSearchQuery, fuzziness, ai_TermSearchQuery_fuzziness, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(TermSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "TermSearchQuery", term_search_query_methods);
    pcbc_term_search_query_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_class_implements(pcbc_term_search_query_ce TSRMLS_CC, 2, pcbc_json_serializable_ce, pcbc_search_query_ce);

    zend_declare_property_null(pcbc_term_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_term_search_query_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_term_search_query_ce, ZEND_STRL("term"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_term_search_query_ce, ZEND_STRL("analyzer"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_term_search_query_ce, ZEND_STRL("prefix_length"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_term_search_query_ce, ZEND_STRL("fuzziness"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}
