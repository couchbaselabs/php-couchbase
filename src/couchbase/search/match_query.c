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
 * A FTS query that matches a given term, applying further processing to it
 * like analyzers, stemming and even #fuzziness(int).
 */
#include "couchbase.h"

zend_class_entry *pcbc_match_search_query_ce;

PHP_METHOD(MatchSearchQuery, __construct)
{
    zend_string *value = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &value);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_match_search_query_ce, getThis(), ZEND_STRL("value"), value TSRMLS_CC);
}

PHP_METHOD(MatchSearchQuery, analyzer)
{
    zend_string *analyzer = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &analyzer);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_match_search_query_ce, getThis(), ZEND_STRL("analyzer"), analyzer TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(MatchSearchQuery, field)
{
    zend_string *field = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &field);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_match_search_query_ce, getThis(), ZEND_STRL("field"), field TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(MatchSearchQuery, prefixLength)
{
    zend_long prefix_length = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "l", &prefix_length);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_long(pcbc_match_search_query_ce, getThis(), ZEND_STRL("prefix_length"),
                              prefix_length TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(MatchSearchQuery, fuzziness)
{
    zend_long fuzziness = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "l", &fuzziness);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_long(pcbc_match_search_query_ce, getThis(), ZEND_STRL("fuzziness"), fuzziness TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(MatchSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_long(pcbc_match_search_query_ce, getThis(), ZEND_STRL("boost"), boost TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(MatchSearchQuery, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    zval *prop, ret;
    prop = zend_read_property(pcbc_match_search_query_ce, getThis(), ZEND_STRL("value"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "match", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_match_search_query_ce, getThis(), ZEND_STRL("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_match_search_query_ce, getThis(), ZEND_STRL("analyzer"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "analyzer", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_match_search_query_ce, getThis(), ZEND_STRL("prefix_length"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "prefix_length", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_match_search_query_ce, getThis(), ZEND_STRL("fuzziness"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "fuzziness", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_match_search_query_ce, getThis(), ZEND_STRL("boost"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "boost", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_MatchSearchQuery_jsonSerialize, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_MatchSearchQuery_construct, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, value, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_MatchSearchQuery_field, 0, 1, Couchbase\\MatchSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, field, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_MatchSearchQuery_analyzer, 0, 1, Couchbase\\MatchSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, analyzer, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_MatchSearchQuery_prefixLength, 0, 1, Couchbase\\MatchSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, prefix_length, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_MatchSearchQuery_fuzziness, 0, 1, Couchbase\\MatchSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, fuzziness, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_MatchSearchQuery_boost, 0, 1, Couchbase\\MatchSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, boost, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry match_search_query_methods[] = {
    PHP_ME(MatchSearchQuery, __construct, ai_MatchSearchQuery_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(MatchSearchQuery, jsonSerialize, ai_MatchSearchQuery_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_ME(MatchSearchQuery, boost, ai_MatchSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(MatchSearchQuery, field, ai_MatchSearchQuery_field, ZEND_ACC_PUBLIC)
    PHP_ME(MatchSearchQuery, analyzer, ai_MatchSearchQuery_analyzer, ZEND_ACC_PUBLIC)
    PHP_ME(MatchSearchQuery, prefixLength, ai_MatchSearchQuery_prefixLength, ZEND_ACC_PUBLIC)
    PHP_ME(MatchSearchQuery, fuzziness, ai_MatchSearchQuery_fuzziness, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(MatchSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MatchSearchQuery", match_search_query_methods);
    pcbc_match_search_query_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_class_implements(pcbc_match_search_query_ce TSRMLS_CC, 2, pcbc_json_serializable_ce, pcbc_search_query_ce);
    zend_declare_property_null(pcbc_match_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_match_search_query_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_match_search_query_ce, ZEND_STRL("value"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_match_search_query_ce, ZEND_STRL("analyzer"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_match_search_query_ce, ZEND_STRL("prefix_length"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_match_search_query_ce, ZEND_STRL("fuzziness"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}
