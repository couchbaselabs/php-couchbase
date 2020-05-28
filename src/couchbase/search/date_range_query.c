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
#include <ext/date/php_date.h>

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/date_range_search_query", __FILE__, __LINE__

zend_class_entry *pcbc_date_range_search_query_ce;

PHP_METHOD(DateRangeSearchQuery, field)
{
    zend_string *field = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &field);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_str(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("field"), field TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(DateRangeSearchQuery, dateTimeParser)
{
    zend_string *date_time_parser = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &date_time_parser);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("date_time_parser"),
                             date_time_parser TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(DateRangeSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_double(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("boost"), boost TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

/*
 * The strings will be taken verbatim and supposed to be formatted with custom date time formatter (see
 * dateTimeParser). Integers interpreted as unix timestamps and represented as RFC3339 strings.
 */
PHP_METHOD(DateRangeSearchQuery, start)
{
    zval *start = NULL;
    zend_bool inclusive = 1, inclusive_null = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "z|b!", &start, &inclusive, &inclusive_null);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    switch (Z_TYPE_P(start)) {
    case IS_STRING:
        zend_update_property(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("start"), start TSRMLS_CC);
        break;
    case IS_LONG: {
        zend_string *date_str = NULL;
        date_str = php_format_date(ZEND_STRL(PCBC_DATE_FORMAT_RFC3339), Z_LVAL_P(start), 1 TSRMLS_CC);
        zend_update_property_str(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("start"), date_str TSRMLS_CC);
    } break;
    default:
        zend_type_error("Start date must be either formatted string or integer (Unix timestamp)");
        RETURN_NULL();
    }
    if (!inclusive_null) {
        zend_update_property_bool(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("inclusive_start"),
                                  inclusive TSRMLS_CC);
    }

    RETURN_ZVAL(getThis(), 1, 0);
}

/*
 * The strings will be taken verbatim and supposed to be formatted with custom date time formatter (see
 * dateTimeParser). Integers interpreted as unix timestamps and represented as RFC3339 strings.
 */
PHP_METHOD(DateRangeSearchQuery, end)
{
    zval *end = NULL;
    zend_bool inclusive = 1, inclusive_null = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "z|b!", &end, &inclusive, &inclusive_null);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    switch (Z_TYPE_P(end)) {
    case IS_STRING:
        zend_update_property(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("end"), end TSRMLS_CC);
        break;
    case IS_LONG: {
        zend_string *date_str = NULL;
        date_str = php_format_date(ZEND_STRL(PCBC_DATE_FORMAT_RFC3339), Z_LVAL_P(end), 1 TSRMLS_CC);
        zend_update_property_str(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("end"), date_str TSRMLS_CC);
    } break;
    default:
        zend_type_error("End date must be either formatted string or integer (Unix timestamp)");
        RETURN_NULL();
    }
    if (!inclusive_null) {
        zend_update_property_bool(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("inclusive_end"),
                                  inclusive TSRMLS_CC);
    }

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(DateRangeSearchQuery, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    zval *prop, ret;

    prop = zend_read_property(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("start"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "start", prop);
        Z_TRY_ADDREF_P(prop);
        prop = zend_read_property(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("inclusive_start"), 0, &ret);
        if (Z_TYPE_P(prop) != IS_NULL) {
            add_assoc_zval(return_value, "inclusive_start", prop);
            Z_TRY_ADDREF_P(prop);
        }
    }

    prop = zend_read_property(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("end"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "end", prop);
        Z_TRY_ADDREF_P(prop);
        prop = zend_read_property(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("inclusive_end"), 0, &ret);
        if (Z_TYPE_P(prop) != IS_NULL) {
            add_assoc_zval(return_value, "inclusive_end", prop);
            Z_TRY_ADDREF_P(prop);
        }
    }

    prop = zend_read_property(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("date_time_parser"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "datetime_parser", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_date_range_search_query_ce, getThis(), ZEND_STRL("boost"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "boost", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_DateRangeSearchQuery_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DateRangeSearchQuery_field, 0, 1, Couchbase\\DateRangeSearchQuery, 0)
ZEND_ARG_INFO(0, field)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DateRangeSearchQuery_boost, 0, 1, Couchbase\\DateRangeSearchQuery, 0)
ZEND_ARG_INFO(0, boost)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DateRangeSearchQuery_start, 0, 1, Couchbase\\DateRangeSearchQuery, 0)
ZEND_ARG_INFO(0, start)
ZEND_ARG_TYPE_INFO(0, inclusive, _IS_BOOL, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DateRangeSearchQuery_end, 0, 1, Couchbase\\DateRangeSearchQuery, 0)
ZEND_ARG_INFO(0, end)
ZEND_ARG_TYPE_INFO(0, inclusive, _IS_BOOL, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DateRangeSearchQuery_dateTimeParser, 0, 1, Couchbase\\DateRangeSearchQuery,
                                       0)
ZEND_ARG_TYPE_INFO(0, dateTimeParser, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry date_range_search_query_methods[] = {
    PHP_ME(DateRangeSearchQuery, jsonSerialize, ai_DateRangeSearchQuery_none, ZEND_ACC_PUBLIC)
    PHP_ME(DateRangeSearchQuery, boost, ai_DateRangeSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(DateRangeSearchQuery, field, ai_DateRangeSearchQuery_field, ZEND_ACC_PUBLIC)
    PHP_ME(DateRangeSearchQuery, start, ai_DateRangeSearchQuery_start, ZEND_ACC_PUBLIC)
    PHP_ME(DateRangeSearchQuery, end, ai_DateRangeSearchQuery_end, ZEND_ACC_PUBLIC)
    PHP_ME(DateRangeSearchQuery, dateTimeParser, ai_DateRangeSearchQuery_dateTimeParser, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(DateRangeSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DateRangeSearchQuery", date_range_search_query_methods);
    pcbc_date_range_search_query_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_class_implements(pcbc_date_range_search_query_ce TSRMLS_CC, 2, pcbc_json_serializable_ce,
                          pcbc_search_query_ce);

    zend_declare_property_null(pcbc_date_range_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_date_range_search_query_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_date_range_search_query_ce, ZEND_STRL("start"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_date_range_search_query_ce, ZEND_STRL("inclusive_start"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_date_range_search_query_ce, ZEND_STRL("end"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_date_range_search_query_ce, ZEND_STRL("inclusive_end"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_date_range_search_query_ce, ZEND_STRL("date_time_parser"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}
