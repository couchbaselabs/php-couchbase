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
 * A facet that categorizes hits into numerical ranges (or buckets) provided by the user.
 */
#include "couchbase.h"

zend_class_entry *pcbc_numeric_range_search_facet_ce;

PHP_METHOD(NumericRangeSearchFacet, __construct)
{
    zend_string *field;
    zend_long limit;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "Sl", &field, &limit);
    if (rv == FAILURE) {
        return;
    }

    zval ranges;
    array_init(&ranges);
    zend_update_property(pcbc_numeric_range_search_facet_ce, getThis(), ZEND_STRL("ranges"), &ranges TSRMLS_CC);
    Z_DELREF(ranges);
    zend_update_property_str(pcbc_numeric_range_search_facet_ce, getThis(), ZEND_STRL("field"), field TSRMLS_CC);
    zend_update_property_long(pcbc_numeric_range_search_facet_ce, getThis(), ZEND_STRL("limit"), limit TSRMLS_CC);
}

PHP_METHOD(NumericRangeSearchFacet, addRange)
{
    zend_string *name = NULL;
    int rv;
    double min = 0, max = 0;
    zend_bool min_null = 0, max_null = 0;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "Sd!d!", &name, &min, &min_null, &max, &max_null);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zval *ranges, ret;
    ranges = zend_read_property(pcbc_numeric_range_search_facet_ce, getThis(), ZEND_STRL("ranges"), 0, &ret);

    zval range;
    array_init(&range);
    add_assoc_str(&range, "name", name);
    if (!min_null) {
        add_assoc_double(&range, "min", min);
    }
    if (!max_null) {
        add_assoc_double(&range, "max", max);
    }
    add_next_index_zval(ranges, &range);
    Z_TRY_ADDREF(range);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(NumericRangeSearchFacet, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    zval *prop, ret;

    prop = zend_read_property(pcbc_numeric_range_search_facet_ce, getThis(), ZEND_STRL("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_numeric_range_search_facet_ce, getThis(), ZEND_STRL("limit"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "size", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_numeric_range_search_facet_ce, getThis(), ZEND_STRL("ranges"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "numeric_ranges", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_NumericRangeSearchFacet_jsonSerialize, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_NumericRangeSearchFacet_construct, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, field, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, limit, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_NumericRangeSearchFacet_addRange, 0, 3, Couchbase\\NumericRangeSearchFacet,
                                       0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, min, IS_DOUBLE, 1)
ZEND_ARG_TYPE_INFO(0, max, IS_DOUBLE, 1)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry numeric_search_facet_methods[] = {
    PHP_ME(NumericRangeSearchFacet, __construct, ai_NumericRangeSearchFacet_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(NumericRangeSearchFacet, jsonSerialize, ai_NumericRangeSearchFacet_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_ME(NumericRangeSearchFacet, addRange, ai_NumericRangeSearchFacet_addRange, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(NumericRangeSearchFacet)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "NumericRangeSearchFacet", numeric_search_facet_methods);
    pcbc_numeric_range_search_facet_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_class_implements(pcbc_numeric_range_search_facet_ce TSRMLS_CC, 2, pcbc_json_serializable_ce,
                          pcbc_search_facet_ce);

    zend_declare_property_null(pcbc_numeric_range_search_facet_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_numeric_range_search_facet_ce, ZEND_STRL("limit"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_numeric_range_search_facet_ce, ZEND_STRL("ranges"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}
