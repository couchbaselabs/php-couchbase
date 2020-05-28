/**
 *     Copyright 2018-2019 Couchbase, Inc.
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
 * Sort by a location and unit in the hits.
 */
#include "couchbase.h"

zend_class_entry *pcbc_search_sort_geo_distance_ce;

PHP_METHOD(SearchSortGeoDistance, __construct)
{
    zend_string *field = NULL;
    double lon, lat;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "Sdd", &field, &lon, &lat);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_search_sort_geo_distance_ce, getThis(), ZEND_STRL("field"), field TSRMLS_CC);
    zend_update_property_double(pcbc_search_sort_geo_distance_ce, getThis(), ZEND_STRL("longitude"), lon TSRMLS_CC);
    zend_update_property_double(pcbc_search_sort_geo_distance_ce, getThis(), ZEND_STRL("latitude"), lat TSRMLS_CC);
}

PHP_METHOD(SearchSortGeoDistance, descending)
{
    zend_bool descending = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &descending);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_bool(pcbc_search_sort_geo_distance_ce, getThis(), ZEND_STRL("desc"), descending TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchSortGeoDistance, unit)
{
    zend_string *unit = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &unit);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_search_sort_geo_distance_ce, getThis(), ZEND_STRL("unit"), unit TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchSortGeoDistance, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    add_assoc_string(return_value, "by", "geo_distance");
    zval *prop, ret;
    prop = zend_read_property(pcbc_search_sort_geo_distance_ce, getThis(), ZEND_STRL("desc"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "desc", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_search_sort_geo_distance_ce, getThis(), ZEND_STRL("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }

    zval location;
    array_init(&location);
    prop = zend_read_property(pcbc_search_sort_geo_distance_ce, getThis(), ZEND_STRL("longitude"), 0, &ret);
    add_next_index_zval(&location, prop);
    prop = zend_read_property(pcbc_search_sort_geo_distance_ce, getThis(), ZEND_STRL("latitude"), 0, &ret);
    add_next_index_zval(&location, prop);
    add_assoc_zval(return_value, "location", &location);

    prop = zend_read_property(pcbc_search_sort_geo_distance_ce, getThis(), ZEND_STRL("unit"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "unit", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_SearchSortGeoDistance_jsonSerialize, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SearchSortGeoDistance_construct, 0, 0, 3)
ZEND_ARG_TYPE_INFO(0, field, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, longitude, IS_DOUBLE, 0)
ZEND_ARG_TYPE_INFO(0, latitude, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchSortGeoDistance_descending, 0, 1, Couchbase\\SearchSortGeoDistance, 0)
ZEND_ARG_TYPE_INFO(0, descending, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchSortGeoDistance_unit, 0, 1, Couchbase\\SearchSortGeoDistance, 0)
ZEND_ARG_TYPE_INFO(0, unit, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry search_sort_geo_distance_methods[] = {
    PHP_ME(SearchSortGeoDistance, __construct, ai_SearchSortGeoDistance_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(SearchSortGeoDistance, jsonSerialize, ai_SearchSortGeoDistance_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_ME(SearchSortGeoDistance, descending, ai_SearchSortGeoDistance_descending, ZEND_ACC_PUBLIC)
    PHP_ME(SearchSortGeoDistance, unit, ai_SearchSortGeoDistance_unit, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(SearchSortGeoDistance)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchSortGeoDistance", search_sort_geo_distance_methods);
    pcbc_search_sort_geo_distance_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_class_implements(pcbc_search_sort_geo_distance_ce TSRMLS_CC, 2, pcbc_json_serializable_ce,
                          pcbc_search_sort_ce);
    zend_declare_property_null(pcbc_search_sort_geo_distance_ce, ZEND_STRL("desc"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_sort_geo_distance_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_sort_geo_distance_ce, ZEND_STRL("longitude"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_sort_geo_distance_ce, ZEND_STRL("latitude"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_sort_geo_distance_ce, ZEND_STRL("unit"), ZEND_ACC_PRIVATE TSRMLS_CC);
    return SUCCESS;
}
