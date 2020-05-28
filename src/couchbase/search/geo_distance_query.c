/**
 *     Copyright 2017-2019 Couchbase, Inc.
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

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/geo_distance_search_query", __FILE__, __LINE__

zend_class_entry *pcbc_geo_distance_search_query_ce;

PHP_METHOD(GeoDistanceSearchQuery, __construct)
{
    int rv;
    double lon, lat;
    zend_string *distance = NULL;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "dd|S", &lon, &lat, &distance);
    if (rv == FAILURE) {
        return;
    }

    zend_update_property_double(pcbc_geo_distance_search_query_ce, getThis(), ZEND_STRL("longitude"), lon TSRMLS_CC);
    zend_update_property_double(pcbc_geo_distance_search_query_ce, getThis(), ZEND_STRL("latitude"), lat TSRMLS_CC);
    if (distance) {
        zend_update_property_str(pcbc_geo_distance_search_query_ce, getThis(), ZEND_STRL("distance"),
                                 distance TSRMLS_CC);
    }
}

PHP_METHOD(GeoDistanceSearchQuery, field)
{
    zend_string *field = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &field);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_geo_distance_search_query_ce, getThis(), ZEND_STRL("field"), field TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(GeoDistanceSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_double(pcbc_geo_distance_search_query_ce, getThis(), ZEND_STRL("boost"), boost TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(GeoDistanceSearchQuery, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    array_init(return_value);
    zval *prop, ret;

    zval location;
    array_init(&location);
    prop = zend_read_property(pcbc_geo_distance_search_query_ce, getThis(), ZEND_STRL("longitude"), 0, &ret);
    add_next_index_zval(&location, prop);
    prop = zend_read_property(pcbc_geo_distance_search_query_ce, getThis(), ZEND_STRL("latitude"), 0, &ret);
    add_next_index_zval(&location, prop);
    add_assoc_zval(return_value, "location", &location);
    Z_TRY_ADDREF(location);

    prop = zend_read_property(pcbc_geo_distance_search_query_ce, getThis(), ZEND_STRL("distance"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "distance", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_geo_distance_search_query_ce, getThis(), ZEND_STRL("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_geo_distance_search_query_ce, getThis(), ZEND_STRL("boost"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "boost", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_GeoDistanceSearchQuery_jsonSerialize, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_GeoDistanceSearchQuery_construct, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, longitude, IS_DOUBLE, 0)
ZEND_ARG_TYPE_INFO(0, latitude, IS_DOUBLE, 0)
ZEND_ARG_TYPE_INFO(0, distance, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GeoDistanceSearchQuery_field, 0, 1, Couchbase\\GeoDistanceSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, field, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GeoDistanceSearchQuery_boost, 0, 1, Couchbase\\GeoDistanceSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, boost, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry geo_distance_search_query_methods[] = {
    PHP_ME(GeoDistanceSearchQuery, __construct, ai_GeoDistanceSearchQuery_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(GeoDistanceSearchQuery, jsonSerialize, ai_GeoDistanceSearchQuery_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_ME(GeoDistanceSearchQuery, boost, ai_GeoDistanceSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(GeoDistanceSearchQuery, field, ai_GeoDistanceSearchQuery_field, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(GeoDistanceSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GeoDistanceSearchQuery", geo_distance_search_query_methods);
    pcbc_geo_distance_search_query_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_class_implements(pcbc_geo_distance_search_query_ce TSRMLS_CC, 2, pcbc_json_serializable_ce,
                          pcbc_search_query_ce);

    zend_declare_property_null(pcbc_geo_distance_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_geo_distance_search_query_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_geo_distance_search_query_ce, ZEND_STRL("longitude"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_geo_distance_search_query_ce, ZEND_STRL("latitude"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_geo_distance_search_query_ce, ZEND_STRL("distance"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}
