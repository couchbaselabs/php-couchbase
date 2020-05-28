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

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/geo_bounding_box_search_query", __FILE__, __LINE__

zend_class_entry *pcbc_geo_bounding_box_search_query_ce;

PHP_METHOD(GeoBoundingBoxSearchQuery, __construct)
{
    int rv;
    double tl_lon, tl_lat, br_lon, br_lat;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "dddd", &tl_lon, &tl_lat, &br_lon, &br_lat);
    if (rv == FAILURE) {
        return;
    }
    zend_update_property_double(pcbc_geo_bounding_box_search_query_ce, getThis(), ZEND_STRL("top_left_longitude"),
                                tl_lon TSRMLS_CC);
    zend_update_property_double(pcbc_geo_bounding_box_search_query_ce, getThis(), ZEND_STRL("top_left_latitude"),
                                tl_lat TSRMLS_CC);
    zend_update_property_double(pcbc_geo_bounding_box_search_query_ce, getThis(), ZEND_STRL("bottom_right_longitude"),
                                br_lon TSRMLS_CC);
    zend_update_property_double(pcbc_geo_bounding_box_search_query_ce, getThis(), ZEND_STRL("bottom_right_latitude"),
                                br_lat TSRMLS_CC);
}

PHP_METHOD(GeoBoundingBoxSearchQuery, field)
{
    zend_string *field = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &field);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_geo_bounding_box_search_query_ce, getThis(), ZEND_STRL("field"), field TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(GeoBoundingBoxSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_double(pcbc_geo_bounding_box_search_query_ce, getThis(), ZEND_STRL("boost"), boost TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(GeoBoundingBoxSearchQuery, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);

    zval *prop, ret;

    zval top_left;
    array_init(&top_left);
    prop =
        zend_read_property(pcbc_geo_bounding_box_search_query_ce, getThis(), ZEND_STRL("top_left_longitude"), 0, &ret);
    add_next_index_zval(&top_left, prop);
    prop =
        zend_read_property(pcbc_geo_bounding_box_search_query_ce, getThis(), ZEND_STRL("top_left_latitude"), 0, &ret);
    add_next_index_zval(&top_left, prop);
    add_assoc_zval(return_value, "top_left", &top_left);
    Z_TRY_ADDREF(top_left);

    zval bottom_right;
    array_init(&bottom_right);
    prop = zend_read_property(pcbc_geo_bounding_box_search_query_ce, getThis(), ZEND_STRL("bottom_right_longitude"), 0,
                              &ret);
    add_next_index_zval(&bottom_right, prop);
    prop = zend_read_property(pcbc_geo_bounding_box_search_query_ce, getThis(), ZEND_STRL("bottom_right_latitude"), 0,
                              &ret);
    add_next_index_zval(&bottom_right, prop);
    add_assoc_zval(return_value, "bottom_right", &bottom_right);
    Z_TRY_ADDREF(bottom_right);

    prop = zend_read_property(pcbc_geo_bounding_box_search_query_ce, getThis(), ZEND_STRL("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_geo_bounding_box_search_query_ce, getThis(), ZEND_STRL("boost"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "boost", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_GeoBoundingBoxSearchQuery_jsonSerialize, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_GeoBoundingBoxSearchQuery_construct, 0, 0, 4)
ZEND_ARG_TYPE_INFO(0, top_left_longitude, IS_DOUBLE, 0)
ZEND_ARG_TYPE_INFO(0, top_left_latitude, IS_DOUBLE, 0)
ZEND_ARG_TYPE_INFO(0, buttom_right_longitude, IS_DOUBLE, 0)
ZEND_ARG_TYPE_INFO(0, buttom_right_latitude, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GeoBoundingBoxSearchQuery_field, 0, 1, Couchbase\\GeoBoundingBoxSearchQuery,
                                       0)
ZEND_ARG_TYPE_INFO(0, field, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GeoBoundingBoxSearchQuery_boost, 0, 1, Couchbase\\GeoBoundingBoxSearchQuery,
                                       0)
ZEND_ARG_TYPE_INFO(0, boost, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry geo_bounding_box_search_query_methods[] = {
    PHP_ME(GeoBoundingBoxSearchQuery, __construct, ai_GeoBoundingBoxSearchQuery_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(GeoBoundingBoxSearchQuery, jsonSerialize, ai_GeoBoundingBoxSearchQuery_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_ME(GeoBoundingBoxSearchQuery, boost, ai_GeoBoundingBoxSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(GeoBoundingBoxSearchQuery, field, ai_GeoBoundingBoxSearchQuery_field, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(GeoBoundingBoxSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GeoBoundingBoxSearchQuery", geo_bounding_box_search_query_methods);
    pcbc_geo_bounding_box_search_query_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_class_implements(pcbc_geo_bounding_box_search_query_ce TSRMLS_CC, 2, pcbc_json_serializable_ce,
                          pcbc_search_query_ce);

    zend_declare_property_null(pcbc_geo_bounding_box_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_geo_bounding_box_search_query_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_geo_bounding_box_search_query_ce, ZEND_STRL("top_left_longitude"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_geo_bounding_box_search_query_ce, ZEND_STRL("top_left_latitude"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_geo_bounding_box_search_query_ce, ZEND_STRL("bottom_right_longitude"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_geo_bounding_box_search_query_ce, ZEND_STRL("bottom_right_latitude"),
                               ZEND_ACC_PRIVATE TSRMLS_CC);
    return SUCCESS;
}
