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
 * Sort by a field in the hits.
 */
#include "couchbase.h"

zend_class_entry *pcbc_search_sort_field_ce;

PHP_METHOD(SearchSortField, __construct)
{
    zend_string *field = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &field);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_search_sort_field_ce, getThis(), ZEND_STRL("field"), field TSRMLS_CC);
}

PHP_METHOD(SearchSortField, descending)
{
    zend_bool descending = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &descending);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_bool(pcbc_search_sort_field_ce, getThis(), ZEND_STRL("desc"), descending TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchSortField, type)
{
    zend_string *type = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &type);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_search_sort_field_ce, getThis(), ZEND_STRL("type"), type TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchSortField, mode)
{
    zend_string *mode = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &mode);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_search_sort_field_ce, getThis(), ZEND_STRL("mode"), mode TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchSortField, missing)
{
    zend_string *missing = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &missing);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_search_sort_field_ce, getThis(), ZEND_STRL("missing"), missing TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchSortField, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    add_assoc_string(return_value, "by", "field");
    zval *prop, ret;
    prop = zend_read_property(pcbc_search_sort_field_ce, getThis(), ZEND_STRL("desc"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "desc", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_search_sort_field_ce, getThis(), ZEND_STRL("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_search_sort_field_ce, getThis(), ZEND_STRL("type"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "type", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_search_sort_field_ce, getThis(), ZEND_STRL("mode"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "mode", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_search_sort_field_ce, getThis(), ZEND_STRL("missing"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "missing", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_SearchSortField_jsonSerialize, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_SearchSortField_construct, 0, 0, 0)
ZEND_ARG_TYPE_INFO(0, field, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchSortField_descending, 0, 1, Couchbase\\SearchSortField, 0)
ZEND_ARG_TYPE_INFO(0, descending, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchSortField_type, 0, 1, Couchbase\\SearchSortField, 0)
ZEND_ARG_TYPE_INFO(0, type, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchSortField_mode, 0, 1, Couchbase\\SearchSortField, 0)
ZEND_ARG_TYPE_INFO(0, mode, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchSortField_missing, 0, 1, Couchbase\\SearchSortField, 0)
ZEND_ARG_TYPE_INFO(0, missing, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry search_sort_field_methods[] = {
    PHP_ME(SearchSortField, __construct, ai_SearchSortField_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(SearchSortField, jsonSerialize, ai_SearchSortField_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_ME(SearchSortField, descending, ai_SearchSortField_descending, ZEND_ACC_PUBLIC)
    PHP_ME(SearchSortField, type, ai_SearchSortField_type, ZEND_ACC_PUBLIC)
    PHP_ME(SearchSortField, mode, ai_SearchSortField_mode, ZEND_ACC_PUBLIC)
    PHP_ME(SearchSortField, missing, ai_SearchSortField_missing, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

zend_class_entry *pcbc_search_sort_type_ce;
static const zend_function_entry search_sort_type_interface[] = {PHP_FE_END};
zend_class_entry *pcbc_search_sort_mode_ce;
static const zend_function_entry search_sort_mode_interface[] = {PHP_FE_END};
zend_class_entry *pcbc_search_sort_missing_ce;
static const zend_function_entry search_sort_missing_interface[] = {PHP_FE_END};

PHP_MINIT_FUNCTION(SearchSortField)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchSortField", search_sort_field_methods);
    pcbc_search_sort_field_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_class_implements(pcbc_search_sort_field_ce TSRMLS_CC, 2, pcbc_json_serializable_ce, pcbc_search_sort_ce);
    zend_declare_property_null(pcbc_search_sort_field_ce, ZEND_STRL("desc"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_sort_field_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_sort_field_ce, ZEND_STRL("type"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_sort_field_ce, ZEND_STRL("mode"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_search_sort_field_ce, ZEND_STRL("missing"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchSortType", search_sort_type_interface);
    pcbc_search_sort_type_ce = zend_register_internal_interface(&ce TSRMLS_CC);
    zend_declare_class_constant_stringl(pcbc_search_sort_type_ce, ZEND_STRL("AUTO"), ZEND_STRL("auto") TSRMLS_CC);
    zend_declare_class_constant_stringl(pcbc_search_sort_type_ce, ZEND_STRL("STRING"), ZEND_STRL("string") TSRMLS_CC);
    zend_declare_class_constant_stringl(pcbc_search_sort_type_ce, ZEND_STRL("NUMBER"), ZEND_STRL("number") TSRMLS_CC);
    zend_declare_class_constant_stringl(pcbc_search_sort_type_ce, ZEND_STRL("DATE"), ZEND_STRL("date") TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchSortMode", search_sort_mode_interface);
    pcbc_search_sort_mode_ce = zend_register_internal_interface(&ce TSRMLS_CC);
    zend_declare_class_constant_stringl(pcbc_search_sort_mode_ce, ZEND_STRL("DEFAULT"), ZEND_STRL("default") TSRMLS_CC);
    zend_declare_class_constant_stringl(pcbc_search_sort_mode_ce, ZEND_STRL("MIN"), ZEND_STRL("min") TSRMLS_CC);
    zend_declare_class_constant_stringl(pcbc_search_sort_mode_ce, ZEND_STRL("MAX"), ZEND_STRL("max") TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchSortMissing", search_sort_missing_interface);
    pcbc_search_sort_missing_ce = zend_register_internal_interface(&ce TSRMLS_CC);
    zend_declare_class_constant_stringl(pcbc_search_sort_missing_ce, ZEND_STRL("FIRST"), ZEND_STRL("first") TSRMLS_CC);
    zend_declare_class_constant_stringl(pcbc_search_sort_missing_ce, ZEND_STRL("LAST"), ZEND_STRL("last") TSRMLS_CC);
    return SUCCESS;
}
