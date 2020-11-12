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
 * A facet that gives the number of occurrences of the most recurring terms in all hits.
 */
#include "couchbase.h"

zend_class_entry *pcbc_term_search_facet_ce;

PHP_METHOD(TermSearchFacet, __construct)
{
    zend_string *field = NULL;
    zend_long limit;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sl", &field, &limit);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_term_search_facet_ce, getThis(), ZEND_STRL("field"), field);
    zend_update_property_long(pcbc_term_search_facet_ce, getThis(), ZEND_STRL("limit"), limit);
}

PHP_METHOD(TermSearchFacet, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    zval *prop, ret;
    prop = zend_read_property(pcbc_term_search_facet_ce, getThis(), ZEND_STRL("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }
    prop = zend_read_property(pcbc_term_search_facet_ce, getThis(), ZEND_STRL("limit"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "size", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_TermSearchFacet_jsonSerialize, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_TermSearchFacet_construct, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, field, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, limit, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry term_search_facet_methods[] = {
    PHP_ME(TermSearchFacet, __construct, ai_TermSearchFacet_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(TermSearchFacet, jsonSerialize, ai_TermSearchFacet_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(TermSearchFacet)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "TermSearchFacet", term_search_facet_methods);
    pcbc_term_search_facet_ce = zend_register_internal_class(&ce);

    zend_class_implements(pcbc_term_search_facet_ce, 2, pcbc_json_serializable_ce, pcbc_search_facet_ce);

    zend_declare_property_null(pcbc_term_search_facet_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_term_search_facet_ce, ZEND_STRL("limit"), ZEND_ACC_PRIVATE);
    return SUCCESS;
}
