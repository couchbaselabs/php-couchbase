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
 * Sort by the hit score.
 */
#include "couchbase.h"

zend_class_entry *pcbc_search_sort_score_ce;

PHP_METHOD(SearchSortScore, descending)
{
    zend_bool descending = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "b", &descending);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_bool(pcbc_search_sort_score_ce, getThis(), ZEND_STRL("desc"), descending TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchSortScore, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    add_assoc_string(return_value, "by", "score");
    zval *prop, ret;
    prop = zend_read_property(pcbc_search_sort_score_ce, getThis(), ZEND_STRL("desc"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "desc", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_SearchSortScore_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchSortScore_descending, 0, 1, Couchbase\\SearchSortScore, 0)
ZEND_ARG_TYPE_INFO(0, descending, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry search_sort_score_methods[] = {
    PHP_ME(SearchSortScore, jsonSerialize, ai_SearchSortScore_none, ZEND_ACC_PUBLIC)
    PHP_ME(SearchSortScore, descending, ai_SearchSortScore_descending, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(SearchSortScore)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchSortScore", search_sort_score_methods);
    pcbc_search_sort_score_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_class_implements(pcbc_search_sort_score_ce TSRMLS_CC, 2, pcbc_json_serializable_ce, pcbc_search_sort_ce);
    zend_declare_property_null(pcbc_search_sort_score_ce, ZEND_STRL("desc"), ZEND_ACC_PRIVATE TSRMLS_CC);
    return SUCCESS;
}
