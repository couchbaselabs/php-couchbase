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
 * A compound FTS query that performs a logical OR between all its sub-queries (disjunction).  It requires that a
 * minimum of the queries match. The minimum is configurable (default 1).
 */
#include "couchbase.h"

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/disjunction_search_query", __FILE__, __LINE__

zend_class_entry *pcbc_disjunction_search_query_ce;

PHP_METHOD(DisjunctionSearchQuery, __construct)
{
    zval *queries = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "|a", &queries);
    if (rv == FAILURE) {
        return;
    }

    zval container;
    array_init(&container);
    zend_update_property(pcbc_disjunction_search_query_ce, getThis(), ZEND_STRL("queries"), &container TSRMLS_CC);
    Z_DELREF(container);

    if (queries && Z_TYPE_P(queries) != IS_NULL) {
        zval *entry;
        ZEND_HASH_FOREACH_VAL(HASH_OF(queries), entry)
        {
            if (Z_TYPE_P(entry) != IS_OBJECT ||
                !instanceof_function(Z_OBJCE_P(entry), pcbc_search_query_ce TSRMLS_CC)) {
                pcbc_log(LOGARGS(WARN), "Non-query value detected in queries array");
                zend_type_error("Expected SearchQuery for a FTS disjunction query");
            }
            add_next_index_zval(&container, entry);
            Z_TRY_ADDREF_P(entry);
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_METHOD(DisjunctionSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_double(pcbc_disjunction_search_query_ce, getThis(), ZEND_STRL("boost"), boost TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(DisjunctionSearchQuery, min)
{
    int rv;
    zend_long min;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "l", &min);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_double(pcbc_disjunction_search_query_ce, getThis(), ZEND_STRL("min"), min TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(DisjunctionSearchQuery, either)
{
    zval *args = NULL;
    int num_args = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "+", &args, &num_args);
    if (rv == FAILURE) {
        return;
    }

    if (num_args && args) {
        zval *container, ret;
        int i;
        container = zend_read_property(pcbc_disjunction_search_query_ce, getThis(), ZEND_STRL("queries"), 0, &ret);
        for (i = 0; i < num_args; ++i) {
            zval *entry;
            entry = &args[i];
            if (Z_TYPE_P(entry) != IS_OBJECT ||
                !instanceof_function(Z_OBJCE_P(entry), pcbc_search_query_ce TSRMLS_CC)) {
                pcbc_log(LOGARGS(WARN), "Non-query value detected in queries array");
                zend_type_error("Expected SearchQuery for a FTS disjunction query");
            }
            add_next_index_zval(container, entry);
            Z_TRY_ADDREF_P(entry);
        }
    }
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(DisjunctionSearchQuery, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    zval *prop, ret;

    prop = zend_read_property(pcbc_disjunction_search_query_ce, getThis(), ZEND_STRL("queries"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "disjuncts", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_disjunction_search_query_ce, getThis(), ZEND_STRL("min"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "min", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_disjunction_search_query_ce, getThis(), ZEND_STRL("boost"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "boost", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_DisjunctionSearchQuery_jsonSerialize, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_DisjunctionSearchQuery_construct, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, queries, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DisjunctionSearchQuery_boost, 0, 1, Couchbase\\DisjunctionSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, boost, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DisjunctionSearchQuery_either, 0, 1, Couchbase\\DisjunctionSearchQuery, 0)
PCBC_ARG_VARIADIC_INFO(0, queries)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DisjunctionSearchQuery_min, 0, 1, Couchbase\\DisjunctionSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, min, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry disjunction_search_query_methods[] = {
    PHP_ME(DisjunctionSearchQuery, __construct, ai_DisjunctionSearchQuery_construct, ZEND_ACC_PUBLIC)
    PHP_ME(DisjunctionSearchQuery, jsonSerialize, ai_DisjunctionSearchQuery_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_ME(DisjunctionSearchQuery, boost, ai_DisjunctionSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(DisjunctionSearchQuery, either, ai_DisjunctionSearchQuery_either, ZEND_ACC_PUBLIC)
    PHP_ME(DisjunctionSearchQuery, min, ai_DisjunctionSearchQuery_min, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(DisjunctionSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DisjunctionSearchQuery", disjunction_search_query_methods);
    pcbc_disjunction_search_query_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_class_implements(pcbc_disjunction_search_query_ce TSRMLS_CC, 2, pcbc_json_serializable_ce,
                          pcbc_search_query_ce);

    zend_declare_property_null(pcbc_disjunction_search_query_ce, ZEND_STRL("queries"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_disjunction_search_query_ce, ZEND_STRL("min"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_disjunction_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}
