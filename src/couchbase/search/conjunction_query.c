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
 * A compound FTS query that performs a logical AND between all its sub-queries (conjunction).
 */
#include "couchbase.h"

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/conjunction_search_query", __FILE__, __LINE__

zend_class_entry *pcbc_conjunction_search_query_ce;

PHP_METHOD(ConjunctionSearchQuery, __construct)
{
    zval *queries = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "|a", &queries);
    if (rv == FAILURE) {
        return;
    }

    zval container;
    array_init(&container);
    pcbc_update_property(pcbc_conjunction_search_query_ce, getThis(), ("queries"), &container);
    Z_DELREF(container);

    if (queries && Z_TYPE_P(queries) != IS_NULL) {
        zval *entry;
        ZEND_HASH_FOREACH_VAL(HASH_OF(queries), entry)
        {
            if (Z_TYPE_P(entry) != IS_OBJECT || !instanceof_function(Z_OBJCE_P(entry), pcbc_search_query_ce)) {
                pcbc_log(LOGARGS(WARN), "Non-query value detected in queries array");
                zend_type_error("Expected SearchQuery for a FTS conjunction query");
            }
            add_next_index_zval(&container, entry);
            Z_TRY_ADDREF_P(entry);
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_METHOD(ConjunctionSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_double(pcbc_conjunction_search_query_ce, getThis(), ("boost"), boost);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ConjunctionSearchQuery, every)
{
    zval *args = NULL;
    int num_args = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "+", &args, &num_args);
    if (rv == FAILURE) {
        return;
    }

    if (num_args && args) {
        zval *container, ret;
        int i;
        container = pcbc_read_property(pcbc_conjunction_search_query_ce, getThis(), ("queries"), 0, &ret);
        for (i = 0; i < num_args; ++i) {
            zval *entry;
            entry = &args[i];
            if (Z_TYPE_P(entry) != IS_OBJECT || !instanceof_function(Z_OBJCE_P(entry), pcbc_search_query_ce)) {
                pcbc_log(LOGARGS(WARN), "Non-query value detected in queries array");
                zend_type_error("Expected SearchQuery for a FTS conjunction query");
            }
            add_next_index_zval(container, entry);
            Z_TRY_ADDREF_P(entry);
        }
    }
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ConjunctionSearchQuery, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    zval *prop, ret;

    prop = pcbc_read_property(pcbc_conjunction_search_query_ce, getThis(), ("queries"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "conjuncts", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_conjunction_search_query_ce, getThis(), ("boost"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "boost", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_WITH_TENTATIVE_RETURN_TYPE_INFO_EX(ai_ConjunctionSearchQuery_jsonSerialize, 0, 0, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_ConjunctionSearchQuery_construct, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, queries, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ConjunctionSearchQuery_boost, 0, 1, Couchbase\\ConjunctionSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, boost, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ConjunctionSearchQuery_every, 0, 1, Couchbase\\ConjunctionSearchQuery, 0)
PCBC_ARG_VARIADIC_INFO(0, queries)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry conjunction_search_query_methods[] = {
    PHP_ME(ConjunctionSearchQuery, __construct, ai_ConjunctionSearchQuery_construct, ZEND_ACC_PUBLIC)
    PHP_ME(ConjunctionSearchQuery, jsonSerialize, ai_ConjunctionSearchQuery_jsonSerialize, ZEND_ACC_PUBLIC)
    PHP_ME(ConjunctionSearchQuery, boost, ai_ConjunctionSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(ConjunctionSearchQuery, every, ai_ConjunctionSearchQuery_every, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(ConjunctionSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ConjunctionSearchQuery", conjunction_search_query_methods);
    pcbc_conjunction_search_query_ce = zend_register_internal_class(&ce);

    zend_class_implements(pcbc_conjunction_search_query_ce, 2, pcbc_json_serializable_ce, pcbc_search_query_ce);

    zend_declare_property_null(pcbc_conjunction_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_conjunction_search_query_ce, ZEND_STRL("queries"), ZEND_ACC_PRIVATE);

    return SUCCESS;
}
