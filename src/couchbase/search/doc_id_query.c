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
 * A FTS query that matches on Couchbase document IDs. Useful to restrict the search space to a list of keys (by using
 * this in a compound query).
 */
#include "couchbase.h"
#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/doc_id_search_query", __FILE__, __LINE__

zend_class_entry *pcbc_doc_id_search_query_ce;

PHP_METHOD(DocIdSearchQuery, field)
{
    zend_string *field = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &field);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_str(pcbc_doc_id_search_query_ce, getThis(), ZEND_STRL("field"), field TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(DocIdSearchQuery, boost)
{
    double boost = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "d", &boost);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_double(pcbc_doc_id_search_query_ce, getThis(), ZEND_STRL("boost"), boost TSRMLS_CC);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(DocIdSearchQuery, docIds)
{
    zval *args = NULL;
    int num_args = 0;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "+", &args, &num_args);
    if (rv == FAILURE) {
        return;
    }

    if (num_args && args) {
        zval *container, rv1;
        container = zend_read_property(pcbc_doc_id_search_query_ce, getThis(), ZEND_STRL("ids"), 0, &rv1);
        if (Z_TYPE_P(container) == IS_NULL) {
            array_init(&rv1);
            container = &rv1;
            zend_update_property(pcbc_doc_id_search_query_ce, getThis(), ZEND_STRL("ids"), container TSRMLS_CC);
            Z_DELREF_P(container);
        }
        int i;
        for (i = 0; i < num_args; ++i) {
            zval *id;
            id = &args[i];
            if (Z_TYPE_P(id) != IS_STRING) {
                pcbc_log(LOGARGS(WARN), "id has to be a string (argument #%d)", i);
                zend_type_error("Expected String for document ID");
            }
            add_next_index_zval(container, id);
            Z_TRY_ADDREF_P(id);
        }
    }

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(DocIdSearchQuery, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);
    zval *prop, ret;

    prop = zend_read_property(pcbc_doc_id_search_query_ce, getThis(), ZEND_STRL("ids"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "ids", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_doc_id_search_query_ce, getThis(), ZEND_STRL("field"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "field", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = zend_read_property(pcbc_doc_id_search_query_ce, getThis(), ZEND_STRL("boost"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "boost", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_DocIdSearchQuery_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DocIdSearchQuery_field, 0, 1, Couchbase\\DocIdSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, field, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DocIdSearchQuery_boost, 0, 1, Couchbase\\DocIdSearchQuery, 0)
ZEND_ARG_TYPE_INFO(0, boost, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_DocIdSearchQuery_docIds, 0, 0, 1)
PCBC_ARG_VARIADIC_INFO(0, documentIds)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry doc_id_search_query_methods[] = {
    PHP_ME(DocIdSearchQuery, jsonSerialize, ai_DocIdSearchQuery_none, ZEND_ACC_PUBLIC)
    PHP_ME(DocIdSearchQuery, boost, ai_DocIdSearchQuery_boost, ZEND_ACC_PUBLIC)
    PHP_ME(DocIdSearchQuery, field, ai_DocIdSearchQuery_field, ZEND_ACC_PUBLIC)
    PHP_ME(DocIdSearchQuery, docIds, ai_DocIdSearchQuery_docIds, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(DocIdSearchQuery)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DocIdSearchQuery", doc_id_search_query_methods);
    pcbc_doc_id_search_query_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_class_implements(pcbc_doc_id_search_query_ce TSRMLS_CC, 2, pcbc_json_serializable_ce, pcbc_search_query_ce);
    zend_declare_property_null(pcbc_doc_id_search_query_ce, ZEND_STRL("boost"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_doc_id_search_query_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_doc_id_search_query_ce, ZEND_STRL("ids"), ZEND_ACC_PRIVATE TSRMLS_CC);
    return SUCCESS;
}
