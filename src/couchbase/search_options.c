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

#include "couchbase.h"
#include <Zend/zend_alloc.h>

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/search_options", __FILE__, __LINE__

zend_class_entry *pcbc_search_options_ce;

PHP_METHOD(SearchOptions, timeout)
{
    zend_long arg;
    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_long(pcbc_search_options_ce, getThis(), ("timeout"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchOptions, limit)
{
    zend_long arg;
    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_long(pcbc_search_options_ce, getThis(), ("limit"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchOptions, skip)
{
    zend_long arg;
    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_long(pcbc_search_options_ce, getThis(), ("skip"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchOptions, explain)
{
    zend_bool arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "b", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_bool(pcbc_search_options_ce, getThis(), ("explain"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchOptions, disableScoring)
{
    zend_bool arg;
    int rv = zend_parse_parameters(ZEND_NUM_ARGS(), "b", &arg);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_bool(pcbc_search_options_ce, getThis(), ("disable_scoring"), arg);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchOptions, consistentWith)
{
    zend_string *index;
    zval *arg;
    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "SO", &index, &arg, pcbc_mutation_state_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, ret;
    prop = pcbc_read_property(pcbc_search_options_ce, getThis(), ("consistent_with"), 0, &ret);
    if (Z_TYPE_P(prop) == IS_NULL) {
        array_init(&ret);
        prop = &ret;
        pcbc_update_property(pcbc_search_options_ce, getThis(), ("consistent_with"), &ret);
        Z_DELREF_P(prop);
    }

    zval scan_vectors;
    ZVAL_UNDEF(&scan_vectors);
    pcbc_mutation_state_export_for_search(arg, &scan_vectors);
    add_assoc_zval_ex(prop, ZSTR_VAL(index), ZSTR_LEN(index), &scan_vectors);
    Z_ADDREF(scan_vectors);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchOptions, facets)
{
    zval *facets;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "a", &facets);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zend_string *string_key = NULL;
    zval *entry;
    ZEND_HASH_FOREACH_STR_KEY_VAL(HASH_OF(facets), string_key, entry)
    {
        if (string_key) {
            if (!instanceof_function(Z_OBJCE_P(entry), pcbc_search_facet_ce)) {
                pcbc_log(LOGARGS(WARN), "Non-facet value detected in facets array");
                zend_type_error("Expected facet object for %s", ZSTR_VAL(string_key));
            }
        } else {
            pcbc_log(LOGARGS(WARN), "Non-string key detected in facets array");
            zend_type_error("Expected string keys in facets argument");
            RETURN_NULL();
        }
    }
    ZEND_HASH_FOREACH_END();
    pcbc_update_property(pcbc_search_options_ce, getThis(), ("facets"), facets);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchOptions, fields)
{
    zval *fields = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "a", &fields);
    if (rv == FAILURE) {
        return;
    }

    zval *entry;
    ZEND_HASH_FOREACH_VAL(HASH_OF(fields), entry)
    {

        if (Z_TYPE_P(entry) != IS_STRING) {
            pcbc_log(LOGARGS(WARN), "Non-string value detected in fields array");
            zend_type_error("Expected string for a FTS field");
            RETURN_NULL();
        }
    }
    ZEND_HASH_FOREACH_END();
    pcbc_update_property(pcbc_search_options_ce, getThis(), ("fields"), fields);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchOptions, sort)
{
    zval *args = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "a", &args);
    if (rv == FAILURE) {
        return;
    }

    zval *entry;
    ZEND_HASH_FOREACH_VAL(HASH_OF(args), entry)
    {
        if (Z_TYPE_P(entry) != IS_STRING &&
            (Z_TYPE_P(entry) != IS_OBJECT || !instanceof_function(Z_OBJCE_P(entry), pcbc_search_sort_ce))) {
            pcbc_log(LOGARGS(WARN), "expected sort entry to be a string or SearchSort");
            zend_type_error("Expected string for a FTS field");
        }
    }
    ZEND_HASH_FOREACH_END();
    pcbc_update_property(pcbc_search_options_ce, getThis(), ("sort"), args);

    RETURN_ZVAL(getThis(), 1, 0);
}

/* {{{ proto \Couchbase\SearchOptions SearchOptions::highlight(string $style, string ...$fields)
   See SearchOptions::HIGHLIGHT_{HTML,ANSI,SIMPLE}. Pass NULL for $style to switch it off.
*/
PHP_METHOD(SearchOptions, highlight)
{
    zend_string *style = NULL;
    zval *fields = NULL;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS(), "S|a", &style, &fields);
    if (rv == FAILURE) {
        return;
    }

    pcbc_update_property_str(pcbc_search_options_ce, getThis(), ("highlight_style"), style);
    if (fields) {
        pcbc_update_property(pcbc_search_options_ce, getThis(), ("highlight_fields"), fields);
    }

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchOptions, collections)
{
    zval *collections = NULL;
    int rv;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "a", &collections);
    if (rv == FAILURE) {
        return;
    }

    zval *entry;
    ZEND_HASH_FOREACH_VAL(HASH_OF(collections), entry)
    {
        if (Z_TYPE_P(entry) != IS_STRING) {
            pcbc_log(LOGARGS(WARN), "Non-string value detected in collections array");
            zend_type_error("Expected string for a FTS collection");
        }
    }
    ZEND_HASH_FOREACH_END();
    pcbc_update_property(pcbc_search_options_ce, getThis(), ("collections"), collections);

    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(SearchOptions, jsonSerialize)
{
    int rv;

    rv = zend_parse_parameters_none_throw();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    array_init(return_value);

    zval *prop, ret;

    prop = pcbc_read_property(pcbc_search_options_ce, getThis(), ("disable_scoring"), 0, &ret);
    if (Z_TYPE_P(prop) == IS_TRUE) {
        add_assoc_string(return_value, "score", "none");
    }

    prop = pcbc_read_property(pcbc_search_options_ce, getThis(), ("explain"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "explain", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_search_options_ce, getThis(), ("limit"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "size", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_search_options_ce, getThis(), ("skip"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "from", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_search_options_ce, getThis(), ("fields"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "fields", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_search_options_ce, getThis(), ("sort"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "sort", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_search_options_ce, getThis(), ("facets"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "facets", prop);
        Z_TRY_ADDREF_P(prop);
    }

    prop = pcbc_read_property(pcbc_search_options_ce, getThis(), ("highlight_style"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        zval highlight;
        array_init(&highlight);
        add_assoc_zval(&highlight, "style", prop);
        Z_TRY_ADDREF_P(prop);

        zval ret2;
        zval *fields = pcbc_read_property(pcbc_search_options_ce, getThis(), ("highlight_style"), 0, &ret2);
        if (Z_TYPE_P(fields) == IS_ARRAY) {
            add_assoc_zval(&highlight, "fields", fields);
        }
        add_assoc_zval(return_value, "highlight", &highlight);
    }

    zval control;
    array_init(&control);
    prop = pcbc_read_property(pcbc_search_options_ce, getThis(), ("timeout"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(&control, "timeout", prop);
        Z_TRY_ADDREF_P(prop);
    }

    zval consistency, vectors;
    prop = pcbc_read_property(pcbc_search_options_ce, getThis(), ("consistent_with"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        array_init(&consistency);
        add_assoc_string(&consistency, "level", "at_plus");
        array_init(&vectors);
        add_assoc_zval(&consistency, "vectors", &vectors);
        add_assoc_zval(&control, "consistency", &consistency);
        Z_TRY_ADDREF(consistency);

        zend_string *index = NULL;
        zval *scan_vector;
        ZEND_HASH_FOREACH_STR_KEY_VAL(HASH_OF(prop), index, scan_vector)
        {
            if (index) {
                add_assoc_zval(&vectors, ZSTR_VAL(index), scan_vector);
                Z_TRY_ADDREF_P(scan_vector);
            }
        }
        ZEND_HASH_FOREACH_END();
        Z_TRY_ADDREF(vectors);
    }
    if (zend_hash_num_elements(Z_ARRVAL(control)) > 0) {
        add_assoc_zval(return_value, "ctl", &control);
    } else {
        zval_dtor(&control);
    }

    prop = pcbc_read_property(pcbc_search_options_ce, getThis(), ("collections"), 0, &ret);
    if (Z_TYPE_P(prop) != IS_NULL) {
        add_assoc_zval(return_value, "collections", prop);
        Z_TRY_ADDREF_P(prop);
    }
}

ZEND_BEGIN_ARG_WITH_TENTATIVE_RETURN_TYPE_INFO_EX(ai_SearchOptions_none, 0, 0, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchOptions_timeout, 0, 1, Couchbase\\SearchOptions, 0)
ZEND_ARG_TYPE_INFO(0, arg, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchOptions_limit, 0, 1, Couchbase\\SearchOptions, 0)
ZEND_ARG_TYPE_INFO(0, limit, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchOptions_skip, 0, 1, Couchbase\\SearchOptions, 0)
ZEND_ARG_TYPE_INFO(0, skip, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchOptions_explain, 0, 1, Couchbase\\SearchOptions, 0)
ZEND_ARG_TYPE_INFO(0, explain, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchOptions_disableScoring, 0, 1, Couchbase\\SearchOptions, 0)
ZEND_ARG_TYPE_INFO(0, disableScoring, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchOptions_consistentWith, 0, 1, Couchbase\\SearchOptions, 0)
ZEND_ARG_TYPE_INFO(0, index, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, state, Couchbase\\MutationState, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchOptions_fields, 0, 1, Couchbase\\SearchOptions, 0)
ZEND_ARG_TYPE_INFO(0, fields, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchOptions_facets, 0, 1, Couchbase\\SearchOptions, 0)
ZEND_ARG_TYPE_INFO(0, facets, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchOptions_sort, 0, 1, Couchbase\\SearchOptions, 0)
ZEND_ARG_TYPE_INFO(0, specs, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchOptions_highlight, 0, 1, Couchbase\\SearchOptions, 0)
ZEND_ARG_TYPE_INFO(0, style, IS_STRING, 1)
ZEND_ARG_TYPE_INFO(0, fields, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_SearchOptions_collections, 0, 1, Couchbase\\SearchOptions, 0)
ZEND_ARG_TYPE_INFO(0, collections, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry search_options_methods[] = {
    PHP_ME(SearchOptions, jsonSerialize, ai_SearchOptions_none, ZEND_ACC_PUBLIC)
    PHP_ME(SearchOptions, timeout, ai_SearchOptions_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(SearchOptions, limit, ai_SearchOptions_limit, ZEND_ACC_PUBLIC)
    PHP_ME(SearchOptions, skip, ai_SearchOptions_skip, ZEND_ACC_PUBLIC)
    PHP_ME(SearchOptions, explain, ai_SearchOptions_explain, ZEND_ACC_PUBLIC)
    PHP_ME(SearchOptions, disableScoring, ai_SearchOptions_disableScoring, ZEND_ACC_PUBLIC)
    PHP_ME(SearchOptions, consistentWith, ai_SearchOptions_consistentWith, ZEND_ACC_PUBLIC)
    PHP_ME(SearchOptions, fields, ai_SearchOptions_fields, ZEND_ACC_PUBLIC)
    PHP_ME(SearchOptions, facets, ai_SearchOptions_facets, ZEND_ACC_PUBLIC)
    PHP_ME(SearchOptions, sort, ai_SearchOptions_sort, ZEND_ACC_PUBLIC)
    PHP_ME(SearchOptions, highlight, ai_SearchOptions_highlight, ZEND_ACC_PUBLIC)
    PHP_ME(SearchOptions, collections, ai_SearchOptions_collections, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

zend_class_entry *pcbc_search_highlight_mode_ce;
static const zend_function_entry pcbc_search_highlight_mode_methods[] = {PHP_FE_END};

PHP_MINIT_FUNCTION(SearchOptions)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchOptions", search_options_methods);
    pcbc_search_options_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_search_options_ce, 1, pcbc_json_serializable_ce);

    zend_declare_property_null(pcbc_search_options_ce, ZEND_STRL("timeout"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_options_ce, ZEND_STRL("limit"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_options_ce, ZEND_STRL("skip"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_options_ce, ZEND_STRL("explain"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_options_ce, ZEND_STRL("consistent_with"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_options_ce, ZEND_STRL("fields"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_options_ce, ZEND_STRL("sort"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_options_ce, ZEND_STRL("facets"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_options_ce, ZEND_STRL("highlight_style"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_options_ce, ZEND_STRL("highlight_fields"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_options_ce, ZEND_STRL("disable_scoring"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_options_ce, ZEND_STRL("collections"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchHighlightMode", pcbc_search_highlight_mode_methods);
    pcbc_search_highlight_mode_ce = zend_register_internal_interface(&ce);
    zend_declare_class_constant_stringl(pcbc_search_highlight_mode_ce, ZEND_STRL("HTML"), ZEND_STRL("html"));
    zend_declare_class_constant_stringl(pcbc_search_highlight_mode_ce, ZEND_STRL("ANSI"), ZEND_STRL("ansi"));
    zend_declare_class_constant_stringl(pcbc_search_highlight_mode_ce, ZEND_STRL("SIMPLE"), ZEND_STRL("simple"));

    return SUCCESS;
}
