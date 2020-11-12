/**
 *     Copyright 2015-2019 Couchbase, Inc.
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

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/mutate_in_spec", __FILE__, __LINE__

// clang-format off
zend_class_entry *pcbc_mutate_in_spec_ce;
static const zend_function_entry pcbc_mutate_in_spec_methods[] = {
    PHP_FE_END
};

PHP_METHOD(MutateInsertSpec, __construct);

ZEND_BEGIN_ARG_INFO_EX(ai_MutateInsertSpec_constructor, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_ARG_INFO(0, value)
ZEND_ARG_TYPE_INFO(0, isXattr, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, createPath, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, expandMacros, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_mutate_insert_spec_ce;
static const zend_function_entry pcbc_mutate_insert_spec_methods[] = {
    PHP_ME(MutateInsertSpec, __construct, ai_MutateInsertSpec_constructor, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_FE_END
};

PHP_METHOD(MutateUpsertSpec, __construct);

ZEND_BEGIN_ARG_INFO_EX(ai_MutateUpsertSpec_constructor, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_ARG_INFO(0, value)
ZEND_ARG_TYPE_INFO(0, isXattr, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, createPath, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, expandMacros, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_mutate_upsert_spec_ce;
static const zend_function_entry pcbc_mutate_upsert_spec_methods[] = {
    PHP_ME(MutateUpsertSpec, __construct, ai_MutateUpsertSpec_constructor, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_FE_END
};

PHP_METHOD(MutateReplaceSpec, __construct);

ZEND_BEGIN_ARG_INFO_EX(ai_MutateReplaceSpec_constructor, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_ARG_INFO(0, value)
ZEND_ARG_TYPE_INFO(0, isXattr, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, expandMacros, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_mutate_replace_spec_ce;
static const zend_function_entry pcbc_mutate_replace_spec_methods[] = {
    PHP_ME(MutateReplaceSpec, __construct, ai_MutateReplaceSpec_constructor, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_FE_END
};

PHP_METHOD(MutateRemoveSpec, __construct);

ZEND_BEGIN_ARG_INFO_EX(ai_MutateRemoveSpec_constructor, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, isXattr, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_mutate_remove_spec_ce;
static const zend_function_entry pcbc_mutate_remove_spec_methods[] = {
    PHP_ME(MutateRemoveSpec, __construct, ai_MutateRemoveSpec_constructor, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_FE_END
};

PHP_METHOD(MutateArrayAppendSpec, __construct);

ZEND_BEGIN_ARG_INFO_EX(ai_MutateArrayAppendSpec_constructor, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, values, IS_ARRAY, 0)
ZEND_ARG_TYPE_INFO(0, isXattr, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, createPath, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, expandMacros, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_mutate_array_append_spec_ce;
static const zend_function_entry pcbc_mutate_array_append_spec_methods[] = {
    PHP_ME(MutateArrayAppendSpec, __construct, ai_MutateArrayAppendSpec_constructor, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_FE_END
};


PHP_METHOD(MutateArrayPrependSpec, __construct);

ZEND_BEGIN_ARG_INFO_EX(ai_MutateArrayPrependSpec_constructor, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, values, IS_ARRAY, 0)
ZEND_ARG_TYPE_INFO(0, isXattr, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, createPath, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, expandMacros, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_mutate_array_prepend_spec_ce;
static const zend_function_entry pcbc_mutate_array_prepend_spec_methods[] = {
    PHP_ME(MutateArrayPrependSpec, __construct, ai_MutateArrayPrependSpec_constructor, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_FE_END
};

PHP_METHOD(MutateArrayInsertSpec, __construct);

ZEND_BEGIN_ARG_INFO_EX(ai_MutateArrayInsertSpec_constructor, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, values, IS_ARRAY, 0)
ZEND_ARG_TYPE_INFO(0, isXattr, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, createPath, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, expandMacros, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_mutate_array_insert_spec_ce;
static const zend_function_entry pcbc_mutate_array_insert_spec_methods[] = {
    PHP_ME(MutateArrayInsertSpec, __construct, ai_MutateArrayInsertSpec_constructor, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_FE_END
};

PHP_METHOD(MutateArrayAddUniqueSpec, __construct);

ZEND_BEGIN_ARG_INFO_EX(ai_MutateArrayAddUniqueSpec_constructor, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_ARG_INFO(0, value)
ZEND_ARG_TYPE_INFO(0, isXattr, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, createPath, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, expandMacros, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_mutate_array_add_unique_spec_ce;
static const zend_function_entry pcbc_mutate_array_add_unique_spec_methods[] = {
    PHP_ME(MutateArrayAddUniqueSpec, __construct, ai_MutateArrayAddUniqueSpec_constructor, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_FE_END
};


PHP_METHOD(MutateCounterSpec, __construct);

ZEND_BEGIN_ARG_INFO_EX(ai_MutateCounterSpec_constructor, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, delta, IS_LONG, 0)
ZEND_ARG_TYPE_INFO(0, isXattr, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, createPath, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_mutate_counter_spec_ce;
static const zend_function_entry pcbc_mutate_counter_spec_methods[] = {
    PHP_ME(MutateCounterSpec, __construct, ai_MutateCounterSpec_constructor, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_FE_END
};

// clang-format on

PHP_MINIT_FUNCTION(MutateInSpec)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutateInSpec", pcbc_mutate_in_spec_methods);
    pcbc_mutate_in_spec_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutateInsertSpec", pcbc_mutate_insert_spec_methods);
    pcbc_mutate_insert_spec_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_mutate_insert_spec_ce, 1, pcbc_mutate_in_spec_ce);
    zend_declare_property_null(pcbc_mutate_insert_spec_ce, ZEND_STRL("path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_insert_spec_ce, ZEND_STRL("value"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_insert_spec_ce, ZEND_STRL("is_xattr"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_insert_spec_ce, ZEND_STRL("create_path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_insert_spec_ce, ZEND_STRL("expand_macros"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutateUpsertSpec", pcbc_mutate_upsert_spec_methods);
    pcbc_mutate_upsert_spec_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_mutate_upsert_spec_ce, 1, pcbc_mutate_in_spec_ce);
    zend_declare_property_null(pcbc_mutate_upsert_spec_ce, ZEND_STRL("path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_upsert_spec_ce, ZEND_STRL("value"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_upsert_spec_ce, ZEND_STRL("is_xattr"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_upsert_spec_ce, ZEND_STRL("create_path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_upsert_spec_ce, ZEND_STRL("expand_macros"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutateReplaceSpec", pcbc_mutate_replace_spec_methods);
    pcbc_mutate_replace_spec_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_mutate_replace_spec_ce, 1, pcbc_mutate_in_spec_ce);
    zend_declare_property_null(pcbc_mutate_replace_spec_ce, ZEND_STRL("path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_replace_spec_ce, ZEND_STRL("value"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_replace_spec_ce, ZEND_STRL("is_xattr"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_replace_spec_ce, ZEND_STRL("expand_macros"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutateRemoveSpec", pcbc_mutate_remove_spec_methods);
    pcbc_mutate_remove_spec_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_mutate_remove_spec_ce, 1, pcbc_mutate_in_spec_ce);
    zend_declare_property_null(pcbc_mutate_remove_spec_ce, ZEND_STRL("path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_remove_spec_ce, ZEND_STRL("is_xattr"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutateArrayAppendSpec", pcbc_mutate_array_append_spec_methods);
    pcbc_mutate_array_append_spec_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_mutate_array_append_spec_ce, 1, pcbc_mutate_in_spec_ce);
    zend_declare_property_null(pcbc_mutate_array_append_spec_ce, ZEND_STRL("path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_append_spec_ce, ZEND_STRL("values"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_append_spec_ce, ZEND_STRL("is_xattr"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_append_spec_ce, ZEND_STRL("create_path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_append_spec_ce, ZEND_STRL("expand_macros"),
                               ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutateArrayPrependSpec", pcbc_mutate_array_prepend_spec_methods);
    pcbc_mutate_array_prepend_spec_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_mutate_array_prepend_spec_ce, 1, pcbc_mutate_in_spec_ce);
    zend_declare_property_null(pcbc_mutate_array_prepend_spec_ce, ZEND_STRL("path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_prepend_spec_ce, ZEND_STRL("values"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_prepend_spec_ce, ZEND_STRL("is_xattr"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_prepend_spec_ce, ZEND_STRL("create_path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_prepend_spec_ce, ZEND_STRL("expand_macros"),
                               ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutateArrayInsertSpec", pcbc_mutate_array_insert_spec_methods);
    pcbc_mutate_array_insert_spec_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_mutate_array_insert_spec_ce, 1, pcbc_mutate_in_spec_ce);
    zend_declare_property_null(pcbc_mutate_array_insert_spec_ce, ZEND_STRL("path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_insert_spec_ce, ZEND_STRL("values"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_insert_spec_ce, ZEND_STRL("is_xattr"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_insert_spec_ce, ZEND_STRL("create_path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_insert_spec_ce, ZEND_STRL("expand_macros"),
                               ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutateArrayAddUniqueSpec", pcbc_mutate_array_add_unique_spec_methods);
    pcbc_mutate_array_add_unique_spec_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_mutate_array_add_unique_spec_ce, 1, pcbc_mutate_in_spec_ce);
    zend_declare_property_null(pcbc_mutate_array_add_unique_spec_ce, ZEND_STRL("path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_add_unique_spec_ce, ZEND_STRL("value"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_add_unique_spec_ce, ZEND_STRL("is_xattr"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_add_unique_spec_ce, ZEND_STRL("create_path"),
                               ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_array_add_unique_spec_ce, ZEND_STRL("expand_macros"),
                               ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutateCounterSpec", pcbc_mutate_counter_spec_methods);
    pcbc_mutate_counter_spec_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_mutate_counter_spec_ce, 1, pcbc_mutate_in_spec_ce);
    zend_declare_property_null(pcbc_mutate_counter_spec_ce, ZEND_STRL("path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_counter_spec_ce, ZEND_STRL("delta"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_counter_spec_ce, ZEND_STRL("is_xattr"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_counter_spec_ce, ZEND_STRL("create_path"), ZEND_ACC_PRIVATE);
    return SUCCESS;
}

PHP_METHOD(MutateInsertSpec, __construct)
{
    zend_string *path;
    zval *value;
    zend_bool is_xattr = 0, create_path = 0, expand_macros = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sz|bbb", &path, &value, &is_xattr, &create_path,
                                         &expand_macros);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_str(pcbc_mutate_insert_spec_ce, getThis(), ("path"), path);
    pcbc_update_property_bool(pcbc_mutate_insert_spec_ce, getThis(), ("is_xattr"), is_xattr);
    pcbc_update_property_bool(pcbc_mutate_insert_spec_ce, getThis(), ("create_path"), create_path);
    pcbc_update_property_bool(pcbc_mutate_insert_spec_ce, getThis(), ("expand_macros"),
                              expand_macros);
    {
        smart_str buf = {0};
        int last_error;
        PCBC_JSON_ENCODE(&buf, value, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(WARN), "Failed to encode value as JSON: json_last_error=%d", last_error);
            smart_str_free(&buf);
            RETURN_NULL();
        }
        smart_str_0(&buf);
        pcbc_update_property_str(pcbc_mutate_insert_spec_ce, getThis(), ("value"), buf.s);
        smart_str_free(&buf);
    }
}

PHP_METHOD(MutateUpsertSpec, __construct)
{
    zend_string *path;
    zval *value;
    zend_bool is_xattr = 0, create_path = 0, expand_macros = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sz|bbb", &path, &value, &is_xattr, &create_path,
                                         &expand_macros);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_str(pcbc_mutate_upsert_spec_ce, getThis(), ("path"), path);
    pcbc_update_property_bool(pcbc_mutate_upsert_spec_ce, getThis(), ("is_xattr"), is_xattr);
    pcbc_update_property_bool(pcbc_mutate_upsert_spec_ce, getThis(), ("create_path"), create_path);
    pcbc_update_property_bool(pcbc_mutate_upsert_spec_ce, getThis(), ("expand_macros"),
                              expand_macros);
    {
        smart_str buf = {0};
        int last_error;
        PCBC_JSON_ENCODE(&buf, value, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(WARN), "Failed to encode value as JSON: json_last_error=%d", last_error);
            smart_str_free(&buf);
            RETURN_NULL();
        }
        smart_str_0(&buf);
        pcbc_update_property_str(pcbc_mutate_upsert_spec_ce, getThis(), ("value"), buf.s);
        smart_str_free(&buf);
    }
}

PHP_METHOD(MutateReplaceSpec, __construct)
{
    zend_string *path;
    zval *value;
    zend_bool is_xattr = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sz|b", &path, &value, &is_xattr);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_str(pcbc_mutate_replace_spec_ce, getThis(), ("path"), path);
    pcbc_update_property_bool(pcbc_mutate_replace_spec_ce, getThis(), ("is_xattr"), is_xattr);
    pcbc_update_property_bool(pcbc_mutate_replace_spec_ce, getThis(), ("expand_macros"), is_xattr);
    {
        smart_str buf = {0};
        int last_error;
        PCBC_JSON_ENCODE(&buf, value, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(WARN), "Failed to encode value as JSON: json_last_error=%d", last_error);
            smart_str_free(&buf);
            RETURN_NULL();
        }
        smart_str_0(&buf);
        pcbc_update_property_str(pcbc_mutate_replace_spec_ce, getThis(), ("value"), buf.s);
        smart_str_free(&buf);
    }
}

PHP_METHOD(MutateRemoveSpec, __construct)
{
    zend_string *path;
    zend_bool is_xattr = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S|b", &path, &is_xattr);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_str(pcbc_mutate_remove_spec_ce, getThis(), ("path"), path);
    pcbc_update_property_bool(pcbc_mutate_remove_spec_ce, getThis(), ("is_xattr"), is_xattr);
}

PHP_METHOD(MutateArrayAppendSpec, __construct)
{
    zend_string *path;
    zval *value;
    zend_bool is_xattr = 0, create_path = 0, expand_macros = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sa|bbb", &path, &value, &is_xattr, &create_path,
                                         &expand_macros);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_str(pcbc_mutate_array_append_spec_ce, getThis(), ("path"), path);
    pcbc_update_property_bool(pcbc_mutate_array_append_spec_ce, getThis(), ("is_xattr"), is_xattr);
    pcbc_update_property_bool(pcbc_mutate_array_append_spec_ce, getThis(), ("create_path"),
                              create_path);
    pcbc_update_property_bool(pcbc_mutate_array_append_spec_ce, getThis(), ("expand_macros"),
                              expand_macros);
    {
        smart_str buf = {0};
        int last_error;
        PCBC_JSON_ENCODE(&buf, value, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(WARN), "Failed to encode value as JSON: json_last_error=%d", last_error);
            smart_str_free(&buf);
            RETURN_NULL();
        }
        smart_str_0(&buf);
        pcbc_update_property_stringl(pcbc_mutate_array_append_spec_ce, getThis(), ("value"),
                                     ZSTR_VAL(buf.s) + 1, ZSTR_LEN(buf.s) - 2);
        smart_str_free(&buf);
    }
}

PHP_METHOD(MutateArrayPrependSpec, __construct)
{
    zend_string *path;
    zval *value;
    zend_bool is_xattr = 0, create_path = 0, expand_macros = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sa|bbb", &path, &value, &is_xattr, &create_path,
                                         &expand_macros);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_str(pcbc_mutate_array_prepend_spec_ce, getThis(), ("path"), path);
    pcbc_update_property_bool(pcbc_mutate_array_prepend_spec_ce, getThis(), ("is_xattr"), is_xattr);
    pcbc_update_property_bool(pcbc_mutate_array_prepend_spec_ce, getThis(), ("create_path"),
                              create_path);
    pcbc_update_property_bool(pcbc_mutate_array_prepend_spec_ce, getThis(), ("expand_macros"),
                              expand_macros);
    {
        smart_str buf = {0};
        int last_error;
        PCBC_JSON_ENCODE(&buf, value, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(WARN), "Failed to encode value as JSON: json_last_error=%d", last_error);
            smart_str_free(&buf);
            RETURN_NULL();
        }
        smart_str_0(&buf);
        pcbc_update_property_stringl(pcbc_mutate_array_prepend_spec_ce, getThis(), ("value"),
                                     ZSTR_VAL(buf.s) + 1, ZSTR_LEN(buf.s) - 2);
        smart_str_free(&buf);
    }
}

PHP_METHOD(MutateArrayInsertSpec, __construct)
{
    zend_string *path;
    zval *value;
    zend_bool is_xattr = 0, create_path = 0, expand_macros = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sa|bbb", &path, &value, &is_xattr, &create_path,
                                         &expand_macros);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_str(pcbc_mutate_array_insert_spec_ce, getThis(), ("path"), path);
    pcbc_update_property_bool(pcbc_mutate_array_insert_spec_ce, getThis(), ("is_xattr"), is_xattr);
    pcbc_update_property_bool(pcbc_mutate_array_insert_spec_ce, getThis(), ("create_path"),
                              create_path);
    pcbc_update_property_bool(pcbc_mutate_array_insert_spec_ce, getThis(), ("expand_macros"),
                              expand_macros);
    {
        smart_str buf = {0};
        int last_error;
        PCBC_JSON_ENCODE(&buf, value, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(WARN), "Failed to encode value as JSON: json_last_error=%d", last_error);
            smart_str_free(&buf);
            RETURN_NULL();
        }
        smart_str_0(&buf);
        pcbc_update_property_stringl(pcbc_mutate_array_insert_spec_ce, getThis(), ("value"),
                                     ZSTR_VAL(buf.s) + 1, ZSTR_LEN(buf.s) - 2);
        smart_str_free(&buf);
    }
}

PHP_METHOD(MutateArrayAddUniqueSpec, __construct)
{
    zend_string *path;
    zval *value;
    zend_bool is_xattr = 0, create_path = 0, expand_macros = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sz|bbb", &path, &value, &is_xattr, &create_path,
                                         &expand_macros);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_str(pcbc_mutate_array_add_unique_spec_ce, getThis(), ("path"), path);
    pcbc_update_property_bool(pcbc_mutate_array_add_unique_spec_ce, getThis(), ("is_xattr"),
                              is_xattr);
    pcbc_update_property_bool(pcbc_mutate_array_add_unique_spec_ce, getThis(), ("create_path"),
                              create_path);
    pcbc_update_property_bool(pcbc_mutate_array_add_unique_spec_ce, getThis(), ("expand_macros"),
                              expand_macros);
    {
        smart_str buf = {0};
        int last_error;
        PCBC_JSON_ENCODE(&buf, value, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(WARN), "Failed to encode value as JSON: json_last_error=%d", last_error);
            smart_str_free(&buf);
            RETURN_NULL();
        }
        smart_str_0(&buf);
        pcbc_update_property_str(pcbc_mutate_array_add_unique_spec_ce, getThis(), ("value"), buf.s);
        smart_str_free(&buf);
    }
}

PHP_METHOD(MutateCounterSpec, __construct)
{
    zend_string *path;
    zend_long delta;
    zend_bool is_xattr = 0, create_path = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "Sl|bb", &path, &delta, &is_xattr, &create_path);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_str(pcbc_mutate_counter_spec_ce, getThis(), ("path"), path);
    pcbc_update_property_long(pcbc_mutate_counter_spec_ce, getThis(), ("delta"), delta);
    pcbc_update_property_bool(pcbc_mutate_counter_spec_ce, getThis(), ("is_xattr"), is_xattr);
    pcbc_update_property_bool(pcbc_mutate_counter_spec_ce, getThis(), ("create_path"), create_path);
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
