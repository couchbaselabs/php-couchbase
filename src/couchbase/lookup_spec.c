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

#define LOGARGS(builder, lvl) LCB_LOG_##lvl, builder->bucket->conn->lcb, "pcbc/lookup_in_spec", __FILE__, __LINE__

// clang-format off
zend_class_entry *pcbc_lookup_in_spec_ce;
static const zend_function_entry pcbc_lookup_in_spec_methods[] = {
    PHP_FE_END
};

PHP_METHOD(LookupGetSpec, __construct);

ZEND_BEGIN_ARG_INFO_EX(ai_LookupGetSpec_constructor, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, isXattr, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_lookup_get_spec_ce;
static const zend_function_entry pcbc_lookup_get_spec_methods[] = {
    PHP_ME(LookupGetSpec, __construct, ai_LookupGetSpec_constructor, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_FE_END
};

PHP_METHOD(LookupCountSpec, __construct);

ZEND_BEGIN_ARG_INFO_EX(ai_LookupCountSpec_constructor, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, isXattr, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_lookup_count_spec_ce;
static const zend_function_entry pcbc_lookup_count_spec_methods[] = {
    PHP_ME(LookupCountSpec, __construct, ai_LookupCountSpec_constructor, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_FE_END
};

PHP_METHOD(LookupExistsSpec, __construct);

ZEND_BEGIN_ARG_INFO_EX(ai_LookupExistsSpec_constructor, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, isXattr, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_lookup_exists_spec_ce;
static const zend_function_entry pcbc_lookup_exists_spec_methods[] = {
    PHP_ME(LookupExistsSpec, __construct, ai_LookupExistsSpec_constructor, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_FE_END
};

// clang-format on

PHP_MINIT_FUNCTION(LookupInSpec)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "LookupInSpec", pcbc_lookup_in_spec_methods);
    pcbc_lookup_in_spec_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "LookupGetSpec", pcbc_lookup_get_spec_methods);
    pcbc_lookup_get_spec_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_lookup_get_spec_ce, 1, pcbc_lookup_in_spec_ce);
    zend_declare_property_null(pcbc_lookup_get_spec_ce, ZEND_STRL("path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_lookup_get_spec_ce, ZEND_STRL("is_xattr"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "LookupCountSpec", pcbc_lookup_count_spec_methods);
    pcbc_lookup_count_spec_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_lookup_count_spec_ce, 1, pcbc_lookup_in_spec_ce);
    zend_declare_property_null(pcbc_lookup_count_spec_ce, ZEND_STRL("path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_lookup_count_spec_ce, ZEND_STRL("is_xattr"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "LookupExistsSpec", pcbc_lookup_exists_spec_methods);
    pcbc_lookup_exists_spec_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_lookup_exists_spec_ce, 1, pcbc_lookup_in_spec_ce);
    zend_declare_property_null(pcbc_lookup_exists_spec_ce, ZEND_STRL("path"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_lookup_exists_spec_ce, ZEND_STRL("is_xattr"), ZEND_ACC_PRIVATE);
    return SUCCESS;
}

PHP_METHOD(LookupGetSpec, __construct)
{
    zend_string *path;
    zend_bool is_xattr = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S|b", &path, &is_xattr);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_str(pcbc_lookup_get_spec_ce, getThis(), ("path"), path);
    pcbc_update_property_bool(pcbc_lookup_get_spec_ce, getThis(), ("is_xattr"), is_xattr);
}

PHP_METHOD(LookupCountSpec, __construct)
{
    zend_string *path;
    zend_bool is_xattr = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S|b", &path, &is_xattr);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_str(pcbc_lookup_count_spec_ce, getThis(), ("path"), path);
    pcbc_update_property_bool(pcbc_lookup_count_spec_ce, getThis(), ("is_xattr"), is_xattr);
}

PHP_METHOD(LookupExistsSpec, __construct)
{
    zend_string *path;
    zend_bool is_xattr = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "S|b", &path, &is_xattr);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    pcbc_update_property_str(pcbc_lookup_exists_spec_ce, getThis(), ("path"), path);
    pcbc_update_property_bool(pcbc_lookup_exists_spec_ce, getThis(), ("is_xattr"), is_xattr);
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
