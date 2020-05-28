/**
 *     Copyright 2019 Couchbase, Inc.
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

zend_class_entry *pcbc_cluster_options_ce;

PHP_METHOD(ClusterOptions, credentials)
{
    zend_string *username, *password;
    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "SS", &username, &password);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    zend_update_property_str(pcbc_cluster_options_ce, getThis(), ZEND_STRL("username"), username TSRMLS_CC);
    zend_update_property_str(pcbc_cluster_options_ce, getThis(), ZEND_STRL("password"), password TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_ClusterOptions_credentials, 0, 1, Couchbase\\ClusterOptions, 0)
ZEND_ARG_TYPE_INFO(0, username, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry cluster_options_methods[] = {
    PHP_ME(ClusterOptions,credentials, ai_ClusterOptions_credentials, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(ClusterOptions)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ClusterOptions", cluster_options_methods);
    pcbc_cluster_options_ce = zend_register_internal_class(&ce TSRMLS_CC);

    zend_declare_property_null(pcbc_cluster_options_ce, ZEND_STRL("username"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_cluster_options_ce, ZEND_STRL("password"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}
