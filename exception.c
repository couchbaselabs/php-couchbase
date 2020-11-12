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
#include <libcouchbase/couchbase.h>

zend_class_entry *pcbc_default_exception_ce;
zend_class_entry *pcbc_base_exception_ce;

static void pcbc_exception_make(zval *return_value, zend_class_entry *exception_ce, long code,
                                const char *message)
{
    object_init_ex(return_value, pcbc_base_exception_ce);

    if (message) {
        zend_update_property_string(pcbc_base_exception_ce, return_value, ZEND_STRL("message"), message);
    }
    if (code) {
        zend_update_property_long(pcbc_base_exception_ce, return_value, ZEND_STRL("code"), code);
    }
}

void pcbc_exception_init(zval *return_value, long code, const char *message)
{
    pcbc_exception_make(return_value, pcbc_base_exception_ce, code, message);
}

zend_class_entry *pcbc_http_exception_ce;
zend_class_entry *pcbc_query_exception_ce;
zend_class_entry *pcbc_query_error_exception_ce;
zend_class_entry *pcbc_query_service_exception_ce;
zend_class_entry *pcbc_search_exception_ce;
zend_class_entry *pcbc_analytics_exception_ce;
zend_class_entry *pcbc_view_exception_ce;
zend_class_entry *pcbc_partial_view_exception_ce;
zend_class_entry *pcbc_bindings_exception_ce;
zend_class_entry *pcbc_invalid_state_exception_ce;
zend_class_entry *pcbc_key_value_exception_ce;
zend_class_entry *pcbc_key_not_found_exception_ce;
zend_class_entry *pcbc_key_exists_exception_ce;
zend_class_entry *pcbc_value_too_big_exception_ce;
zend_class_entry *pcbc_key_locked_exception_ce;
zend_class_entry *pcbc_temp_fail_exception_ce;
zend_class_entry *pcbc_path_not_found_exception_ce;
zend_class_entry *pcbc_path_exists_exception_ce;
zend_class_entry *pcbc_invalid_range_exception_ce;
zend_class_entry *pcbc_key_deleted_exception_ce;
zend_class_entry *pcbc_cas_mismatch_exception_ce;
zend_class_entry *pcbc_invalid_configuration_exception_ce;
zend_class_entry *pcbc_service_missing_exception_ce;
zend_class_entry *pcbc_network_exception_ce;
zend_class_entry *pcbc_timeout_exception_ce;
zend_class_entry *pcbc_bucket_missing_exception_ce;
zend_class_entry *pcbc_scope_missing_exception_ce;
zend_class_entry *pcbc_collection_missing_exception_ce;
zend_class_entry *pcbc_authentication_exception_ce;
zend_class_entry *pcbc_bad_input_exception_ce;
zend_class_entry *pcbc_durability_exception_ce;
zend_class_entry *pcbc_subdocument_exception_ce;

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BaseException_ref, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_BaseException_context, IS_OBJECT, 1)
ZEND_END_ARG_INFO()

PHP_METHOD(BaseException, ref);
PHP_METHOD(BaseException, context);

// clang-format off
static const zend_function_entry pcbc_base_exception_methods[] = {
    PHP_ME(BaseException, ref, ai_BaseException_ref, ZEND_ACC_PUBLIC)
    PHP_ME(BaseException, context, ai_BaseException_context, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(CouchbaseException)
{
    zend_class_entry ce;
    pcbc_default_exception_ce = (zend_class_entry *)zend_exception_get_default();

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "BaseException", pcbc_base_exception_methods);
    pcbc_base_exception_ce = zend_register_internal_class_ex(&ce, pcbc_default_exception_ce);
    zend_declare_property_null(pcbc_base_exception_ce, ZEND_STRL("ref"), ZEND_ACC_PROTECTED);
    zend_declare_property_null(pcbc_base_exception_ce, ZEND_STRL("context"), ZEND_ACC_PROTECTED);
    zend_declare_property_null(pcbc_base_exception_ce, ZEND_STRL("is_input"), ZEND_ACC_PROTECTED);
    zend_declare_property_null(pcbc_base_exception_ce, ZEND_STRL("is_network"), ZEND_ACC_PROTECTED);
    zend_declare_property_null(pcbc_base_exception_ce, ZEND_STRL("is_fatal"), ZEND_ACC_PROTECTED);
    zend_declare_property_null(pcbc_base_exception_ce, ZEND_STRL("is_transient"), ZEND_ACC_PROTECTED);
    zend_declare_property_null(pcbc_base_exception_ce, ZEND_STRL("is_data_operation"), ZEND_ACC_PROTECTED);
    zend_declare_property_null(pcbc_base_exception_ce, ZEND_STRL("is_internal"), ZEND_ACC_PROTECTED);
    zend_declare_property_null(pcbc_base_exception_ce, ZEND_STRL("is_plugin"), ZEND_ACC_PROTECTED);
    zend_declare_property_null(pcbc_base_exception_ce, ZEND_STRL("is_server_under_load"), ZEND_ACC_PROTECTED);
    zend_declare_property_null(pcbc_base_exception_ce, ZEND_STRL("is_server_generated"), ZEND_ACC_PROTECTED);
    zend_declare_property_null(pcbc_base_exception_ce, ZEND_STRL("is_subdoc"), ZEND_ACC_PROTECTED);
    zend_declare_property_null(pcbc_base_exception_ce, ZEND_STRL("is_durability"), ZEND_ACC_PROTECTED);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "HttpException", NULL);
    pcbc_http_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "QueryException", NULL);
    pcbc_query_exception_ce = zend_register_internal_class_ex(&ce, pcbc_http_exception_ce);
    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "QueryErrorException", NULL);
    pcbc_query_error_exception_ce = zend_register_internal_class_ex(&ce, pcbc_query_exception_ce);
    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "QueryServiceException", NULL);
    pcbc_query_service_exception_ce = zend_register_internal_class_ex(&ce, pcbc_query_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchException", NULL);
    pcbc_search_exception_ce = zend_register_internal_class_ex(&ce, pcbc_http_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "AnalyticsException", NULL);
    pcbc_analytics_exception_ce = zend_register_internal_class_ex(&ce, pcbc_http_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ViewException", NULL);
    pcbc_view_exception_ce = zend_register_internal_class_ex(&ce, pcbc_http_exception_ce);
    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "PartialViewException", NULL);
    pcbc_partial_view_exception_ce = zend_register_internal_class_ex(&ce, pcbc_view_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "BindingsException", NULL);
    pcbc_bindings_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "InvalidStateException", NULL);
    pcbc_invalid_state_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "KeyValueException", NULL);
    pcbc_key_value_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);
    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DocumentNotFoundException", NULL);
    pcbc_key_not_found_exception_ce = zend_register_internal_class_ex(&ce, pcbc_key_value_exception_ce);
    zend_register_class_alias("Couchbase\\KeyNotFoundException", pcbc_key_not_found_exception_ce);
    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "KeyExistsException", NULL);
    pcbc_key_exists_exception_ce = zend_register_internal_class_ex(&ce, pcbc_key_value_exception_ce);
    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ValueTooBigException", NULL);
    pcbc_value_too_big_exception_ce = zend_register_internal_class_ex(&ce, pcbc_key_value_exception_ce);
    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "KeyLockedException", NULL);
    pcbc_key_locked_exception_ce = zend_register_internal_class_ex(&ce, pcbc_key_value_exception_ce);
    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "TempFailException", NULL);
    pcbc_temp_fail_exception_ce = zend_register_internal_class_ex(&ce, pcbc_key_value_exception_ce);
    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "PathNotFoundException", NULL);
    pcbc_path_not_found_exception_ce = zend_register_internal_class_ex(&ce, pcbc_key_value_exception_ce);
    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "PathExistsException", NULL);
    pcbc_path_exists_exception_ce = zend_register_internal_class_ex(&ce, pcbc_key_value_exception_ce);
    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "InvalidRangeException", NULL);
    pcbc_invalid_range_exception_ce = zend_register_internal_class_ex(&ce, pcbc_key_value_exception_ce);
    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "KeyDeletedException", NULL);
    pcbc_key_deleted_exception_ce = zend_register_internal_class_ex(&ce, pcbc_key_value_exception_ce);
    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "CasMismatchException", NULL);
    pcbc_cas_mismatch_exception_ce = zend_register_internal_class_ex(&ce, pcbc_key_value_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "InvalidConfigurationException", NULL);
    pcbc_invalid_configuration_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ServiceMissingException", NULL);
    pcbc_service_missing_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "NetworkException", NULL);
    pcbc_network_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "TimeoutException", NULL);
    pcbc_timeout_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "BucketMissingException", NULL);
    pcbc_bucket_missing_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ScopeMissingException", NULL);
    pcbc_scope_missing_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "CollectionMissingException", NULL);
    pcbc_collection_missing_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "AuthenticationException", NULL);
    pcbc_authentication_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "BadInputException", NULL);
    pcbc_bad_input_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DurabilityException", NULL);
    pcbc_durability_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SubdocumentException", NULL);
    pcbc_subdocument_exception_ce = zend_register_internal_class_ex(&ce, pcbc_base_exception_ce);

    return SUCCESS;
}

void pcbc_create_lcb_exception(zval *return_value, long code, zend_string *context, zend_string *ref, int http_code,
                               const char *http_msg, int opcode)
{
    zend_class_entry *exc_ce = NULL;

    switch (code) {
    case LCB_SUCCESS:
        return;

    case LCB_ERR_AUTH_CONTINUE:
    case LCB_ERR_AUTHENTICATION_FAILURE:
        exc_ce = pcbc_authentication_exception_ce;
        break;

    case LCB_ERR_DOCUMENT_EXISTS:
        switch (opcode) {
        case PCBC_OPCODE_DELETE:
        case PCBC_OPCODE_REPLACE:
            exc_ce = pcbc_cas_mismatch_exception_ce;
            break;
        default:
            exc_ce = pcbc_key_exists_exception_ce;
        }
        break;

    case LCB_ERR_DOCUMENT_LOCKED:
        if (opcode == PCBC_OPCODE_UNLOCK) {
            exc_ce = pcbc_cas_mismatch_exception_ce;
        } else {
            exc_ce = pcbc_key_exists_exception_ce;
        }
        break;

    case LCB_ERR_DOCUMENT_NOT_FOUND:
        exc_ce = pcbc_key_not_found_exception_ce;
        break;

    case LCB_ERR_VALUE_TOO_LARGE:
        exc_ce = pcbc_value_too_big_exception_ce;
        break;

    case LCB_ERR_TEMPORARY_FAILURE:
    case LCB_ERR_BUSY:
    case LCB_ERR_MAP_CHANGED:
        exc_ce = pcbc_temp_fail_exception_ce;
        break;

    case LCB_ERR_SUBDOC_PATH_NOT_FOUND:
        exc_ce = pcbc_path_not_found_exception_ce;
        break;

    case LCB_ERR_SUBDOC_PATH_EXISTS:
        exc_ce = pcbc_path_exists_exception_ce;
        break;

    case LCB_ERR_SUBDOC_PATH_MISMATCH:
    case LCB_ERR_SUBDOC_PATH_TOO_BIG:
    case LCB_ERR_SUBDOC_PATH_TOO_DEEP:
    case LCB_ERR_SUBDOC_VALUE_INVALID:
    case LCB_ERR_SUBDOC_DOCUMENT_NOT_JSON:
    case LCB_ERR_SUBDOC_VALUE_TOO_DEEP:
    case LCB_ERR_SUBDOC_XATTR_INVALID_FLAG_COMBO:
    case LCB_ERR_SUBDOC_XATTR_INVALID_KEY_COMBO:
    case LCB_ERR_SUBDOC_XATTR_UNKNOWN_MACRO:
    case LCB_ERR_SUBDOC_XATTR_UNKNOWN_VIRTUAL_ATTRIBUTE:
    case LCB_ERR_SUBDOC_XATTR_CANNOT_MODIFY_VIRTUAL_ATTRIBUTE:
    case LCB_ERR_SUBDOC_XATTR_INVALID_ORDER:
        exc_ce = pcbc_subdocument_exception_ce;
        break;

    case LCB_ERR_INVALID_CHAR:
    case LCB_ERR_INVALID_ARGUMENT:
    case LCB_ERR_UNKNOWN_SUBDOC_COMMAND:
    case LCB_ERR_EMPTY_KEY:
    case LCB_ERR_OPTIONS_CONFLICT:
    case LCB_ERR_SUBDOC_PATH_INVALID:
        exc_ce = pcbc_bad_input_exception_ce;
        break;

    case LCB_ERR_UNSUPPORTED_OPERATION:
    case LCB_ERR_PROTOCOL_ERROR:
    case LCB_ERR_GENERIC:
    case LCB_ERR_INTERNAL_SERVER_FAILURE:
    case LCB_ERR_CONTROL_UNKNOWN_CODE:
    case LCB_ERR_CONTROL_INVALID_ARGUMENT:
    case LCB_ERR_CONTROL_UNSUPPORTED_MODE:
    case LCB_ERR_NOT_STORED:
        exc_ce = pcbc_invalid_state_exception_ce;
        break;

    case LCB_ERR_DLOPEN_FAILED:
    case LCB_ERR_DLSYM_FAILED:
    case LCB_ERR_NO_MEMORY:
    case LCB_ERR_DUPLICATE_COMMANDS:
    case LCB_ERR_PLUGIN_VERSION_MISMATCH:
    case LCB_ERR_NOT_MY_VBUCKET:
    case LCB_ERR_BAD_ENVIRONMENT:
    case LCB_ERR_INCOMPLETE_PACKET:
    case LCB_ERR_SDK_INTERNAL:
    case LCB_ERR_KVENGINE_UNKNOWN_ERROR:
    case LCB_ERR_NO_COMMANDS:
        exc_ce = pcbc_bindings_exception_ce;
        break;

    case LCB_ERR_BUCKET_NOT_FOUND:
        exc_ce = pcbc_bucket_missing_exception_ce;
        break;

    case LCB_ERR_INVALID_DELTA:
    case LCB_ERR_INVALID_RANGE:
    case LCB_ERR_SUBDOC_DELTA_INVALID:
        exc_ce = pcbc_invalid_range_exception_ce;
        break;

    case LCB_ERR_CONNECTION_REFUSED:
    case LCB_ERR_SOCKET_SHUTDOWN:
    case LCB_ERR_CONNECTION_RESET:
    case LCB_ERR_CANNOT_GET_PORT:
    case LCB_ERR_FD_LIMIT_REACHED:
    case LCB_ERR_NODE_UNREACHABLE:
    case LCB_ERR_NETWORK:
    case LCB_ERR_CONNECT_ERROR:
    case LCB_ERR_UNKNOWN_HOST:
    case LCB_ERR_SSL_ERROR:
    case LCB_ERR_SSL_CANTVERIFY:
    case LCB_ERR_SSL_INVALID_CIPHERSUITES:
    case LCB_ERR_SSL_NO_CIPHERS:
    case LCB_ERR_NAMESERVER:
    case LCB_ERR_TOO_MANY_REDIRECTS:
        exc_ce = pcbc_network_exception_ce;
        break;

    case LCB_ERR_COLLECTION_NOT_FOUND:
    case LCB_ERR_SCOPE_NOT_FOUND:
        exc_ce = pcbc_collection_missing_exception_ce;
        break;

    case LCB_ERR_NO_CONFIGURATION:
    case LCB_ERR_CONFIG_CACHE_INVALID:
    case LCB_ERR_SDK_FEATURE_UNAVAILABLE:
    case LCB_ERR_COLLECTION_NO_MANIFEST:
    case LCB_ERR_COLLECTION_CANNOT_APPLY_MANIFEST:
    case LCB_ERR_COLLECTION_MANIFEST_IS_AHEAD:
        exc_ce = pcbc_invalid_configuration_exception_ce;
        break;

    case LCB_ERR_DURABILITY_TOO_MANY:
    case LCB_ERR_NO_MATCHING_SERVER:
    case LCB_ERR_MUTATION_LOST:
    case LCB_ERR_DURABILITY_NO_MUTATION_TOKENS:
    case LCB_ERR_DURABILITY_LEVEL_NOT_AVAILABLE:
    case LCB_ERR_DURABILITY_IMPOSSIBLE:
    case LCB_ERR_DURABLE_WRITE_IN_PROGRESS:
    case LCB_ERR_DURABLE_WRITE_RE_COMMIT_IN_PROGRESS:
    case LCB_ERR_DURABILITY_AMBIGUOUS:
        exc_ce = pcbc_durability_exception_ce;
        break;

    case LCB_ERR_TIMEOUT:
    case LCB_ERR_AMBIGUOUS_TIMEOUT:
    case LCB_ERR_UNAMBIGUOUS_TIMEOUT:
        exc_ce = pcbc_timeout_exception_ce;
        break;

    case LCB_ERR_HTTP:
        exc_ce = pcbc_http_exception_ce;
        break;

    case LCB_ERR_QUERY:
        exc_ce = pcbc_query_exception_ce;
        break;

    default:
        exc_ce = pcbc_base_exception_ce;
        break;
    }
    object_init_ex(return_value, exc_ce);
    zend_update_property_long(pcbc_default_exception_ce, return_value, ZEND_STRL("code"),
                              http_code ? http_code : code);
    zend_update_property_string(pcbc_default_exception_ce, return_value, ZEND_STRL("message"),
                                http_msg ? http_msg : lcb_strerror_short(code));

    if (ref) {
        zend_update_property_str(pcbc_base_exception_ce, return_value, ZEND_STRL("ref"), ref);
    }
    if (context) {
        zend_update_property_str(pcbc_base_exception_ce, return_value, ZEND_STRL("context"), context);
    }
}

PHP_METHOD(BaseException, context)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_base_exception_ce, getThis(), ZEND_STRL("context"), 0, &rv);
    ZVAL_DEREF(prop);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BaseException, code)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_base_exception_ce, getThis(), ZEND_STRL("code"), 0, &rv);
    ZVAL_DEREF(prop);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BaseException, message)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_base_exception_ce, getThis(), ZEND_STRL("message"), 0, &rv);
    ZVAL_DEREF(prop);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(BaseException, ref)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_base_exception_ce, getThis(), ZEND_STRL("ref"), 0, &rv);
    ZVAL_DEREF(prop);
    ZVAL_COPY(return_value, prop);
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
