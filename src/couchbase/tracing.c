/**
 *     Copyright 2021 Couchbase, Inc.
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

zend_class_entry *pcbc_request_span_ce;
zend_class_entry *pcbc_request_tracer_ce;
zend_class_entry *pcbc_logging_request_span_ce;
zend_class_entry *pcbc_threshold_logging_tracer_ce;
zend_class_entry *pcbc_noop_request_span_ce;
zend_class_entry *pcbc_noop_tracer_ce;

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_RequestSpan_addTag, IS_VOID, 0)
ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_RequestSpan_end, IS_VOID, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry request_span_interface[] = {
    PHP_ABSTRACT_ME(RequestSpan, addTag, ai_RequestSpan_addTag)
    PHP_ABSTRACT_ME(RequestSpan, end, ai_RequestSpan_end)
    PHP_FE_END
};
// clang-format on

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_RequestTracer_requestSpan, Couchbase\\RequestSpan, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, parent, Couchbase\\RequestSpan, 1)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry request_tracer_interface[] = {
    PHP_ABSTRACT_ME(RequestTracer, requestSpan, ai_RequestTracer_requestSpan)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(LoggingRequestSpan, addTag)
{
    // the function never actually called, because the class triggers threshold logging tracer, that shipped with
    // libcouchbase.
}

PHP_METHOD(LoggingRequestSpan, end)
{
    // the function never actually called, because the class triggers threshold logging tracer, that shipped with
    // libcouchbase.
}

// clang-format off
static const zend_function_entry logging_request_span_class[] = {
    PHP_ME(LoggingRequestSpan, addTag, ai_RequestSpan_addTag, ZEND_ACC_PUBLIC)
    PHP_ME(LoggingRequestSpan, end, ai_RequestSpan_end, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(ThresholdLoggingTracer, requestSpan)
{
    // the function never actually called, because the class triggers threshold logging tracer, that shipped with
    // libcouchbase.
    object_init_ex(return_value, pcbc_logging_request_span_ce);
}

PHP_METHOD(ThresholdLoggingTracer, emitInterval)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_threshold_logging_tracer_ce, getThis(), ("emit_interval"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ThresholdLoggingTracer, kvThreshold)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_threshold_logging_tracer_ce, getThis(), ("kv_threshold"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ThresholdLoggingTracer, queryThreshold)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_threshold_logging_tracer_ce, getThis(), ("query_threshold"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ThresholdLoggingTracer, viewsThreshold)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_threshold_logging_tracer_ce, getThis(), ("views_threshold"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ThresholdLoggingTracer, searchThreshold)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_threshold_logging_tracer_ce, getThis(), ("search_threshold"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ThresholdLoggingTracer, analyticsThreshold)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_threshold_logging_tracer_ce, getThis(), ("analytics_threshold"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(ThresholdLoggingTracer, sampleSize)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_threshold_logging_tracer_ce, getThis(), ("sample_size"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_RequestTracer_emitInterval, Couchbase\\ThresholdLoggingTracer, 0)
ZEND_ARG_TYPE_INFO(0, duration, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_RequestTracer_kvThreshold, Couchbase\\ThresholdLoggingTracer, 0)
ZEND_ARG_TYPE_INFO(0, threshold, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_RequestTracer_queryThreshold, Couchbase\\ThresholdLoggingTracer, 0)
ZEND_ARG_TYPE_INFO(0, threshold, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_RequestTracer_viewsThreshold, Couchbase\\ThresholdLoggingTracer, 0)
ZEND_ARG_TYPE_INFO(0, threshold, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_RequestTracer_searchThreshold, Couchbase\\ThresholdLoggingTracer, 0)
ZEND_ARG_TYPE_INFO(0, threshold, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_RequestTracer_analyticsThreshold, Couchbase\\ThresholdLoggingTracer, 0)
ZEND_ARG_TYPE_INFO(0, threshold, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_RequestTracer_sampleSize, Couchbase\\ThresholdLoggingTracer, 0)
ZEND_ARG_TYPE_INFO(0, size, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry threshold_logging_tracer_class[] = {
    PHP_ME(ThresholdLoggingTracer, requestSpan, ai_RequestTracer_requestSpan, ZEND_ACC_PUBLIC)
    PHP_ME(ThresholdLoggingTracer, emitInterval, ai_RequestTracer_emitInterval, ZEND_ACC_PUBLIC)
    PHP_ME(ThresholdLoggingTracer, kvThreshold, ai_RequestTracer_kvThreshold, ZEND_ACC_PUBLIC)
    PHP_ME(ThresholdLoggingTracer, queryThreshold, ai_RequestTracer_queryThreshold, ZEND_ACC_PUBLIC)
    PHP_ME(ThresholdLoggingTracer, viewsThreshold, ai_RequestTracer_viewsThreshold, ZEND_ACC_PUBLIC)
    PHP_ME(ThresholdLoggingTracer, searchThreshold, ai_RequestTracer_searchThreshold, ZEND_ACC_PUBLIC)
    PHP_ME(ThresholdLoggingTracer, analyticsThreshold, ai_RequestTracer_analyticsThreshold, ZEND_ACC_PUBLIC)
    PHP_ME(ThresholdLoggingTracer, sampleSize, ai_RequestTracer_sampleSize, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(NoopRequestSpan, addTag)
{
    // the function never actually called, because the class switches off tracing completely
}

PHP_METHOD(NoopRequestSpan, end)
{
    // the function never actually called, because the class switches off tracing completely
}

// clang-format off
static const zend_function_entry noop_request_span_class[] = {
    PHP_ME(NoopRequestSpan, addTag, ai_RequestSpan_addTag, ZEND_ACC_PUBLIC)
    PHP_ME(NoopRequestSpan, end, ai_RequestSpan_end, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(NoopTracer, requestSpan)
{
    // the function never actually called, because the class triggers logging meter, that shipped with libcouchbase.
    object_init_ex(return_value, pcbc_noop_request_span_ce);
}

// clang-format off
static const zend_function_entry noop_tracer_class[] = {
    PHP_ME(NoopTracer, requestSpan, ai_RequestTracer_requestSpan, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

typedef struct {
    zval *php_impl;
} tracer_wrapper;

static void *tracer_wrapper_start_span(struct lcbtrace_TRACER *lcb_tracer, const char *name, void *parent)
{
    if (lcb_tracer == NULL) {
        return NULL;
    }
    if (lcb_tracer->cookie == NULL) {
        return NULL;
    }
    tracer_wrapper *tracer = lcb_tracer->cookie;

    zval method_name;
    ZVAL_STRING(&method_name, "requestSpan");

    zval *retval = ecalloc(sizeof(zval), 1);

    zval params[2];

    ZVAL_STRING(&params[0], name);
    ZVAL_NULL(&params[1]);
    if (parent) {
        zval *parent_span = parent;
        if (Z_TYPE_P(parent_span) == IS_OBJECT && instanceof_function(Z_OBJCE_P(parent_span), pcbc_request_span_ce)) {
            ZVAL_ZVAL(&params[1], parent_span, 1, 0);
        }
    }

    int rv = call_user_function(NULL, tracer->php_impl, &method_name, retval, 2, params);
    zval_ptr_dtor(&method_name);
    zval_ptr_dtor(&params[0]);
    zval_ptr_dtor(&params[1]);

    if (rv == FAILURE || Z_TYPE_P(retval) == IS_UNDEF) {
        if (!EG(exception)) {
            zend_throw_exception_ex(NULL, 0, "Failed calling %s::requestSpan()",
                                    ZSTR_VAL(Z_OBJCE_P(tracer->php_impl)->name));
        }

        efree(retval);
        return NULL;
    }

    if (EG(exception)) {
        zval_ptr_dtor(retval);
        efree(retval);
        return NULL;
    }

    if (Z_TYPE_P(retval) != IS_OBJECT || !instanceof_function(Z_OBJCE_P(retval), pcbc_request_span_ce)) {
        zval_ptr_dtor(retval);
        return NULL;
    }

    return retval;
}

static void tracer_wrapper_end_span(void *span)
{
    if (span == NULL) {
        return;
    }
    zval *php_span = (zval *)span;
    if (Z_TYPE_P(php_span) != IS_OBJECT || !instanceof_function(Z_OBJCE_P(php_span), pcbc_request_span_ce)) {
        return;
    }

    zval method_name;
    ZVAL_STRING(&method_name, "end");

    zval retval;
    ZVAL_NULL(&retval);

    call_user_function(NULL, php_span, &method_name, &retval, 0, NULL);
    zval_ptr_dtor(&method_name);
}

static void tracer_wrapper_destroy_span(void *span)
{
    if (span != NULL) {
        efree(span);
    }
}

static void tracer_wrapper_add_tag_string(void *span, const char *name, const char *value, size_t value_len)
{
    if (span == NULL) {
        return;
    }
    zval *php_span = (zval *)span;
    if (Z_TYPE_P(php_span) != IS_OBJECT || !instanceof_function(Z_OBJCE_P(php_span), pcbc_request_span_ce)) {
        return;
    }

    zval method_name;
    ZVAL_STRING(&method_name, "addTag");

    zval params[2];
    ZVAL_STRING(&params[0], name);
    ZVAL_STRINGL(&params[1], value, value_len);

    zval retval;
    ZVAL_NULL(&retval);

    call_user_function(NULL, php_span, &method_name, &retval, 2, params);
    zval_ptr_dtor(&method_name);
    zval_ptr_dtor(&params[0]);
    zval_ptr_dtor(&params[1]);
}

static void tracer_wrapper_add_tag_uint64(void *span, const char *name, uint64_t value)
{
    if (span == NULL) {
        return;
    }
    zval *php_span = (zval *)span;
    if (Z_TYPE_P(php_span) != IS_OBJECT || !instanceof_function(Z_OBJCE_P(php_span), pcbc_request_span_ce)) {
        return;
    }

    zval method_name;
    ZVAL_STRING(&method_name, "addTag");

    zval params[2];
    ZVAL_STRING(&params[0], name);
    ZVAL_LONG(&params[1], value);

    zval retval;
    ZVAL_NULL(&retval);

    call_user_function(NULL, php_span, &method_name, &retval, 2, params);
    zval_ptr_dtor(&method_name);
    zval_ptr_dtor(&params[0]);
    zval_ptr_dtor(&params[1]);
}

lcbtrace_TRACER *tracer_wrapper_constructor(zval *php_tracer)
{
    tracer_wrapper *wrapper = calloc(1, sizeof(tracer_wrapper));
    wrapper->php_impl = php_tracer;

    lcbtrace_TRACER *tracer = lcbtrace_new(NULL, LCBTRACE_F_EXTERNAL);
    tracer->version = 1;
    tracer->v.v1.start_span = tracer_wrapper_start_span;
    tracer->v.v1.end_span = tracer_wrapper_end_span;
    tracer->v.v1.destroy_span = tracer_wrapper_destroy_span;
    tracer->v.v1.add_tag_string = tracer_wrapper_add_tag_string;
    tracer->v.v1.add_tag_uint64 = tracer_wrapper_add_tag_uint64;
    tracer->cookie = wrapper;

    return tracer;
}

void tracer_wrapper_destructor(lcbtrace_TRACER *tracer)
{
    if (tracer == NULL) {
        return;
    }
    tracer_wrapper *wrapper = (tracer_wrapper *)tracer->cookie;
    wrapper->php_impl = NULL;
    free(tracer->cookie);
    tracer->cookie = NULL;
    lcbtrace_destroy(tracer);
}

PHP_MINIT_FUNCTION(Tracing)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "RequestSpan", request_span_interface);
    pcbc_request_span_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "RequestTracer", request_tracer_interface);
    pcbc_request_tracer_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "LoggingRequestSpan", logging_request_span_class);
    pcbc_logging_request_span_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_logging_request_span_ce, 1, pcbc_request_span_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ThresholdLoggingTracer", threshold_logging_tracer_class);
    pcbc_threshold_logging_tracer_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_threshold_logging_tracer_ce, 1, pcbc_request_tracer_ce);
    zend_declare_property_null(pcbc_threshold_logging_tracer_ce, ZEND_STRL("emit_interval"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_threshold_logging_tracer_ce, ZEND_STRL("kv_threshold"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_threshold_logging_tracer_ce, ZEND_STRL("query_threshold"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_threshold_logging_tracer_ce, ZEND_STRL("views_threshold"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_threshold_logging_tracer_ce, ZEND_STRL("search_threshold"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_threshold_logging_tracer_ce, ZEND_STRL("analytics_threshold"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_threshold_logging_tracer_ce, ZEND_STRL("sample_size"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "NoopRequestSpan", noop_request_span_class);
    pcbc_noop_request_span_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_noop_request_span_ce, 1, pcbc_request_span_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "NoopTracer", noop_tracer_class);
    pcbc_noop_tracer_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_noop_tracer_ce, 1, pcbc_request_tracer_ce);
    return SUCCESS;
}
