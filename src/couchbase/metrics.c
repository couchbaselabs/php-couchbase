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

zend_class_entry *pcbc_value_recorder_ce;
zend_class_entry *pcbc_meter_ce;
zend_class_entry *pcbc_logging_value_recorder_ce;
zend_class_entry *pcbc_logging_meter_ce;
zend_class_entry *pcbc_noop_value_recorder_ce;
zend_class_entry *pcbc_noop_meter_ce;

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_ValueRecorder_recordValue, IS_VOID, 0)
ZEND_ARG_TYPE_INFO(0, value, IS_LONG, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry value_recorder_interface[] = {
    PHP_ABSTRACT_ME(ValueRecorder, recordValue, ai_ValueRecorder_recordValue)
    PHP_FE_END
};
// clang-format on

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_Meter_valueRecorder, Couchbase\\ValueRecorder, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, tags, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

// clang-format off
static const zend_function_entry meter_interface[] = {
    PHP_ABSTRACT_ME(Meter, valueRecorder, ai_Meter_valueRecorder)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(LoggingValueRecorder, recordValue)
{
    // the function never actually called, becaue the class triggers logging meter, that shipped with libcouchbase.
    RETURN_NULL();
}

// clang-format off
static const zend_function_entry logging_value_recorder_class[] = {
    PHP_ME(LoggingValueRecorder, recordValue, ai_ValueRecorder_recordValue, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(LoggingMeter, valueRecorder)
{
    // the function never actually called, becaue the class triggers logging meter, that shipped with libcouchbase.
    object_init_ex(return_value, pcbc_logging_value_recorder_ce);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_Meter_flushInterval, Couchbase\\LoggingMeter, 0)
ZEND_ARG_TYPE_INFO(0, duration, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(LoggingMeter, flushInterval)
{
    zend_long val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &val) == FAILURE) {
        RETURN_NULL();
    }

    pcbc_update_property_long(pcbc_logging_meter_ce, getThis(), ("flush_interval"), val);
    RETURN_ZVAL(getThis(), 1, 0);
}

// clang-format off
static const zend_function_entry logging_meter_class[] = {
    PHP_ME(LoggingMeter, valueRecorder, ai_Meter_valueRecorder, ZEND_ACC_PUBLIC)
    PHP_ME(LoggingMeter, flushInterval, ai_Meter_flushInterval, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(NoopValueRecorder, recordValue)
{
    // the function never actually called, because the class switches off metrics completely
    RETURN_NULL();
}

// clang-format off
static const zend_function_entry noop_value_recorder_class[] = {
    PHP_ME(NoopValueRecorder, recordValue, ai_ValueRecorder_recordValue, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(NoopMeter, valueRecorder)
{
    // the function never actually called, because the class triggers logging meter, that shipped with libcouchbase.
    object_init_ex(return_value, pcbc_noop_value_recorder_ce);
}

// clang-format off
static const zend_function_entry noop_meter_class[] = {
    PHP_ME(NoopMeter, valueRecorder, ai_Meter_valueRecorder, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

typedef struct {
    zval *php_impl;
} meter_wrapper;

void meter_wrapper_destructor(const lcbmetrics_METER *lcb_meter);
const lcbmetrics_VALUERECORDER *meter_value_recorder(const lcbmetrics_METER *lcb_meter, const char *name,
                                                     const lcbmetrics_TAG *tags, size_t ntags);

lcbmetrics_METER *meter_wrapper_constructor(zval *php_meter)
{
    meter_wrapper *wrapper = calloc(1, sizeof(meter_wrapper));
    wrapper->php_impl = php_meter;

    lcbmetrics_METER *lcb_meter = NULL;
    lcbmetrics_meter_create(&lcb_meter, wrapper);
    lcbmetrics_meter_dtor_callback(lcb_meter, meter_wrapper_destructor);
    lcbmetrics_meter_value_recorder_callback(lcb_meter, meter_value_recorder);

    return lcb_meter;
}

void meter_wrapper_destructor(const lcbmetrics_METER *lcb_meter)
{
    if (lcb_meter) {
        meter_wrapper *meter = NULL;
        if (lcbmetrics_meter_cookie(lcb_meter, (void **)(&meter)) == LCB_SUCCESS) {
            free(meter);
        }
    }
}

typedef struct {
    zval *php_impl;
} value_recorder_wrapper;

void value_recorder_wrapper_record_value(const lcbmetrics_VALUERECORDER *recorder, uint64_t value);
void value_recorder_wrapper_destructor(const lcbmetrics_VALUERECORDER *lcb_value_recorder);

lcbmetrics_VALUERECORDER *value_recorder_wrapper_constructor(zval *php_value_recorder)
{

    value_recorder_wrapper *wrapper = calloc(1, sizeof(value_recorder_wrapper));
    wrapper->php_impl = php_value_recorder;

    lcbmetrics_VALUERECORDER *lcb_recorder;
    lcbmetrics_valuerecorder_create(&lcb_recorder, wrapper);
    lcbmetrics_valuerecorder_dtor_callback(lcb_recorder, value_recorder_wrapper_destructor);
    lcbmetrics_valuerecorder_record_value_callback(lcb_recorder, value_recorder_wrapper_record_value);

    return lcb_recorder;
}

void value_recorder_wrapper_destructor(const lcbmetrics_VALUERECORDER *lcb_value_recorder)
{
    if (lcb_value_recorder) {
        value_recorder_wrapper *value_recorder = NULL;
        if (lcbmetrics_valuerecorder_cookie(lcb_value_recorder, (void **)(&value_recorder)) == LCB_SUCCESS) {
            efree(value_recorder->php_impl);
            free(value_recorder);
        }
    }
}

void value_recorder_wrapper_record_value(const lcbmetrics_VALUERECORDER *lcb_recorder, uint64_t value)
{
    if (lcb_recorder == NULL) {
        return;
    }
    value_recorder_wrapper *recorder = NULL;
    if (lcbmetrics_valuerecorder_cookie(lcb_recorder, (void **)(&recorder)) != LCB_SUCCESS || recorder == NULL) {
        return;
    }

    zval method_name;
    ZVAL_STRING(&method_name, "recordValue");

    zval retval;
    zval params[1];
    ZVAL_LONG(&params[0], value);

    call_user_function(NULL, recorder->php_impl, &method_name, &retval, 1, params);
    zval_ptr_dtor(&method_name);
    zval_ptr_dtor(&params[0]);
    zval_ptr_dtor(&retval);
}

const lcbmetrics_VALUERECORDER *meter_value_recorder(const lcbmetrics_METER *lcb_meter, const char *name,
                                                     const lcbmetrics_TAG *tags, size_t ntags)
{
    if (lcb_meter == NULL) {
        return NULL;
    }
    meter_wrapper *meter = NULL;
    if (lcbmetrics_meter_cookie(lcb_meter, (void **)(&meter)) != LCB_SUCCESS || meter == NULL) {
        return NULL;
    }

    zval method_name;
    ZVAL_STRING(&method_name, "valueRecorder");

    zval *retval = ecalloc(sizeof(zval), 1);

    zval params[2];

    ZVAL_STRING(&params[0], name);
    array_init_size(&params[1], ntags);
    for (int i = 0; i < ntags; ++i) {
        add_assoc_string(&params[1], tags[i].key, tags[i].value);
    }

    int rv = call_user_function(NULL, meter->php_impl, &method_name, retval, 2, params);
    zval_ptr_dtor(&method_name);
    zval_ptr_dtor(&params[0]);
    zval_ptr_dtor(&params[1]);

    if (rv == FAILURE || Z_TYPE_P(retval) == IS_UNDEF) {
        if (!EG(exception)) {
            zend_throw_exception_ex(NULL, 0, "Failed calling %s::valueRecorder()",
                                    ZSTR_VAL(Z_OBJCE_P(meter->php_impl)->name));
        }

        efree(retval);
        return NULL;
    }

    if (EG(exception)) {
        zval_ptr_dtor(retval);
        efree(retval);
        return NULL;
    }

    if (Z_TYPE_P(retval) != IS_OBJECT || !instanceof_function(Z_OBJCE_P(retval), pcbc_value_recorder_ce)) {
        zval_ptr_dtor(retval);
        return NULL;
    }

    return value_recorder_wrapper_constructor(retval);
}

PHP_MINIT_FUNCTION(Metrics)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ValueRecorder", value_recorder_interface);
    pcbc_value_recorder_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "Meter", meter_interface);
    pcbc_meter_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "LoggingValueRecorder", logging_value_recorder_class);
    pcbc_logging_value_recorder_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_logging_value_recorder_ce, 1, pcbc_value_recorder_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "LoggingMeter", logging_meter_class);
    pcbc_logging_meter_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_logging_meter_ce, 1, pcbc_meter_ce);
    zend_declare_property_null(pcbc_logging_meter_ce, ZEND_STRL("flush_interval"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "NoopValueRecorder", noop_value_recorder_class);
    pcbc_noop_value_recorder_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_noop_value_recorder_ce, 1, pcbc_value_recorder_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "NoopMeter", noop_meter_class);
    pcbc_noop_meter_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_noop_meter_ce, 1, pcbc_meter_ce);
    return SUCCESS;
}
