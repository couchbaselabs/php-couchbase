/**
 *     Copyright 2018-2019 Couchbase, Inc.
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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/health", __FILE__, __LINE__

typedef struct {
    opcookie_res header;
    zval val;
} opcookie_health_res;

static lcb_STATUS proc_health_results(zval *return_value, opcookie *cookie)
{
    opcookie_health_res *res;
    lcb_STATUS err = LCB_SUCCESS;

    err = opcookie_get_first_error(cookie);

    if (err == LCB_SUCCESS) {
        FOREACH_OPCOOKIE_RES(opcookie_health_res, res, cookie)
        {
            ZVAL_ZVAL(return_value, &res->val, 1, 0);
        }
    }

    FOREACH_OPCOOKIE_RES(opcookie_health_res, res, cookie)
    {
        zval_ptr_dtor(&res->val);
    }
    return err;
}

void ping_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPPING *resp)
{
    opcookie_health_res *result = ecalloc(1, sizeof(opcookie_health_res));

    result->header.err = lcb_respping_status(resp);
    if (result->header.err == LCB_SUCCESS) {
        int last_error = 0;
        ZVAL_UNDEF(&result->val);
        const char *json = NULL;
        size_t njson = 0;
        lcb_respping_value(resp, &json, &njson);
        PCBC_JSON_COPY_DECODE(&result->val, json, njson, PHP_JSON_OBJECT_AS_ARRAY, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(instance, WARN), "Failed to decode PING response as JSON: json_last_error=%d", last_error);
        }
    }
    opcookie *cookie;
    lcb_respping_cookie(resp, (void **)&cookie);
    opcookie_push(cookie, &result->header);
    (void)instance;
    (void)cbtype;
}

PHP_METHOD(Bucket, ping)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    zval *options = NULL;
    int rv;
    lcb_STATUS err;

    rv = zend_parse_parameters(ZEND_NUM_ARGS(), "|z", &options);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    lcb_CMDPING *cmd;

    lcb_cmdping_create(&cmd);
    lcb_cmdping_all(cmd);
    lcb_cmdping_encode_json(cmd, 1, 0, 1);
    opcookie *cookie = opcookie_init();
    err = lcb_ping(obj->conn->lcb, cookie, cmd);
    lcb_cmdping_destroy(cmd);
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, NULL);
    }
    lcb_wait(obj->conn->lcb, LCB_WAIT_DEFAULT);
    err = proc_health_results(return_value, cookie);
    opcookie_destroy(cookie);
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, NULL);
    }
}

void diag_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPDIAG *resp)
{
    opcookie_health_res *result = ecalloc(1, sizeof(opcookie_health_res));

    result->header.err = lcb_respdiag_status(resp);
    if (result->header.err == LCB_SUCCESS) {
        int last_error = 0;
        ZVAL_UNDEF(&result->val);
        const char *json = NULL;
        size_t njson = 0;
        lcb_respdiag_value(resp, &json, &njson);
        PCBC_JSON_COPY_DECODE(&result->val, json, njson, PHP_JSON_OBJECT_AS_ARRAY, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(instance, WARN), "Failed to decode PING response as JSON: json_last_error=%d", last_error);
        }
    }
    opcookie *cookie;
    lcb_respdiag_cookie(resp, (void **)&cookie);
    opcookie_push(cookie, &result->header);
    (void)instance;
    (void)cbtype;
}

PHP_METHOD(Bucket, diagnostics)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    zend_string *report_id;
    int rv;
    lcb_STATUS err;

    rv = zend_parse_parameters(ZEND_NUM_ARGS(), "|S", &report_id);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    lcb_CMDDIAG *cmd;
    lcb_cmddiag_create(&cmd);
    lcb_cmddiag_report_id(cmd, ZSTR_VAL(report_id), ZSTR_LEN(report_id));
    opcookie *cookie = opcookie_init();
    err = lcb_diag(obj->conn->lcb, cookie, cmd);
    lcb_cmddiag_destroy(cmd);
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, NULL);
    }
    lcb_wait(obj->conn->lcb, LCB_WAIT_DEFAULT);
    err = proc_health_results(return_value, cookie);
    opcookie_destroy(cookie);
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, NULL);
    }
}
