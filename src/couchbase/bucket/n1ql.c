/**
 *     Copyright 2016-2017 Couchbase, Inc.
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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/n1ql", __FILE__, __LINE__

typedef struct {
    opcookie_res header;
    lcb_U16 rflags;
    PCBC_ZVAL row;
} opcookie_n1qlrow_res;

static void n1qlrow_callback(lcb_t instance, int ignoreme, const lcb_RESPN1QL *resp)
{
    opcookie_n1qlrow_res *result = ecalloc(1, sizeof(opcookie_n1qlrow_res));
    opcookie *cookie = (opcookie *)resp->cookie;
    TSRMLS_FETCH();

    result->header.err = resp->rc;
    result->rflags = resp->rflags;
    PCBC_ZVAL_ALLOC(result->row);
    ZVAL_NULL(PCBC_P(result->row));
    if (cookie->json_response) {
        int last_error;
        int json_options = cookie->json_options;

        if (resp->rflags & LCB_RESP_F_FINAL) {
            // parse meta into arrays
            json_options |= PHP_JSON_OBJECT_AS_ARRAY;
        }
        PCBC_JSON_COPY_DECODE(PCBC_P(result->row), resp->row, resp->nrow, json_options, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(instance, WARN), "Failed to decode N1QL row as JSON: json_last_error=%d", last_error);
            PCBC_STRINGL(result->row, resp->row, resp->nrow);
        }
    } else {
        PCBC_STRINGL(result->row, resp->row, resp->nrow);
    }
    if (result->header.err != LCB_SUCCESS) {
        int reported = 0;
        if (Z_TYPE_P(PCBC_P(result->row)) == IS_ARRAY) {
            zval *val;
            val = php_array_fetch(PCBC_P(result->row), "errors");
            if (val) {
                zval *err = php_array_fetch(val, "0");
                if (err) {
                    char *msg = NULL;
                    int msg_len;
                    zend_bool need_free = 0;
                    long code = php_array_fetch_long(err, "code");
                    msg = php_array_fetch_string(err, "msg", &msg_len, &need_free);
                    if (code && msg) {
                        char *m = NULL;
                        spprintf(&m, 0, "Failed to perform N1QL query. HTTP %d: code: %d, message: \"%*s\"",
                                 (int)resp->htresp->htstatus, (int)code, msg_len, msg);
                        PCBC_ZVAL_ALLOC(cookie->exc);
                        pcbc_exception_init(PCBC_P(cookie->exc), code, m TSRMLS_CC);
                        reported = 1;
                        if (m) {
                            efree(m);
                        }
                    }
                    if (msg && need_free) {
                        efree(msg);
                    }
                }
            }
        }
        if (!reported) {
            if (resp->htresp) {
                pcbc_log(LOGARGS(instance, ERROR), "Failed to perform N1QL query. %d: %.*s", (int)resp->htresp->htstatus,
                         (int)resp->nrow, (char *)resp->row);
            } else {
                pcbc_log(LOGARGS(instance, ERROR), "Failed to perform N1QL query. %.*s",
                         (int)resp->nrow, (char *)resp->row);
            }
        }
    }

    opcookie_push((opcookie *)resp->cookie, &result->header);
}

static lcb_error_t proc_n1qlrow_results(zval *return_value, opcookie *cookie TSRMLS_DC)
{
    opcookie_n1qlrow_res *res;
    lcb_error_t err = LCB_SUCCESS;

    // Any error should cause everything to fail... for now?
    err = opcookie_get_first_error(cookie);

    if (err == LCB_SUCCESS) {
        PCBC_ZVAL rows;

        PCBC_ZVAL_ALLOC(rows);
        array_init(PCBC_P(rows));

        object_init(return_value);
        add_property_zval(return_value, "rows", PCBC_P(rows));
        Z_DELREF_P(PCBC_P(rows));

        FOREACH_OPCOOKIE_RES(opcookie_n1qlrow_res, res, cookie)
        {
            if (res->rflags & LCB_RESP_F_FINAL) {
                zval *val;
                val = php_array_fetch(PCBC_P(res->row), "requestID");
                if (val) {
                    add_property_zval(return_value, "requestId", val);
                }
                val = php_array_fetch(PCBC_P(res->row), "status");
                if (val) {
                    add_property_zval(return_value, "status", val);
                }
                val = php_array_fetch(PCBC_P(res->row), "signature");
                if (val) {
                    add_property_zval(return_value, "signature", val);
                }
                val = php_array_fetch(PCBC_P(res->row), "metrics");
                if (val) {
                    add_property_zval(return_value, "metrics", val);
                }
            } else {
                add_next_index_zval(PCBC_P(rows), PCBC_P(res->row));
                PCBC_ADDREF_P(PCBC_P(res->row));
            }
        }
    }

    FOREACH_OPCOOKIE_RES(opcookie_n1qlrow_res, res, cookie)
    {
        zval_ptr_dtor(&res->row);
    }

    return err;
}

void pcbc_bucket_n1ql_request(pcbc_bucket_t *bucket, lcb_CMDN1QL *cmd, int json_response, int json_options, int is_cbas,
                              zval *return_value TSRMLS_DC)
{
    opcookie *cookie;
    lcb_error_t err;
#ifdef LCB_TRACING
    lcbtrace_TRACER *tracer = NULL;
    lcb_N1QLHANDLE handle = NULL;
#endif

    cmd->callback = n1qlrow_callback;
    cmd->content_type = PCBC_CONTENT_TYPE_JSON;
    cookie = opcookie_init();
    cookie->json_response = json_response;
    cookie->json_options = json_options;
    cookie->is_cbas = is_cbas;
#ifdef LCB_TRACING
    tracer = lcb_get_tracer(bucket->conn->lcb);
    if (tracer) {
        cookie->span = lcbtrace_span_start(tracer, is_cbas ? "php/analytics" : "php/n1ql", 0, NULL);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_SERVICE,
                                  is_cbas ? LCBTRACE_TAG_SERVICE_ANALYTICS : LCBTRACE_TAG_SERVICE_N1QL);
        cmd->handle = &handle;
    }
#endif
    err = lcb_n1ql_query(bucket->conn->lcb, cookie, cmd);
    if (err == LCB_SUCCESS) {
#ifdef LCB_TRACING
        if (cookie->span) {
            lcb_n1ql_set_parent_span(bucket->conn->lcb, handle, cookie->span);
        }
#endif
        lcb_wait(bucket->conn->lcb);
        err = proc_n1qlrow_results(return_value, cookie TSRMLS_CC);
    }
    if (err != LCB_SUCCESS) {
        if (Z_ISUNDEF(cookie->exc)) {
            throw_lcb_exception(err);
        } else {
            zend_throw_exception_object(PCBC_P(cookie->exc) TSRMLS_CC);
        }
    }
#ifdef LCB_TRACING
    if (cookie->span) {
        lcbtrace_span_finish(cookie->span, LCBTRACE_NOW);
    }
#endif
    opcookie_destroy(cookie);
}
