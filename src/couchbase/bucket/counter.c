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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/counter", __FILE__, __LINE__

typedef struct {
    opcookie_res header;
    char *key;
    int key_len;
    lcb_U64 value;
    lcb_cas_t cas;
    lcb_MUTATION_TOKEN token;
} opcookie_arithmetic_res;

void counter_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb)
{
    opcookie_arithmetic_res *result = ecalloc(1, sizeof(opcookie_arithmetic_res));
    const lcb_RESPCOUNTER *resp = (const lcb_RESPCOUNTER *)rb;
    const lcb_MUTATION_TOKEN *mutinfo;
    TSRMLS_FETCH();

    result->header.err = resp->rc;
    PCBC_RESP_ERR_COPY(result->header, cbtype, rb);
    result->key_len = resp->nkey;
    if (resp->nkey) {
        result->key = estrndup(resp->key, resp->nkey);
    }
    result->value = resp->value;
    result->cas = resp->cas;
    mutinfo = lcb_resp_get_mutation_token(cbtype, rb);
    if (mutinfo) {
        memcpy(&result->token, mutinfo, sizeof(result->token));
    }

    opcookie_push((opcookie *)rb->cookie, &result->header);
}

static lcb_error_t proc_arithmetic_results(pcbc_bucket_t *bucket, zval *return_value, opcookie *cookie,
                                           int is_mapped TSRMLS_DC)
{
    opcookie_arithmetic_res *res;
    lcb_error_t err = LCB_SUCCESS;

    // If we are not mapped, we need to throw any op errors
    if (is_mapped == 0) {
        err = opcookie_get_first_error(cookie);
    }

    if (err == LCB_SUCCESS) {
        FOREACH_OPCOOKIE_RES(opcookie_arithmetic_res, res, cookie)
        {
            zval *doc = bop_get_return_doc(return_value, res->key, res->key_len, is_mapped TSRMLS_CC);

            if (res->header.err == LCB_SUCCESS) {
                pcbc_document_init_counter(doc, bucket, res->value, res->cas, &res->token TSRMLS_CC);
            } else {
                pcbc_document_init_error(doc, &res->header TSRMLS_CC);
            }
        }
    }

    FOREACH_OPCOOKIE_RES(opcookie_arithmetic_res, res, cookie)
    {
        if (res->key) {
            efree(res->key);
        }
        PCBC_RESP_ERR_FREE(res->header);
    }

    return err;
}

// counter($id, $delta {, $initial, $expiry}) : MetaDoc
PHP_METHOD(Bucket, counter)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    int ii, ncmds, nscheduled;
    pcbc_pp_state pp_state;
    pcbc_pp_id id;
    zval *zdelta, *zinitial, *zexpiry, *zgroupid;
    opcookie *cookie;
    lcb_error_t err = LCB_SUCCESS;
#ifdef LCB_TRACING
    lcbtrace_TRACER *tracer = NULL;
#endif

    // Note that groupid is experimental here and should not be used.
    if (pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id|delta|initial,expiry,groupid", &id, &zdelta, &zinitial,
                      &zexpiry, &zgroupid) != SUCCESS) {
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    ncmds = pcbc_pp_keycount(&pp_state);
    cookie = opcookie_init();
#ifdef LCB_TRACING
    tracer = lcb_get_tracer(obj->conn->lcb);
    if (tracer) {
        cookie->span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_COUNTER, 0, NULL);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }
#endif

    nscheduled = 0;
    for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
        lcb_CMDCOUNTER cmd = {0};
        PCBC_CHECK_ZVAL_LONG(zdelta, "delta must be an integer");
        PCBC_CHECK_ZVAL_LONG(zinitial, "initial must be an integer");
        PCBC_CHECK_ZVAL_LONG(zexpiry, "expiry must be an integer");
        PCBC_CHECK_ZVAL_STRING(zgroupid, "groupid must be a string");

        LCB_CMD_SET_KEY(&cmd, id.str, id.len);
        if (zdelta) {
            cmd.delta = Z_LVAL_P(zdelta);
        } else {
            cmd.delta = 1;
        }
        if (zinitial) {
            cmd.initial = Z_LVAL_P(zinitial);
            cmd.create = 1;
        }
        if (zexpiry) {
            cmd.exptime = Z_LVAL_P(zexpiry);
        }
        if (zgroupid) {
            LCB_KREQ_SIMPLE(&cmd._hashkey, Z_STRVAL_P(zgroupid), Z_STRLEN_P(zgroupid));
        }
#ifdef LCB_TRACING
        if (cookie->span) {
            LCB_CMD_SET_TRACESPAN(&cmd, cookie->span);
        }
#endif

        err = lcb_counter3(obj->conn->lcb, cookie, &cmd);
        if (err != LCB_SUCCESS) {
            break;
        }
        nscheduled++;
    }
    pcbc_assert_number_of_commands(obj->conn->lcb, "counter", nscheduled, ncmds, err);

    if (nscheduled) {
        lcb_wait(obj->conn->lcb);

        err = proc_arithmetic_results(obj, return_value, cookie, pcbc_pp_ismapped(&pp_state) TSRMLS_CC);
    }

#ifdef LCB_TRACING
    if (cookie->span) {
        lcbtrace_span_finish(cookie->span, LCBTRACE_NOW);
    }
#endif
    opcookie_destroy(cookie);

    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err);
    }
}
