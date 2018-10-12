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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/touch", __FILE__, __LINE__

void touch_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb)
{
    opcookie_store_res *result = ecalloc(1, sizeof(opcookie_store_res));
    const lcb_RESPTOUCH *resp = (const lcb_RESPTOUCH *)rb;
    TSRMLS_FETCH();

    PCBC_RESP_ERR_COPY(result->header, cbtype, rb);
    if (resp->nkey) {
        result->key = estrndup(resp->key, resp->nkey);
    }
    result->cas = resp->cas;

    opcookie_push((opcookie *)rb->cookie, &result->header);
}

// touch($id {, $lock, $groupid}) : MetaDoc
PHP_METHOD(Bucket, touch)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    int ii, ncmds, nscheduled;
    pcbc_pp_state pp_state;
    pcbc_pp_id id;
    zval *zexpiry, *zgroupid;
    opcookie *cookie;
    lcb_error_t err;
#ifdef LCB_TRACING
    lcbtrace_TRACER *tracer = NULL;
#endif

    // Note that groupid is experimental here and should not be used.
    if (pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id|expiry|groupid", &id, &zexpiry, &zgroupid) != SUCCESS) {
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    ncmds = pcbc_pp_keycount(&pp_state);
    cookie = opcookie_init();
#ifdef LCB_TRACING
    tracer = lcb_get_tracer(obj->conn->lcb);
    if (tracer) {
        cookie->span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_TOUCH, 0, NULL);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }
#endif

    nscheduled = 0;
    for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
        lcb_CMDTOUCH cmd = {0};

        PCBC_CHECK_ZVAL_LONG(zexpiry, "expiry must be an integer");
        PCBC_CHECK_ZVAL_STRING(zgroupid, "groupid must be a string");

        LCB_CMD_SET_KEY(&cmd, id.str, id.len);
        cmd.exptime = Z_LVAL_P(zexpiry);
        if (zgroupid) {
            LCB_KREQ_SIMPLE(&cmd._hashkey, Z_STRVAL_P(zgroupid), Z_STRLEN_P(zgroupid));
        }
#ifdef LCB_TRACING
        if (cookie->span) {
            LCB_CMD_SET_TRACESPAN(&cmd, cookie->span);
        }
#endif

        err = lcb_touch3(obj->conn->lcb, cookie, &cmd);
        if (err != LCB_SUCCESS) {
            break;
        }
        nscheduled++;
    }
    pcbc_assert_number_of_commands(obj->conn->lcb, "touch", nscheduled, ncmds, err);

    if (nscheduled) {
        lcb_wait(obj->conn->lcb);

        err = proc_touch_results(obj, return_value, cookie, pcbc_pp_ismapped(&pp_state) TSRMLS_CC);
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
