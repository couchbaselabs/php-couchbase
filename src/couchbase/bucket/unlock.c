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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/unlock", __FILE__, __LINE__

typedef struct {
    opcookie_res header;
    int key_len;
    char *key;
} opcookie_unlock_res;

void unlock_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb)
{
    opcookie_unlock_res *result = ecalloc(1, sizeof(opcookie_unlock_res));
    const lcb_RESPUNLOCK *resp = (const lcb_RESPUNLOCK *)rb;
    TSRMLS_FETCH();

    PCBC_RESP_ERR_COPY(result->header, cbtype, rb);
    result->key_len = resp->nkey;
    if (resp->nkey) {
        result->key = estrndup(resp->key, resp->nkey);
    }

    opcookie_push((opcookie *)rb->cookie, &result->header);
}

static lcb_error_t proc_unlock_results(pcbc_bucket_t *bucket, zval *return_value, opcookie *cookie,
                                       int is_mapped TSRMLS_DC)
{
    opcookie_unlock_res *res;
    lcb_error_t err = LCB_SUCCESS;

    // If we are not mapped, we need to throw any op errors
    if (is_mapped == 0) {
        err = opcookie_get_first_error(cookie);
    }

    if (err == LCB_SUCCESS) {
        FOREACH_OPCOOKIE_RES(opcookie_unlock_res, res, cookie)
        {
            zval *doc = bop_get_return_doc(return_value, res->key, res->key_len, is_mapped TSRMLS_CC);

            if (res->header.err == LCB_SUCCESS) {
                pcbc_document_init(doc, bucket, NULL, 0, 0, 0, NULL TSRMLS_CC);
            } else {
                pcbc_document_init_error(doc, &res->header TSRMLS_CC);
            }
        }
    }

    FOREACH_OPCOOKIE_RES(opcookie_unlock_res, res, cookie)
    {
        if (res->key) {
            efree(res->key);
        }
        PCBC_RESP_ERR_FREE(res->header);
    }

    return err;
}

// unlock($id {, $cas, $groupid}) : MetaDoc
PHP_METHOD(Bucket, unlock)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    int ii, ncmds, nscheduled;
    pcbc_pp_state pp_state;
    pcbc_pp_id id;
    zval *zcas, *zgroupid;
    opcookie *cookie;
    lcb_error_t err;
#ifdef LCB_TRACING
    lcbtrace_TRACER *tracer = NULL;
#endif

    // Note that groupid is experimental here and should not be used.
    if (pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id||cas,groupid", &id, &zcas, &zgroupid) != SUCCESS) {
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    ncmds = pcbc_pp_keycount(&pp_state);
    cookie = opcookie_init();
#ifdef LCB_TRACING
    tracer = lcb_get_tracer(obj->conn->lcb);
    if (tracer) {
        cookie->span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_UNLOCK, 0, NULL);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }
#endif

    nscheduled = 0;
    for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
        lcb_CMDUNLOCK cmd = {0};

        PCBC_CHECK_ZVAL_STRING(zcas, "cas must be a string");
        PCBC_CHECK_ZVAL_STRING(zgroupid, "groupid must be a string");

        LCB_CMD_SET_KEY(&cmd, id.str, id.len);
        if (zcas) {
            cmd.cas = pcbc_cas_decode(zcas TSRMLS_CC);
        }
        if (zgroupid) {
            LCB_KREQ_SIMPLE(&cmd._hashkey, Z_STRVAL_P(zgroupid), Z_STRLEN_P(zgroupid));
        }
#ifdef LCB_TRACING
        if (cookie->span) {
            LCB_CMD_SET_TRACESPAN(&cmd, cookie->span);
        }
#endif

        err = lcb_unlock3(obj->conn->lcb, cookie, &cmd);
        if (err != LCB_SUCCESS) {
            break;
        }
        nscheduled++;
    }
    pcbc_assert_number_of_commands(obj->conn->lcb, "unlock", nscheduled, ncmds, err);

    if (nscheduled) {
        lcb_wait(obj->conn->lcb);

        err = proc_unlock_results(obj, return_value, cookie, pcbc_pp_ismapped(&pp_state) TSRMLS_CC);
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
