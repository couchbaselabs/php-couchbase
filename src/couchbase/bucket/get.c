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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/get", __FILE__, __LINE__

typedef struct {
    opcookie_res header;
    char *key;
    int key_len;
    char *bytes;
    int bytes_len;
    lcb_U32 flags;
    lcb_datatype_t datatype;
    lcb_cas_t cas;
} opcookie_get_res;

void get_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb)
{
    opcookie_get_res *result = ecalloc(1, sizeof(opcookie_get_res));
    const lcb_RESPGET *resp = (const lcb_RESPGET *)rb;
    TSRMLS_FETCH();

    PCBC_RESP_ERR_COPY(result->header, cbtype, rb);
    result->key_len = resp->nkey;
    if (resp->nkey) {
        result->key = estrndup(resp->key, resp->nkey);
    }
    result->bytes_len = resp->nvalue;
    if (resp->nvalue) {
        result->bytes = estrndup(resp->value, resp->nvalue);
    }
    result->flags = resp->itmflags;
    result->datatype = resp->datatype;
    result->cas = resp->cas;

    opcookie_push((opcookie *)rb->cookie, &result->header);
}

static lcb_error_t proc_get_results(pcbc_bucket_t *bucket, zval *return_value, opcookie *cookie,
                                    int is_mapped TSRMLS_DC)
{
    opcookie_get_res *res;
    lcb_error_t err = LCB_SUCCESS;
#ifdef LCB_TRACING
    lcbtrace_SPAN *parent = cookie->span;
    lcbtrace_TRACER *tracer = lcb_get_tracer(bucket->conn->lcb);
#endif

    // If we are not mapped, we need to throw any op errors
    if (is_mapped == 0) {
        err = opcookie_get_first_error(cookie);
    }

    if (err == LCB_SUCCESS) {
        FOREACH_OPCOOKIE_RES(opcookie_get_res, res, cookie)
        {
            zval *doc = bop_get_return_doc(return_value, res->key, res->key_len, is_mapped TSRMLS_CC);

            if (res->header.err == LCB_SUCCESS) {
#ifdef LCB_TRACING
                lcbtrace_SPAN *span = NULL;
                if (parent) {
                    lcbtrace_REF ref;
                    ref.type = LCBTRACE_REF_CHILD_OF;
                    ref.span = parent;
                    span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_RESPONSE_DECODING, LCBTRACE_NOW, &ref);
                    lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
                    lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
                }
#endif
                pcbc_document_init_decode(doc, bucket, res->bytes, res->bytes_len, res->flags, res->datatype, res->cas,
                                          NULL TSRMLS_CC);
#ifdef LCB_TRACING
                if (span) {
                    lcbtrace_span_finish(span, LCBTRACE_NOW);
                }
#endif
            } else {
                pcbc_document_init_error(doc, &res->header TSRMLS_CC);
            }
        }
    }

    FOREACH_OPCOOKIE_RES(opcookie_get_res, res, cookie)
    {
        if (res->key) {
            efree(res->key);
        }
        if (res->bytes) {
            efree(res->bytes);
        }
        PCBC_RESP_ERR_FREE(res->header);
    }

    return err;
}

void pcbc_bucket_get(pcbc_bucket_t *obj, pcbc_pp_state *pp_state, pcbc_pp_id *id, zval **lock, zval **expiry,
                     zval **groupid, zval *return_value TSRMLS_DC)
{
    int ii, ncmds, nscheduled;
    opcookie *cookie;
    lcb_error_t err = LCB_SUCCESS;
#ifdef LCB_TRACING
    lcbtrace_TRACER *tracer = NULL;
#endif

    ncmds = pcbc_pp_keycount(pp_state);
    cookie = opcookie_init();

#ifdef LCB_TRACING
    tracer = lcb_get_tracer(obj->conn->lcb);
    if (tracer) {
        cookie->span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_GET, 0, NULL);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }
#endif

    nscheduled = 0;
    for (ii = 0; pcbc_pp_next(pp_state); ++ii) {
        lcb_CMDGET cmd = {0};

        if (lock) {
            PCBC_CHECK_ZVAL_LONG(*lock, "lockTime must be an integer");
        }
        if (expiry) {
            PCBC_CHECK_ZVAL_LONG(*expiry, "expiry must be an integer");
        }
        if (groupid) {
            PCBC_CHECK_ZVAL_STRING(*groupid, "groupid must be a string");
        }

        LCB_CMD_SET_KEY(&cmd, id->str, id->len);
#ifdef LCB_TRACING
        if (cookie->span) {
            LCB_CMD_SET_TRACESPAN(&cmd, cookie->span);
        }
#endif
        if (expiry && *expiry) {
            cmd.lock = 0;
            cmd.exptime = Z_LVAL_P(*expiry);
        } else if (lock && *lock) {
            cmd.lock = 1;
            cmd.exptime = Z_LVAL_P(*lock);
        }
        if (groupid && *groupid) {
            LCB_KREQ_SIMPLE(&cmd._hashkey, Z_STRVAL_P(*groupid), Z_STRLEN_P(*groupid));
        }
        err = lcb_get3(obj->conn->lcb, cookie, &cmd);
        if (err != LCB_SUCCESS) {
            break;
        }

        nscheduled++;
    }
    pcbc_assert_number_of_commands(obj->conn->lcb, "get", nscheduled, ncmds, err);

    if (nscheduled) {
        lcb_wait(obj->conn->lcb);
        err = proc_get_results(obj, return_value, cookie, pcbc_pp_ismapped(pp_state) TSRMLS_CC);
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

/* {{{ proto mixed Bucket::get(string $id, array $options) */
PHP_METHOD(Bucket, get)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    pcbc_pp_state pp_state;
    pcbc_pp_id id;
    zval *lock = NULL, *expiry = NULL, *groupid = NULL;

    // Note that groupid is experimental here and should not be used.
    if (pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id||lockTime,expiry,groupid", &id, &lock, &expiry,
                      &groupid) != SUCCESS) {
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    pcbc_bucket_get(obj, &pp_state, &id, &lock, &expiry, &groupid, return_value TSRMLS_CC);
}

/* {{{ proto mixed Bucket::getAndLock(string $id, int $lockTime, array $options) */
PHP_METHOD(Bucket, getAndLock)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    pcbc_pp_state pp_state;
    pcbc_pp_id id;
    zval *lock = NULL, *groupid = NULL;

    // Note that groupid is experimental here and should not be used.
    if (pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id,lockTime||groupid", &id, &lock, &groupid) != SUCCESS) {
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    pcbc_bucket_get(obj, &pp_state, &id, &lock, NULL, &groupid, return_value TSRMLS_CC);
}

/* {{{ proto mixed Bucket::getAndTouch(string $id, int $expiry, array $options) */
PHP_METHOD(Bucket, getAndTouch)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    pcbc_pp_state pp_state;
    pcbc_pp_id id;
    zval *expiry = NULL, *groupid = NULL;

    // Note that groupid is experimental here and should not be used.
    if (pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id,expiry||groupid", &id, &expiry, &groupid) != SUCCESS) {
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    pcbc_bucket_get(obj, &pp_state, &id, NULL, &expiry, &groupid, return_value TSRMLS_CC);
}

// get($id {, $lock, $groupid}) : MetaDoc
PHP_METHOD(Bucket, getFromReplica)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    int ii, ncmds, nscheduled;
    pcbc_pp_state pp_state;
    pcbc_pp_id id;
    zval *zindex, *zgroupid;
    opcookie *cookie;
    lcb_error_t err = LCB_SUCCESS;
#ifdef LCB_TRACING
    lcbtrace_TRACER *tracer = NULL;
#endif

    // Note that groupid is experimental here and should not be used.
    if (pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id||index,groupid", &id, &zindex, &zgroupid) != SUCCESS) {
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    ncmds = pcbc_pp_keycount(&pp_state);
    cookie = opcookie_init();
#ifdef LCB_TRACING
    tracer = lcb_get_tracer(obj->conn->lcb);
    if (tracer) {
        cookie->span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_GET_FROM_REPLICA, 0, NULL);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }
#endif

    nscheduled = 0;
    for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
        lcb_CMDGETREPLICA cmd = {0};

        PCBC_CHECK_ZVAL_LONG(zindex, "index must be an integer");
        PCBC_CHECK_ZVAL_STRING(zgroupid, "groupid must be a string");

        LCB_CMD_SET_KEY(&cmd, id.str, id.len);
#ifdef LCB_TRACING
        if (cookie->span) {
            LCB_CMD_SET_TRACESPAN(&cmd, cookie->span);
        }
#endif
        if (zindex) {
            cmd.index = Z_LVAL_P(zindex);
            if (cmd.index >= 0) {
                cmd.strategy = LCB_REPLICA_SELECT;
            } else {
                cmd.strategy = LCB_REPLICA_FIRST;
            }
        }
        if (zgroupid) {
            LCB_KREQ_SIMPLE(&cmd._hashkey, Z_STRVAL_P(zgroupid), Z_STRLEN_P(zgroupid));
        }

        err = lcb_rget3(obj->conn->lcb, cookie, &cmd);
        if (err != LCB_SUCCESS) {
            break;
        }
        nscheduled++;
    }
    pcbc_assert_number_of_commands(obj->conn->lcb, "get_from_replica", nscheduled, ncmds, err);

    if (nscheduled) {
        lcb_wait(obj->conn->lcb);

        err = proc_get_results(obj, return_value, cookie, pcbc_pp_ismapped(&pp_state) TSRMLS_CC);
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
