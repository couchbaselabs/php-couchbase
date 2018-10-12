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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/store", __FILE__, __LINE__

void store_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb)
{
    opcookie_store_res *result = ecalloc(1, sizeof(opcookie_store_res));
    const lcb_MUTATION_TOKEN *mutinfo;
    TSRMLS_FETCH();

    PCBC_RESP_ERR_COPY(result->header, cbtype, rb);
    result->key_len = rb->nkey;
    if (rb->nkey) {
        result->key = estrndup(rb->key, rb->nkey);
    }
    result->cas = rb->cas;
    mutinfo = lcb_resp_get_mutation_token(cbtype, rb);
    if (mutinfo) {
        memcpy(&result->token, mutinfo, sizeof(result->token));
    }

    if (cbtype == LCB_CALLBACK_STOREDUR) {
        const lcb_RESPSTOREDUR *resp = (lcb_RESPSTOREDUR *)rb;
        if (resp->rc != LCB_SUCCESS && resp->store_ok) {
            pcbc_log(LOGARGS(instance, WARN), "Stored, but durability failed. Persisted(%u). Replicated(%u)",
                     resp->dur_resp->npersisted, resp->dur_resp->nreplicated);
        }
    }

    opcookie_push((opcookie *)rb->cookie, &result->header);
}

lcb_error_t proc_store_results(pcbc_bucket_t *bucket, zval *return_value, opcookie *cookie, int is_mapped TSRMLS_DC)
{
    opcookie_store_res *res;
    lcb_error_t err = LCB_SUCCESS;

    // If we are not mapped, we need to throw any op errors
    if (is_mapped == 0) {
        err = opcookie_get_first_error(cookie);
    }

    if (err == LCB_SUCCESS) {
        FOREACH_OPCOOKIE_RES(opcookie_store_res, res, cookie)
        {
            zval *doc = bop_get_return_doc(return_value, res->key, res->key_len, is_mapped TSRMLS_CC);

            if (res->header.err == LCB_SUCCESS) {
                pcbc_document_init(doc, bucket, NULL, 0, 0, res->cas, &res->token TSRMLS_CC);
            } else {
                pcbc_document_init_error(doc, &res->header TSRMLS_CC);
            }
        }
    }

    FOREACH_OPCOOKIE_RES(opcookie_store_res, res, cookie)
    {
        if (res->key) {
            efree(res->key);
        }
        PCBC_RESP_ERR_FREE(res->header);
    }

    return err;
}

// insert($id, $doc {, $expiry, $groupid}) : MetaDoc
PHP_METHOD(Bucket, insert)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    int ii, ncmds, nscheduled;
    pcbc_pp_state pp_state;
    pcbc_pp_id id;
    zval *zvalue, *zexpiry, *zflags, *zgroupid, *zpersist, *zreplica;
    opcookie *cookie;
    lcb_error_t err;
#ifdef LCB_TRACING
    lcbtrace_TRACER *tracer = NULL;
#endif

    // Note that groupid is experimental here and should not be used.
    if (pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id|value|expiry,flags,groupid,persist_to,replicate_to",
                      &id, &zvalue, &zexpiry, &zflags, &zgroupid, &zpersist, &zreplica) != SUCCESS) {
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    ncmds = pcbc_pp_keycount(&pp_state);
    cookie = opcookie_init();
#ifdef LCB_TRACING
    tracer = lcb_get_tracer(obj->conn->lcb);
    if (tracer) {
        cookie->span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_INSERT, 0, NULL);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }
#endif

    nscheduled = 0;
    for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
        lcb_CMDSTOREDUR cmd = {0};
        void *bytes;
        lcb_size_t nbytes;
        int rc;
#ifdef LCB_TRACING
        lcbtrace_SPAN *span = NULL;
#endif

        PCBC_CHECK_ZVAL_LONG(zexpiry, "expiry must be an integer");
        PCBC_CHECK_ZVAL_LONG(zflags, "flags must be an integer");
        PCBC_CHECK_ZVAL_STRING(zgroupid, "groupid must be a string");

        cmd.operation = LCB_ADD;
        LCB_CMD_SET_KEY(&cmd, id.str, id.len);

#ifdef LCB_TRACING
        if (cookie->span) {
            lcbtrace_REF ref;
            ref.type = LCBTRACE_REF_CHILD_OF;
            ref.span = cookie->span;
            span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_REQUEST_ENCODING, LCBTRACE_NOW, &ref);
            lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
            lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        }
#endif
        rc = pcbc_encode_value(obj, zvalue, &bytes, &nbytes, &cmd.flags, &cmd.datatype TSRMLS_CC);
#ifdef LCB_TRACING
        if (span) {
            lcbtrace_span_finish(span, LCBTRACE_NOW);
        }
#endif
        if (rc != SUCCESS) {
            pcbc_log(LOGARGS(obj->conn->lcb, ERROR), "Failed to encode value for before storing");
            err = LCB_ERROR;
            break;
        }
        LCB_CMD_SET_VALUE(&cmd, bytes, nbytes);

        if (zexpiry) {
            cmd.exptime = Z_LVAL_P(zexpiry);
        }
        if (zflags) {
            cmd.flags = Z_LVAL_P(zflags);
        }
        if (zgroupid) {
            LCB_KREQ_SIMPLE(&cmd._hashkey, Z_STRVAL_P(zgroupid), Z_STRLEN_P(zgroupid));
        }
        if (zpersist) {
            cmd.persist_to = (char)Z_LVAL_P(zpersist);
        }
        if (zreplica) {
            cmd.replicate_to = (char)Z_LVAL_P(zreplica);
        }

#ifdef LCB_TRACING
        if (cookie->span) {
            LCB_CMD_SET_TRACESPAN(&cmd, cookie->span);
        }
#endif
        if (cmd.persist_to || cmd.replicate_to) {
            err = lcb_storedur3(obj->conn->lcb, cookie, &cmd);
        } else {
            err = lcb_store3(obj->conn->lcb, cookie, (lcb_CMDSTORE *)&cmd);
        }
        efree(bytes);
        if (err != LCB_SUCCESS) {
            break;
        }
        nscheduled++;
    }
    pcbc_assert_number_of_commands(obj->conn->lcb, "insert", nscheduled, ncmds, err);

    if (nscheduled) {
        lcb_wait(obj->conn->lcb);

        err = proc_store_results(obj, return_value, cookie, pcbc_pp_ismapped(&pp_state) TSRMLS_CC);
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

// upsert($id, $doc {, $expiry, $groupid}) : MetaDoc
PHP_METHOD(Bucket, upsert)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    int ii, ncmds, nscheduled;
    pcbc_pp_state pp_state;
    zval *zvalue, *zexpiry, *zflags, *zgroupid, *zpersist, *zreplica;
    pcbc_pp_id id;
    opcookie *cookie;
    lcb_error_t err;
#ifdef LCB_TRACING
    lcbtrace_TRACER *tracer = NULL;
#endif

    // Note that groupid is experimental here and should not be used.
    if (pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id|value|expiry,flags,groupid,persist_to,replicate_to",
                      &id, &zvalue, &zexpiry, &zflags, &zgroupid, &zpersist, &zreplica) != SUCCESS) {
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    ncmds = pcbc_pp_keycount(&pp_state);
    cookie = opcookie_init();
#ifdef LCB_TRACING
    tracer = lcb_get_tracer(obj->conn->lcb);
    if (tracer) {
        cookie->span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_UPSERT, 0, NULL);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }
#endif

    nscheduled = 0;
    for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
        lcb_CMDSTOREDUR cmd = {0};
        void *bytes;
        lcb_size_t nbytes;
        int rc;
#ifdef LCB_TRACING
        lcbtrace_SPAN *span = NULL;
#endif

        PCBC_CHECK_ZVAL_LONG(zexpiry, "expiry must be an integer");
        PCBC_CHECK_ZVAL_LONG(zflags, "flags must be an integer");
        PCBC_CHECK_ZVAL_STRING(zgroupid, "groupid must be a string");
        PCBC_CHECK_ZVAL_LONG(zpersist, "persist_to must be an integer");
        PCBC_CHECK_ZVAL_LONG(zreplica, "replicate_to must be an integer");

        cmd.operation = LCB_SET;
        LCB_CMD_SET_KEY(&cmd, id.str, id.len);

#ifdef LCB_TRACING
        if (cookie->span) {
            lcbtrace_REF ref;
            ref.type = LCBTRACE_REF_CHILD_OF;
            ref.span = cookie->span;
            span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_REQUEST_ENCODING, LCBTRACE_NOW, &ref);
            lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
            lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        }
#endif
        rc = pcbc_encode_value(obj, zvalue, &bytes, &nbytes, &cmd.flags, &cmd.datatype TSRMLS_CC);
#ifdef LCB_TRACING
        if (span) {
            lcbtrace_span_finish(span, LCBTRACE_NOW);
        }
#endif
        if (rc != SUCCESS) {
            pcbc_log(LOGARGS(obj->conn->lcb, ERROR), "Failed to encode value for before storing");
            err = LCB_ERROR;
            break;
        }
        LCB_CMD_SET_VALUE(&cmd, bytes, nbytes);

        if (zexpiry) {
            cmd.exptime = Z_LVAL_P(zexpiry);
        }
        if (zflags) {
            cmd.flags = Z_LVAL_P(zflags);
        }
        if (zgroupid) {
            LCB_KREQ_SIMPLE(&cmd._hashkey, Z_STRVAL_P(zgroupid), Z_STRLEN_P(zgroupid));
        }
        if (zpersist) {
            cmd.persist_to = (char)Z_LVAL_P(zpersist);
        }
        if (zreplica) {
            cmd.replicate_to = (char)Z_LVAL_P(zreplica);
        }

#ifdef LCB_TRACING
        if (cookie->span) {
            LCB_CMD_SET_TRACESPAN(&cmd, cookie->span);
        }
#endif
        if (cmd.persist_to || cmd.replicate_to) {
            err = lcb_storedur3(obj->conn->lcb, cookie, &cmd);
        } else {
            err = lcb_store3(obj->conn->lcb, cookie, (lcb_CMDSTORE *)&cmd);
        }
        efree(bytes);
        if (err != LCB_SUCCESS) {
            break;
        }
        nscheduled++;
    }
    pcbc_assert_number_of_commands(obj->conn->lcb, "upsert", nscheduled, ncmds, err);

    if (nscheduled) {
        lcb_wait(obj->conn->lcb);

        err = proc_store_results(obj, return_value, cookie, pcbc_pp_ismapped(&pp_state) TSRMLS_CC);
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

// replace($id, $doc {, $cas, $expiry, $groupid}) : MetaDoc
PHP_METHOD(Bucket, replace)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    int ii, ncmds, nscheduled;
    pcbc_pp_state pp_state;
    pcbc_pp_id id;
    zval *zvalue, *zcas, *zexpiry, *zflags, *zgroupid, *zpersist, *zreplica;
    opcookie *cookie;
    lcb_error_t err;
#ifdef LCB_TRACING
    lcbtrace_TRACER *tracer = NULL;
#endif

    // Note that groupid is experimental here and should not be used.
    if (pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id|value|cas,expiry,flags,groupid,persist_to,replicate_to",
                      &id, &zvalue, &zcas, &zexpiry, &zflags, &zgroupid, &zpersist, &zreplica) != SUCCESS) {
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    ncmds = pcbc_pp_keycount(&pp_state);
    cookie = opcookie_init();
#ifdef LCB_TRACING
    tracer = lcb_get_tracer(obj->conn->lcb);
    if (tracer) {
        cookie->span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_REPLACE, 0, NULL);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }
#endif

    nscheduled = 0;
    for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
        lcb_CMDSTOREDUR cmd = {0};
        void *bytes;
        lcb_size_t nbytes;
        int rc;
#ifdef LCB_TRACING
        lcbtrace_SPAN *span = NULL;
#endif

        PCBC_CHECK_ZVAL_STRING(zcas, "cas must be a string");
        PCBC_CHECK_ZVAL_LONG(zexpiry, "expiry must be an integer");
        PCBC_CHECK_ZVAL_LONG(zflags, "flags must be an integer");
        PCBC_CHECK_ZVAL_STRING(zgroupid, "groupid must be a string");
        PCBC_CHECK_ZVAL_LONG(zpersist, "persist_to must be an integer");
        PCBC_CHECK_ZVAL_LONG(zreplica, "replicate_to must be an integer");

        cmd.operation = LCB_REPLACE;
        LCB_CMD_SET_KEY(&cmd, id.str, id.len);

#ifdef LCB_TRACING
        if (cookie->span) {
            lcbtrace_REF ref;
            ref.type = LCBTRACE_REF_CHILD_OF;
            ref.span = cookie->span;
            span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_REQUEST_ENCODING, LCBTRACE_NOW, &ref);
            lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
            lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        }
#endif
        rc = pcbc_encode_value(obj, zvalue, &bytes, &nbytes, &cmd.flags, &cmd.datatype TSRMLS_CC);
#ifdef LCB_TRACING
        if (span) {
            lcbtrace_span_finish(span, LCBTRACE_NOW);
        }
#endif
        if (rc != SUCCESS) {
            pcbc_log(LOGARGS(obj->conn->lcb, ERROR), "Failed to encode value for before storing");
            err = LCB_ERROR;
            break;
        }
        LCB_CMD_SET_VALUE(&cmd, bytes, nbytes);

        if (zcas) {
            cmd.cas = pcbc_cas_decode(zcas TSRMLS_CC);
        }
        if (zexpiry) {
            cmd.exptime = Z_LVAL_P(zexpiry);
        }
        if (zflags) {
            cmd.flags = Z_LVAL_P(zflags);
        }
        if (zgroupid) {
            LCB_KREQ_SIMPLE(&cmd._hashkey, Z_STRVAL_P(zgroupid), Z_STRLEN_P(zgroupid));
        }
        if (zpersist) {
            cmd.persist_to = (char)Z_LVAL_P(zpersist);
        }
        if (zreplica) {
            cmd.replicate_to = (char)Z_LVAL_P(zreplica);
        }

#ifdef LCB_TRACING
        if (cookie->span) {
            LCB_CMD_SET_TRACESPAN(&cmd, cookie->span);
        }
#endif
        if (cmd.persist_to || cmd.replicate_to) {
            err = lcb_storedur3(obj->conn->lcb, cookie, &cmd);
        } else {
            err = lcb_store3(obj->conn->lcb, cookie, (lcb_CMDSTORE *)&cmd);
        }
        efree(bytes);
        if (err != LCB_SUCCESS) {
            break;
        }
        nscheduled++;
    }
    pcbc_assert_number_of_commands(obj->conn->lcb, "replace", nscheduled, ncmds, err);

    if (nscheduled) {
        lcb_wait(obj->conn->lcb);

        err = proc_store_results(obj, return_value, cookie, pcbc_pp_ismapped(&pp_state) TSRMLS_CC);
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

// append($id, $doc {, $cas, $groupid}) : MetaDoc
PHP_METHOD(Bucket, append)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    int ii, ncmds, nscheduled;
    pcbc_pp_state pp_state;
    pcbc_pp_id id;
    zval *zvalue, *zcas, *zgroupid, *zpersist, *zreplica;
    opcookie *cookie;
    lcb_error_t err;
#ifdef LCB_TRACING
    lcbtrace_TRACER *tracer = NULL;
#endif

    // Note that groupid is experimental here and should not be used.
    if (pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id|value|cas,groupid,persist_to,replicate_to", &id,
                      &zvalue, &zcas, &zgroupid, &zpersist, &zreplica) != SUCCESS) {
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    ncmds = pcbc_pp_keycount(&pp_state);
    cookie = opcookie_init();
#ifdef LCB_TRACING
    tracer = lcb_get_tracer(obj->conn->lcb);
    if (tracer) {
        cookie->span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_APPEND, 0, NULL);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }
#endif

    nscheduled = 0;
    for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
        lcb_CMDSTOREDUR cmd = {0};
        void *bytes;
        lcb_size_t nbytes;
        int rc;
#ifdef LCB_TRACING
        lcbtrace_SPAN *span = NULL;
#endif

        PCBC_CHECK_ZVAL_STRING(zcas, "cas must be a string");
        PCBC_CHECK_ZVAL_STRING(zgroupid, "groupid must be a string");
        PCBC_CHECK_ZVAL_LONG(zpersist, "persist_to must be an integer");
        PCBC_CHECK_ZVAL_LONG(zreplica, "replicate_to must be an integer");

        cmd.operation = LCB_APPEND;
        LCB_CMD_SET_KEY(&cmd, id.str, id.len);

#ifdef LCB_TRACING
        if (cookie->span) {
            lcbtrace_REF ref;
            ref.type = LCBTRACE_REF_CHILD_OF;
            ref.span = cookie->span;
            span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_REQUEST_ENCODING, LCBTRACE_NOW, &ref);
            lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
            lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        }
#endif
        rc = pcbc_encode_value(obj, zvalue, &bytes, &nbytes, &cmd.flags, &cmd.datatype TSRMLS_CC);
#ifdef LCB_TRACING
        if (span) {
            lcbtrace_span_finish(span, LCBTRACE_NOW);
        }
#endif
        if (rc != SUCCESS) {
            pcbc_log(LOGARGS(obj->conn->lcb, ERROR), "Failed to encode value for before storing");
            err = LCB_ERROR;
            break;
        }
        LCB_CMD_SET_VALUE(&cmd, bytes, nbytes);

        if (zcas) {
            cmd.cas = pcbc_cas_decode(zcas TSRMLS_CC);
        }
        if (zgroupid) {
            LCB_KREQ_SIMPLE(&cmd._hashkey, Z_STRVAL_P(zgroupid), Z_STRLEN_P(zgroupid));
        }
        if (zpersist) {
            cmd.persist_to = (char)Z_LVAL_P(zpersist);
        }
        if (zreplica) {
            cmd.replicate_to = (char)Z_LVAL_P(zreplica);
        }

        // Flags ignored for this op, enforced by libcouchbase
        cmd.flags = 0;

#ifdef LCB_TRACING
        if (cookie->span) {
            LCB_CMD_SET_TRACESPAN(&cmd, cookie->span);
        }
#endif
        if (cmd.persist_to || cmd.replicate_to) {
            err = lcb_storedur3(obj->conn->lcb, cookie, &cmd);
        } else {
            err = lcb_store3(obj->conn->lcb, cookie, (lcb_CMDSTORE *)&cmd);
        }
        efree(bytes);
        if (err != LCB_SUCCESS) {
            break;
        }
        nscheduled++;
    }
    pcbc_assert_number_of_commands(obj->conn->lcb, "append", nscheduled, ncmds, err);

    if (nscheduled) {
        lcb_wait(obj->conn->lcb);

        err = proc_store_results(obj, return_value, cookie, pcbc_pp_ismapped(&pp_state) TSRMLS_CC);
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

// prepend($id, $doc {, $cas, $groupid}) : MetaDoc
PHP_METHOD(Bucket, prepend)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    int ii, ncmds, nscheduled;
    pcbc_pp_state pp_state;
    pcbc_pp_id id;
    zval *zvalue, *zcas, *zgroupid, *zpersist, *zreplica;
    opcookie *cookie;
    lcb_error_t err = LCB_SUCCESS;
#ifdef LCB_TRACING
    lcbtrace_TRACER *tracer = NULL;
#endif

    // Note that groupid is experimental here and should not be used.
    if (pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id|value|cas,groupid,persist_to,replicate_to", &id,
                      &zvalue, &zcas, &zgroupid, &zpersist, &zreplica) != SUCCESS) {
        throw_pcbc_exception("Invalid arguments.", LCB_EINVAL);
        RETURN_NULL();
    }

    ncmds = pcbc_pp_keycount(&pp_state);
    cookie = opcookie_init();
#ifdef LCB_TRACING
    tracer = lcb_get_tracer(obj->conn->lcb);
    if (tracer) {
        cookie->span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_PREPEND, 0, NULL);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(cookie->span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
    }
#endif

    nscheduled = 0;
    for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
        lcb_CMDSTOREDUR cmd = {0};
        void *bytes;
        lcb_size_t nbytes;
        int rc;
#ifdef LCB_TRACING
        lcbtrace_SPAN *span = NULL;
#endif

        PCBC_CHECK_ZVAL_STRING(zcas, "cas must be a string");
        PCBC_CHECK_ZVAL_STRING(zgroupid, "groupid must be a string");
        PCBC_CHECK_ZVAL_LONG(zpersist, "persist_to must be an integer");
        PCBC_CHECK_ZVAL_LONG(zreplica, "replicate_to must be an integer");

        cmd.operation = LCB_PREPEND;
        LCB_CMD_SET_KEY(&cmd, id.str, id.len);

#ifdef LCB_TRACING
        if (cookie->span) {
            lcbtrace_REF ref;
            ref.type = LCBTRACE_REF_CHILD_OF;
            ref.span = cookie->span;
            span = lcbtrace_span_start(tracer, "php/" LCBTRACE_OP_REQUEST_ENCODING, LCBTRACE_NOW, &ref);
            lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
            lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_KV);
        }
#endif
        rc = pcbc_encode_value(obj, zvalue, &bytes, &nbytes, &cmd.flags, &cmd.datatype TSRMLS_CC);
#ifdef LCB_TRACING
        if (span) {
            lcbtrace_span_finish(span, LCBTRACE_NOW);
        }
#endif
        if (rc != SUCCESS) {
            pcbc_log(LOGARGS(obj->conn->lcb, ERROR), "Failed to encode value for before storing");
            err = LCB_ERROR;
            break;
        }
        LCB_CMD_SET_VALUE(&cmd, bytes, nbytes);

        if (zcas) {
            cmd.cas = pcbc_cas_decode(zcas TSRMLS_CC);
        }
        if (zgroupid) {
            LCB_KREQ_SIMPLE(&cmd._hashkey, Z_STRVAL_P(zgroupid), Z_STRLEN_P(zgroupid));
        }
        if (zpersist) {
            cmd.persist_to = (char)Z_LVAL_P(zpersist);
        }
        if (zreplica) {
            cmd.replicate_to = (char)Z_LVAL_P(zreplica);
        }

        // Flags ignored for this op, enforced by libcouchbase
        cmd.flags = 0;

#ifdef LCB_TRACING
        if (cookie->span) {
            LCB_CMD_SET_TRACESPAN(&cmd, cookie->span);
        }
#endif
        if (cmd.persist_to || cmd.replicate_to) {
            err = lcb_storedur3(obj->conn->lcb, cookie, &cmd);
        } else {
            err = lcb_store3(obj->conn->lcb, cookie, (lcb_CMDSTORE *)&cmd);
        }
        efree(bytes);
        if (err != LCB_SUCCESS) {
            break;
        }
        nscheduled++;
    }
    pcbc_assert_number_of_commands(obj->conn->lcb, "prepend", nscheduled, ncmds, err);

    if (nscheduled) {
        lcb_wait(obj->conn->lcb);

        err = proc_store_results(obj, return_value, cookie, pcbc_pp_ismapped(&pp_state) TSRMLS_CC);
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
