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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/http", __FILE__, __LINE__

extern zend_class_entry *pcbc_default_exception_ce;
extern zend_class_entry *pcbc_http_exception_ce;

typedef struct {
    opcookie_res header;
    zval bytes;
} opcookie_http_res;

void http_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPHTTP *resp)
{
    opcookie_http_res *result = ecalloc(1, sizeof(opcookie_http_res));

    result->header.err = lcb_resphttp_status(resp);
    if (result->header.err != LCB_SUCCESS) {
        pcbc_log(LOGARGS(instance, WARN), "Failed to perform HTTP request: rc=%d", (int)result->header.err);
    }
    opcookie *cookie;
    lcb_resphttp_cookie(resp, (void **)&cookie);

    ZVAL_UNDEF(&result->bytes);
    const char *body = NULL;
    size_t nbody = 0;
    lcb_resphttp_body(resp, &body, &nbody);
    if (nbody) {
        if (cookie->json_response) {
            int last_error;

            PCBC_JSON_COPY_DECODE(&result->bytes, body, nbody, PHP_JSON_OBJECT_AS_ARRAY, last_error);
            if (last_error != 0) {
                pcbc_log(LOGARGS(instance, WARN), "Failed to decode value as JSON: json_last_error=%d", last_error);
                ZVAL_NULL(&result->bytes);
            }
        } else {
            PCBC_STRINGL(result->bytes, body, nbody);
        }
    } else {
        ZVAL_NULL(&result->bytes);
    }

    opcookie_push(cookie, &result->header);
}

static lcb_STATUS proc_http_results(zval *return_value, opcookie *cookie, void *ctx,
                                    void(httpcb)(void *ctx, zval *, zval *))
{
    opcookie_http_res *res;
    lcb_STATUS err = LCB_SUCCESS;

    // Any error should cause everything to fail... for now?
    err = opcookie_get_first_error(cookie);

    if (err == LCB_SUCCESS) {
        int has_value = 0;
        FOREACH_OPCOOKIE_RES(opcookie_http_res, res, cookie)
        {
            if (has_value == 0) {
                if (Z_TYPE(res->bytes) == IS_ARRAY) {
                    zend_long first_query_code = 0;
                    HashTable *marr = Z_ARRVAL(res->bytes);
                    zval *mval;
                    mval = zend_symtable_str_find(marr, ZEND_STRL("errors"));
                    if (mval && Z_TYPE_P(mval) == IS_ARRAY) {
                        smart_str buf = {0};
                        zend_ulong num;
                        zend_string *string_key = NULL;
                        zval *entry;
                        ZEND_HASH_FOREACH_KEY_VAL(HASH_OF(mval), num, string_key, entry)
                        {
                            (void)num;
                            if (string_key) {
                                smart_str_append_ex(&buf, string_key, 0);
                                if (Z_TYPE_P(entry) == IS_STRING) {
                                    smart_str_appends(&buf, ": ");
                                    smart_str_append_ex(&buf, Z_STR_P(entry), 0);
                                }
                                smart_str_appends(&buf, ", ");
                            } else {
                                if (Z_TYPE_P(entry) == IS_ARRAY) {
                                    zval *code = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("code"));
                                    zval *msg = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("msg"));
                                    if (code && Z_TYPE_P(code) == IS_LONG) {
                                        if (first_query_code == 0) {
                                            first_query_code = Z_LVAL_P(code);
                                        }
                                        smart_str_append_printf(&buf, "%d: ", (int)Z_LVAL_P(code));
                                    }
                                    if (msg && Z_TYPE_P(msg) == IS_STRING) {
                                        smart_str_append_ex(&buf, Z_STR_P(msg), 0);
                                    }
                                    smart_str_appends(&buf, ", ");
                                }
                            }
                        }
                        ZEND_HASH_FOREACH_END();
                        if (buf.s && ZSTR_LEN(buf.s) > 2) {
                            ZSTR_LEN(buf.s) -= 2;
                            ZSTR_VAL(buf.s)[ZSTR_LEN(buf.s)] = '\0';
                        }
                        object_init_ex(return_value, pcbc_http_exception_ce);
                        pcbc_update_property_str(pcbc_default_exception_ce, return_value, ("message"),
                                                 buf.s);
                        if (first_query_code) {
                            pcbc_update_property_long(pcbc_default_exception_ce, return_value, ("code"),
                                                      first_query_code);
                        }
                        smart_str_free(&buf);
                        err = LCB_ERR_HTTP;
                    } else {
                        mval = zend_symtable_str_find(marr, ZEND_STRL("status"));
                        if (mval && Z_TYPE_P(mval) == IS_STRING) {
                            if (zend_binary_strcmp("fail", 4, Z_STRVAL_P(mval), Z_STRLEN_P(mval)) == 0) {
                                object_init_ex(return_value, pcbc_http_exception_ce);
                                mval = zend_symtable_str_find(marr, ZEND_STRL("error"));
                                if (mval && Z_TYPE_P(mval) == IS_STRING) {
                                    pcbc_update_property(pcbc_default_exception_ce, return_value, ("message"),
                                                         mval);
                                }
                                err = LCB_ERR_HTTP;
                            }
                        }
                    }
                }
                if (err == LCB_SUCCESS) {
                    if (httpcb) {
                        httpcb(ctx, return_value, &res->bytes);
                    } else {
                        ZVAL_ZVAL(return_value, &res->bytes, 1, 0);
                    }
                }
                has_value = 1;
            } else {
                err = LCB_ERR_GENERIC;
                break;
            }
        }
    }

    FOREACH_OPCOOKIE_RES(opcookie_http_res, res, cookie)
    {
        zval_ptr_dtor(&res->bytes);
    }

    return err;
}

void pcbc_http_request(zval *return_value, lcb_INSTANCE *conn, lcb_CMDHTTP *cmd, int json_response, void *cbctx,
                       void(httpcb)(void *, zval *, zval *), int(errorcb)(void *, zval *))
{
    lcb_STATUS err;
    opcookie *cookie;

    cookie = opcookie_init();
    cookie->json_response = json_response;
    err = lcb_http(conn, cookie, cmd);
    lcb_cmdhttp_destroy(cmd);
    if (err == LCB_SUCCESS) {
        lcb_wait(conn, LCB_WAIT_DEFAULT);
        err = proc_http_results(return_value, cookie, cbctx, httpcb);
    }
    opcookie_destroy(cookie);

    if (Z_TYPE_P(return_value) == IS_OBJECT &&
        instanceof_function(Z_OBJCE_P(return_value), pcbc_default_exception_ce)) {
        if (errorcb && errorcb(cbctx, return_value) == 0) {
            zval_dtor(return_value);
            RETURN_NULL();
        }
        zend_throw_exception_object(return_value);
        RETURN_NULL();
    } else if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, NULL);
    }
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
