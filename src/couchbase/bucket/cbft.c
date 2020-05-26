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

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/cbft", __FILE__, __LINE__

extern zend_class_entry *pcbc_search_result_impl_ce;
extern zend_class_entry *pcbc_search_meta_data_impl_ce;

struct search_cookie {
    lcb_STATUS rc;
    zval *return_value;
};

static void ftsrow_callback(lcb_INSTANCE *instance, int ignoreme, const lcb_RESPSEARCH *resp)
{
    TSRMLS_FETCH();

    struct search_cookie *cookie;
    lcb_respsearch_cookie(resp, (void **)&cookie);
    cookie->rc = lcb_respsearch_status(resp);
    zval *return_value = cookie->return_value;

    zend_update_property_long(pcbc_search_result_impl_ce, return_value, ZEND_STRL("status"), cookie->rc TSRMLS_CC);

    const char *row = NULL;
    size_t nrow = 0;
    lcb_respsearch_row(resp, &row, &nrow);

    if (nrow > 0) {
        zval value;
        ZVAL_NULL(&value);

        int last_error;
        PCBC_JSON_COPY_DECODE(&value, row, nrow, PHP_JSON_OBJECT_AS_ARRAY, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(instance, WARN), "Failed to decode FTS response as JSON: json_last_error=%d", last_error);
        }
        if (lcb_respsearch_is_final(resp)) {
            zval meta, *mval, *mstatus;
            object_init_ex(&meta, pcbc_search_meta_data_impl_ce);
            HashTable *marr = Z_ARRVAL(value);

            mval = zend_symtable_str_find(marr, ZEND_STRL("took"));
            if (mval) {
                zend_update_property(pcbc_search_meta_data_impl_ce, &meta, ZEND_STRL("took"), mval TSRMLS_CC);
            }
            mval = zend_symtable_str_find(marr, ZEND_STRL("total_hits"));
            if (mval) {
                zend_update_property(pcbc_search_meta_data_impl_ce, &meta, ZEND_STRL("total_hits"), mval TSRMLS_CC);
            }
            mval = zend_symtable_str_find(marr, ZEND_STRL("max_score"));
            if (mval) {
                zend_update_property(pcbc_search_meta_data_impl_ce, &meta, ZEND_STRL("max_score"), mval TSRMLS_CC);
            }
            mval = zend_symtable_str_find(marr, ZEND_STRL("metrics"));
            if (mval) {
                zend_update_property(pcbc_search_meta_data_impl_ce, &meta, ZEND_STRL("metrics"), mval TSRMLS_CC);
            }

            mstatus = zend_symtable_str_find(marr, ZEND_STRL("status"));
            if (mstatus) {
                switch (Z_TYPE_P(mstatus)) {
                case IS_STRING:
                    // TODO: read and expose value in "error" key
                    zend_update_property_stringl(pcbc_search_meta_data_impl_ce, &meta, ZEND_STRL("status"),
                                                 Z_STRVAL_P(mstatus), Z_STRLEN_P(mstatus) TSRMLS_CC);
                    break;
                case IS_ARRAY:
                    zend_update_property_string(pcbc_search_meta_data_impl_ce, &meta, ZEND_STRL("status"),
                                                "success" TSRMLS_CC);
                    mval = zend_symtable_str_find(Z_ARRVAL_P(mstatus), ZEND_STRL("successful"));
                    if (mval) {
                        zend_update_property(pcbc_search_meta_data_impl_ce, &meta, ZEND_STRL("success_count"),
                                             mval TSRMLS_CC);
                    }
                    mval = zend_symtable_str_find(Z_ARRVAL_P(mstatus), ZEND_STRL("failed"));
                    if (mval) {
                        zend_update_property(pcbc_search_meta_data_impl_ce, &meta, ZEND_STRL("error_count"),
                                             mval TSRMLS_CC);
                    }
                    break;
                }
            }
            zend_update_property(pcbc_search_result_impl_ce, return_value, ZEND_STRL("meta"), &meta TSRMLS_CC);
            mval = zend_symtable_str_find(marr, ZEND_STRL("facets"));
            if (mval) {
                zend_update_property(pcbc_search_result_impl_ce, return_value, ZEND_STRL("facets"), mval TSRMLS_CC);
            }
            zval_ptr_dtor(&meta);
            zval_dtor(&value);
        } else {
            zval *hits, rv;
            hits = zend_read_property(pcbc_search_result_impl_ce, return_value, ZEND_STRL("rows"), 0, &rv);
            add_next_index_zval(hits, &value);
        }
    }
}

PHP_METHOD(Cluster, searchQuery)
{
    lcb_STATUS err;
    zend_string *index;
    zval *query;
    zval *options = NULL;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "SO|O!", &index, &query, pcbc_search_query_ce, &options,
                               pcbc_search_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zval payload;
    array_init(&payload);
    add_assoc_str(&payload, "indexName", index);
    add_assoc_zval(&payload, "query", query);
    Z_ADDREF_P(query);
    if (options && Z_TYPE_P(options) != IS_NULL) {
        zval fname;
        zval values;
        PCBC_STRING(fname, "jsonSerialize");
        ZVAL_UNDEF(&values);
        rv = call_user_function_ex(EG(function_table), options, &fname, &values, 0, NULL, 1, NULL TSRMLS_CC);
        if (rv != FAILURE && !EG(exception) && !Z_ISUNDEF(values)) {
            zend_hash_merge(HASH_OF(&payload), HASH_OF(&values), NULL, 0);
        }
    }

    pcbc_cluster_t *cluster = Z_CLUSTER_OBJ_P(getThis());

    lcb_CMDSEARCH *cmd;
    lcb_cmdsearch_create(&cmd);
    lcb_cmdsearch_callback(cmd, ftsrow_callback);

    smart_str buf = {0};
    int last_error;
    PCBC_JSON_ENCODE(&buf, &payload, 0, last_error);
    zval_dtor(&payload);
    if (last_error != 0) {
        pcbc_log(LOGARGS(cluster->conn->lcb, WARN), "Failed to encode FTS query as JSON: json_last_error=%d",
                 last_error);
        smart_str_free(&buf);
        RETURN_NULL();
    }
    smart_str_0(&buf);
    lcb_cmdsearch_payload(cmd, ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));

    object_init_ex(return_value, pcbc_search_result_impl_ce);
    zval hits;
    array_init(&hits);
    zend_update_property(pcbc_search_result_impl_ce, return_value, ZEND_STRL("rows"), &hits TSRMLS_CC);
    Z_DELREF(hits);
    struct search_cookie cookie = {LCB_SUCCESS, return_value};

    lcb_SEARCH_HANDLE *handle = NULL;
    lcb_cmdsearch_handle(cmd, &handle);
    lcbtrace_SPAN *span = NULL;
    lcbtrace_TRACER *tracer = lcb_get_tracer(cluster->conn->lcb);
    if (tracer) {
        span = lcbtrace_span_start(tracer, "php/search", 0, NULL);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_COMPONENT, pcbc_client_string);
        lcbtrace_span_add_tag_str(span, LCBTRACE_TAG_SERVICE, LCBTRACE_TAG_SERVICE_SEARCH);
        lcb_cmdsearch_parent_span(cmd, span);
    }
    err = lcb_search(cluster->conn->lcb, &cookie, cmd);
    lcb_cmdsearch_destroy(cmd);
    smart_str_free(&buf);
    if (err == LCB_SUCCESS) {
        lcb_wait(cluster->conn->lcb, LCB_WAIT_DEFAULT);
        err = cookie.rc;
    }
    if (span) {
        lcbtrace_span_finish(span, LCBTRACE_NOW);
    }
    if (err != LCB_SUCCESS) {
        throw_lcb_exception(err, NULL);
    }
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
