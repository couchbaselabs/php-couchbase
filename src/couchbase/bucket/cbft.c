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
extern zend_class_entry *pcbc_search_facet_result_impl_ce;
extern zend_class_entry *pcbc_term_facet_result_impl_ce;
extern zend_class_entry *pcbc_numeric_range_facet_result_impl_ce;
extern zend_class_entry *pcbc_date_range_facet_result_impl_ce;

struct search_cookie {
    lcb_STATUS rc;
    zval *return_value;
};

static void ftsrow_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPSEARCH *resp)
{
    (void)cbtype;
    struct search_cookie *cookie;
    lcb_respsearch_cookie(resp, (void **)&cookie);
    cookie->rc = lcb_respsearch_status(resp);
    zval *return_value = cookie->return_value;

    pcbc_update_property_long(pcbc_search_result_impl_ce, return_value, ("status"), cookie->rc);

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
                pcbc_update_property(pcbc_search_meta_data_impl_ce, &meta, ("took"), mval);
            }
            mval = zend_symtable_str_find(marr, ZEND_STRL("total_hits"));
            if (mval) {
                pcbc_update_property(pcbc_search_meta_data_impl_ce, &meta, ("total_hits"), mval);
            }
            mval = zend_symtable_str_find(marr, ZEND_STRL("max_score"));
            if (mval) {
                pcbc_update_property(pcbc_search_meta_data_impl_ce, &meta, ("max_score"), mval);
            }
            mval = zend_symtable_str_find(marr, ZEND_STRL("metrics"));
            if (mval) {
                pcbc_update_property(pcbc_search_meta_data_impl_ce, &meta, ("metrics"), mval);
            }

            mstatus = zend_symtable_str_find(marr, ZEND_STRL("status"));
            if (mstatus) {
                switch (Z_TYPE_P(mstatus)) {
                case IS_STRING:
                    // TODO: read and expose value in "error" key
                    pcbc_update_property_stringl(pcbc_search_meta_data_impl_ce, &meta, ("status"), Z_STRVAL_P(mstatus),
                                                 Z_STRLEN_P(mstatus));
                    break;
                case IS_ARRAY:
                    pcbc_update_property_string(pcbc_search_meta_data_impl_ce, &meta, ("status"), "success");
                    mval = zend_symtable_str_find(Z_ARRVAL_P(mstatus), ZEND_STRL("successful"));
                    if (mval) {
                        pcbc_update_property(pcbc_search_meta_data_impl_ce, &meta, ("success_count"), mval);
                    }
                    mval = zend_symtable_str_find(Z_ARRVAL_P(mstatus), ZEND_STRL("failed"));
                    if (mval) {
                        pcbc_update_property(pcbc_search_meta_data_impl_ce, &meta, ("error_count"), mval);
                    }
                    break;
                }
            }
            pcbc_update_property(pcbc_search_result_impl_ce, return_value, ("meta"), &meta);
            zval_ptr_dtor(&meta);
            mval = zend_symtable_str_find(marr, ZEND_STRL("facets"));
            if (mval && Z_TYPE_P(mval) == IS_ARRAY) {
                zval facets;
                array_init(&facets);
                zend_string *string_key = NULL;
                zval *entry;
                ZEND_HASH_FOREACH_STR_KEY_VAL(HASH_OF(mval), string_key, entry)
                {
                    if (string_key) {
                        zval facet_result;
                        object_init_ex(&facet_result, pcbc_search_facet_result_impl_ce);

                        zval *eval;
                        HashTable *earr = Z_ARRVAL_P(entry);

                        pcbc_update_property_str(pcbc_search_facet_result_impl_ce, &facet_result, ("name"), string_key);
                        eval = zend_symtable_str_find(earr, ZEND_STRL("field"));
                        if (eval && Z_TYPE_P(eval) == IS_STRING) {
                            pcbc_update_property(pcbc_search_facet_result_impl_ce, &facet_result, ("field"), eval);
                        }
                        eval = zend_symtable_str_find(earr, ZEND_STRL("total"));
                        if (eval && Z_TYPE_P(eval) == IS_LONG) {
                            pcbc_update_property(pcbc_search_facet_result_impl_ce, &facet_result, ("total"), eval);
                        }
                        eval = zend_symtable_str_find(earr, ZEND_STRL("missing"));
                        if (eval && Z_TYPE_P(eval) == IS_LONG) {
                            pcbc_update_property(pcbc_search_facet_result_impl_ce, &facet_result, ("missing"), eval);
                        }
                        eval = zend_symtable_str_find(earr, ZEND_STRL("other"));
                        if (eval && Z_TYPE_P(eval) == IS_LONG) {
                            pcbc_update_property(pcbc_search_facet_result_impl_ce, &facet_result, ("other"), eval);
                        }
                        eval = zend_symtable_str_find(earr, ZEND_STRL("terms"));
                        if (eval && Z_TYPE_P(eval) == IS_ARRAY) {
                            zval terms;
                            array_init(&terms);
                            zval *terms_entry;
                            ZEND_HASH_FOREACH_VAL(HASH_OF(eval), terms_entry)
                            {
                                HashTable *terms_arr = Z_ARRVAL_P(terms_entry);
                                zval term_result;
                                object_init_ex(&term_result, pcbc_term_facet_result_impl_ce);
                                eval = zend_symtable_str_find(terms_arr, ZEND_STRL("term"));
                                if (eval && Z_TYPE_P(eval) == IS_STRING) {
                                    pcbc_update_property(pcbc_term_facet_result_impl_ce, &term_result, ("term"), eval);
                                }
                                eval = zend_symtable_str_find(terms_arr, ZEND_STRL("count"));
                                if (eval && Z_TYPE_P(eval) == IS_LONG) {
                                    pcbc_update_property(pcbc_term_facet_result_impl_ce, &term_result, ("count"), eval);
                                }
                                add_next_index_zval(&terms, &term_result);
                            }
                            ZEND_HASH_FOREACH_END();
                            pcbc_update_property(pcbc_search_facet_result_impl_ce, &facet_result, ("terms"), &terms);
                            zval_ptr_dtor(&terms);
                        }
                        eval = zend_symtable_str_find(earr, ZEND_STRL("numeric_ranges"));
                        if (eval && Z_TYPE_P(eval) == IS_ARRAY) {
                            zval numeric_ranges;
                            array_init(&numeric_ranges);
                            zval *numeric_ranges_entry;
                            ZEND_HASH_FOREACH_VAL(HASH_OF(eval), numeric_ranges_entry)
                            {
                                HashTable *numeric_ranges_arr = Z_ARRVAL_P(numeric_ranges_entry);
                                zval numeric_range_result;
                                object_init_ex(&numeric_range_result, pcbc_numeric_range_facet_result_impl_ce);
                                eval = zend_symtable_str_find(numeric_ranges_arr, ZEND_STRL("name"));
                                if (eval && Z_TYPE_P(eval) == IS_STRING) {
                                    pcbc_update_property(pcbc_numeric_range_facet_result_impl_ce, &numeric_range_result,
                                                         ("name"), eval);
                                }
                                eval = zend_symtable_str_find(numeric_ranges_arr, ZEND_STRL("min"));
                                if (eval && (Z_TYPE_P(eval) == IS_LONG || Z_TYPE_P(eval) == IS_DOUBLE)) {
                                    pcbc_update_property(pcbc_numeric_range_facet_result_impl_ce, &numeric_range_result,
                                                         ("min"), eval);
                                }
                                eval = zend_symtable_str_find(numeric_ranges_arr, ZEND_STRL("max"));
                                if (eval && (Z_TYPE_P(eval) == IS_LONG || Z_TYPE_P(eval) == IS_DOUBLE)) {
                                    pcbc_update_property(pcbc_numeric_range_facet_result_impl_ce, &numeric_range_result,
                                                         ("max"), eval);
                                }
                                eval = zend_symtable_str_find(numeric_ranges_arr, ZEND_STRL("count"));
                                if (eval && Z_TYPE_P(eval) == IS_LONG) {
                                    pcbc_update_property(pcbc_numeric_range_facet_result_impl_ce, &numeric_range_result,
                                                         ("count"), eval);
                                }
                                add_next_index_zval(&numeric_ranges, &numeric_range_result);
                            }
                            ZEND_HASH_FOREACH_END();
                            pcbc_update_property(pcbc_search_facet_result_impl_ce, &facet_result, ("numeric_ranges"),
                                                 &numeric_ranges);
                            zval_ptr_dtor(&numeric_ranges);
                        }
                        eval = zend_symtable_str_find(earr, ZEND_STRL("date_ranges"));
                        if (eval && Z_TYPE_P(eval) == IS_ARRAY) {
                            zval date_ranges;
                            array_init(&date_ranges);
                            zval *date_ranges_entry;
                            ZEND_HASH_FOREACH_VAL(HASH_OF(eval), date_ranges_entry)
                            {
                                HashTable *date_ranges_arr = Z_ARRVAL_P(date_ranges_entry);
                                zval date_range_result;
                                object_init_ex(&date_range_result, pcbc_date_range_facet_result_impl_ce);
                                eval = zend_symtable_str_find(date_ranges_arr, ZEND_STRL("name"));
                                if (eval && Z_TYPE_P(eval) == IS_STRING) {
                                    pcbc_update_property(pcbc_date_range_facet_result_impl_ce, &date_range_result,
                                                         ("name"), eval);
                                }
                                eval = zend_symtable_str_find(date_ranges_arr, ZEND_STRL("start"));
                                if (eval && Z_TYPE_P(eval) == IS_STRING) {
                                    pcbc_update_property(pcbc_date_range_facet_result_impl_ce, &date_range_result,
                                                         ("start"), eval);
                                }
                                eval = zend_symtable_str_find(date_ranges_arr, ZEND_STRL("end"));
                                if (eval && Z_TYPE_P(eval) == IS_STRING) {
                                    pcbc_update_property(pcbc_date_range_facet_result_impl_ce, &date_range_result,
                                                         ("end"), eval);
                                }
                                eval = zend_symtable_str_find(date_ranges_arr, ZEND_STRL("count"));
                                if (eval && Z_TYPE_P(eval) == IS_LONG) {
                                    pcbc_update_property(pcbc_date_range_facet_result_impl_ce, &date_range_result,
                                                         ("count"), eval);
                                }
                                add_next_index_zval(&date_ranges, &date_range_result);
                            }
                            ZEND_HASH_FOREACH_END();
                            pcbc_update_property(pcbc_search_facet_result_impl_ce, &facet_result, ("date_ranges"),
                                                 &date_ranges);
                            zval_ptr_dtor(&date_ranges);
                        }
                        add_assoc_zval_ex(&facets, ZSTR_VAL(string_key), ZSTR_LEN(string_key), &facet_result);
                    }
                }
                ZEND_HASH_FOREACH_END();
                pcbc_update_property(pcbc_search_result_impl_ce, return_value, ("facets"), &facets);
                zval_ptr_dtor(&facets);
            }
            zval_dtor(&value);
        } else {
            zval *hits, rv;
            hits = pcbc_read_property(pcbc_search_result_impl_ce, return_value, ("rows"), 0, &rv);
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

    rv = zend_parse_parameters(ZEND_NUM_ARGS(), "SO|O!", &index, &query, pcbc_search_query_ce, &options,
                               pcbc_search_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    zval payload, options_payload;
    array_init(&payload);
    add_assoc_str(&payload, "indexName", index);
    add_assoc_zval(&payload, "query", query);
    Z_ADDREF_P(query);
    ZVAL_UNDEF(&options_payload);
    if (options && Z_TYPE_P(options) != IS_NULL) {
        zval fname;
        PCBC_STRING(fname, "jsonSerialize");
        rv = call_user_function(EG(function_table), options, &fname, &options_payload, 0, NULL);
        if (rv != FAILURE && !EG(exception) && !Z_ISUNDEF(options_payload)) {
            zend_hash_merge(HASH_OF(&payload), HASH_OF(&options_payload), zval_add_ref, 0);
        }
        zval_dtor(&fname);
    }

    pcbc_cluster_t *cluster = Z_CLUSTER_OBJ_P(getThis());

    lcb_CMDSEARCH *cmd;
    lcb_cmdsearch_create(&cmd);
    lcb_cmdsearch_callback(cmd, ftsrow_callback);

    smart_str buf = {0};
    int last_error;
    PCBC_JSON_ENCODE(&buf, &payload, 0, last_error);
    zval_dtor(&payload);
    zval_dtor(&options_payload);
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
    pcbc_update_property(pcbc_search_result_impl_ce, return_value, ("rows"), &hits);
    zval_dtor(&hits);
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
