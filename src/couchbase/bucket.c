/**
 *     Copyright 2017 Couchbase, Inc.
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

#define LOGARGS(obj, lvl) LCB_LOG_##lvl, obj->conn->lcb, "pcbc/bucket", __FILE__, __LINE__

zend_class_entry *pcbc_bucket_ce;
extern zend_class_entry *pcbc_classic_authenticator_ce;
extern zend_class_entry *pcbc_password_authenticator_ce;

PHP_METHOD(Bucket, get);
PHP_METHOD(Bucket, getAndLock);
PHP_METHOD(Bucket, getAndTouch);
PHP_METHOD(Bucket, getFromReplica);
PHP_METHOD(Bucket, insert);
PHP_METHOD(Bucket, upsert);
PHP_METHOD(Bucket, replace);
PHP_METHOD(Bucket, append);
PHP_METHOD(Bucket, prepend);
PHP_METHOD(Bucket, unlock);
PHP_METHOD(Bucket, remove);
PHP_METHOD(Bucket, touch);
PHP_METHOD(Bucket, counter);
PHP_METHOD(Bucket, n1ql_request);
PHP_METHOD(Bucket, fts_request);
PHP_METHOD(Bucket, n1ix_list);
PHP_METHOD(Bucket, n1ix_create);
PHP_METHOD(Bucket, n1ix_drop);
PHP_METHOD(Bucket, http_request);
PHP_METHOD(Bucket, durability);

/* {{{ proto void Bucket::__construct()
   Should not be called directly */
PHP_METHOD(Bucket, __construct)
{
    throw_pcbc_exception("Accessing private constructor.", LCB_EINVAL);
}
/* }}} */

/* {{{ proto void Bucket::setTranscoder(callable $encoder, callable $decoder)
   Sets custom encoder and decoder functions for handling serialization */
PHP_METHOD(Bucket, setTranscoder)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    zval *encoder, *decoder;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &encoder, &decoder);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    if (!Z_ISUNDEF(obj->encoder)) {
        zval_ptr_dtor(&obj->encoder);
        ZVAL_UNDEF(PCBC_P(obj->encoder));
    }
#if PHP_VERSION_ID >= 70000
    ZVAL_ZVAL(&obj->encoder, encoder, 1, 0);
#else
    PCBC_ADDREF_P(encoder);
    obj->encoder = encoder;
#endif

    if (!Z_ISUNDEF(obj->decoder)) {
        zval_ptr_dtor(&obj->decoder);
        ZVAL_UNDEF(PCBC_P(obj->decoder));
    }
#if PHP_VERSION_ID >= 70000
    ZVAL_ZVAL(&obj->decoder, decoder, 1, 0);
#else
    PCBC_ADDREF_P(decoder);
    obj->decoder = decoder;
#endif

    RETURN_NULL();
}
/* }}} */

/* {{{ proto \Couchbase\LookupInBuilder Bucket::lookupIn(string $id) */
PHP_METHOD(Bucket, lookupIn)
{
    char *id = NULL;
    pcbc_str_arg_size id_len = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &id, &id_len);
    if (rv == FAILURE) {
        return;
    }
    pcbc_lookup_in_builder_init(return_value, getThis(), id, id_len, NULL, 0 TSRMLS_CC);
} /* }}} */

/* {{{ proto \Couchbase\LookupInBuilder Bucket::retrieveIn(string $id, string ...$paths) */
PHP_METHOD(Bucket, retrieveIn)
{
    pcbc_bucket_t *obj;
    const char *id = NULL;
#if PHP_VERSION_ID >= 70000
    zval *args = NULL;
#else
    zval ***args = NULL;
#endif
    pcbc_str_arg_size id_len = 0, num_args = 0;
    int rv;
    PCBC_ZVAL builder;

    obj = Z_BUCKET_OBJ_P(getThis());

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s+", &id, &id_len, &args, &num_args);
    if (rv == FAILURE) {
        return;
    }
    if (num_args == 0) {
        throw_pcbc_exception("retrieveIn() requires at least one path specified", LCB_EINVAL);
        RETURN_NULL();
    }
    PCBC_ZVAL_ALLOC(builder);
    pcbc_lookup_in_builder_init(PCBC_P(builder), getThis(), id, id_len, args, num_args TSRMLS_CC);
#if PHP_VERSION_ID < 70000
    if (args) {
        efree(args);
    }
#endif
    pcbc_bucket_subdoc_request(obj, Z_LOOKUP_IN_BUILDER_OBJ_P(PCBC_P(builder)), 1, return_value TSRMLS_CC);
    zval_ptr_dtor(&builder);
} /* }}} */

/* {{{ proto \Couchbase\MutateInBuilder Bucket::mutateIn(string $id, string $cas) */
PHP_METHOD(Bucket, mutateIn)
{
    char *id = NULL, *cas = NULL;
    pcbc_str_arg_size id_len = 0, cas_len = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &id, &id_len, &cas, &cas_len);
    if (rv == FAILURE) {
        return;
    }
    pcbc_mutate_in_builder_init(return_value, getThis(), id, id_len, pcbc_base36_decode_str(cas, cas_len) TSRMLS_CC);
} /* }}} */

PHP_METHOD(Bucket, __set)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    char *name;
    pcbc_str_arg_size name_len = 0;
    int rv, cmd;
    long val;
    lcb_uint32_t lcbval;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl", &name, &name_len, &val);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    lcbval = val;

    if (strncmp(name, "operationTimeout", name_len) == 0) {
        cmd = LCB_CNTL_OP_TIMEOUT;
    } else if (strncmp(name, "viewTimeout", name_len) == 0) {
        cmd = LCB_CNTL_VIEW_TIMEOUT;
    } else if (strncmp(name, "n1qlTimeout", name_len) == 0) {
        cmd = LCB_CNTL_N1QL_TIMEOUT;
    } else if (strncmp(name, "durabilityInterval", name_len) == 0) {
        cmd = LCB_CNTL_DURABILITY_INTERVAL;
    } else if (strncmp(name, "durabilityTimeout", name_len) == 0) {
        cmd = LCB_CNTL_DURABILITY_TIMEOUT;
    } else if (strncmp(name, "httpTimeout", name_len) == 0) {
        cmd = LCB_CNTL_HTTP_TIMEOUT;
    } else if (strncmp(name, "configTimeout", name_len) == 0) {
        cmd = LCB_CNTL_CONFIGURATION_TIMEOUT;
    } else if (strncmp(name, "configDelay", name_len) == 0) {
        cmd = LCB_CNTL_CONFDELAY_THRESH;
    } else if (strncmp(name, "configNodeTimeout", name_len) == 0) {
        cmd = LCB_CNTL_CONFIG_NODE_TIMEOUT;
    } else if (strncmp(name, "htconfigIdleTimeout", name_len) == 0) {
        cmd = LCB_CNTL_HTCONFIG_IDLE_TIMEOUT;
    } else {
        pcbc_log(LOGARGS(obj, WARN), "Undefined property of \\Couchbase\\Bucket via __set(): %s", name);
        RETURN_NULL();
    }
    lcb_cntl(obj->conn->lcb, LCB_CNTL_SET, cmd, &lcbval);

    RETURN_LONG(val);
}

PHP_METHOD(Bucket, __get)
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ_P(getThis());
    char *name;
    pcbc_str_arg_size name_len = 0;
    int rv, cmd;
    lcb_uint32_t lcbval;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &name, &name_len);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    if (strncmp(name, "operationTimeout", name_len) == 0) {
        cmd = LCB_CNTL_OP_TIMEOUT;
    } else if (strncmp(name, "viewTimeout", name_len) == 0) {
        cmd = LCB_CNTL_VIEW_TIMEOUT;
    } else if (strncmp(name, "durabilityInterval", name_len) == 0) {
        cmd = LCB_CNTL_DURABILITY_INTERVAL;
    } else if (strncmp(name, "durabilityTimeout", name_len) == 0) {
        cmd = LCB_CNTL_DURABILITY_TIMEOUT;
    } else if (strncmp(name, "httpTimeout", name_len) == 0) {
        cmd = LCB_CNTL_HTTP_TIMEOUT;
    } else if (strncmp(name, "configTimeout", name_len) == 0) {
        cmd = LCB_CNTL_CONFIGURATION_TIMEOUT;
    } else if (strncmp(name, "configDelay", name_len) == 0) {
        cmd = LCB_CNTL_CONFDELAY_THRESH;
    } else if (strncmp(name, "configNodeTimeout", name_len) == 0) {
        cmd = LCB_CNTL_CONFIG_NODE_TIMEOUT;
    } else if (strncmp(name, "htconfigIdleTimeout", name_len) == 0) {
        cmd = LCB_CNTL_HTCONFIG_IDLE_TIMEOUT;
    } else {
        pcbc_log(LOGARGS(obj, WARN), "Undefined property of \\Couchbase\\Bucket via __get(): %s", name);
        RETURN_NULL();
    }
    lcb_cntl(obj->conn->lcb, LCB_CNTL_GET, cmd, &lcbval);

    RETURN_LONG(lcbval);
}

/* {{{ proto \Couchbase\BucketManager Bucket::manager() */
PHP_METHOD(Bucket, manager)
{
    int rv;

    rv = zend_parse_parameters_none();
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_bucket_manager_init(return_value, getThis() TSRMLS_CC);
} /* }}} */

/* {{{ proto mixed Bucket::query($query, boolean $jsonassoc = false) */
PHP_METHOD(Bucket, query)
{
    int rv;
    pcbc_bucket_t *obj;
    zend_bool jsonassoc = 0;
    int json_options = 0;
    zval *query;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "o|b", &query, &jsonassoc);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    if (jsonassoc) {
        json_options |= PHP_JSON_OBJECT_AS_ARRAY;
    }
    obj = Z_BUCKET_OBJ_P(getThis());
    if (instanceof_function(Z_OBJCE_P(query), pcbc_n1ql_query_ce TSRMLS_CC)) {
        smart_str buf = {0};
        int last_error;
        zval *options = NULL;
        lcb_CMDN1QL cmd = {0};

        PCBC_READ_PROPERTY(options, pcbc_n1ql_query_ce, query, "options", 0);
        PCBC_JSON_ENCODE(&buf, options, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(obj, WARN), "Failed to encode N1QL query as JSON: json_last_error=%d", last_error);
            smart_str_free(&buf);
            RETURN_NULL();
        }
        smart_str_0(&buf);
        PCBC_SMARTSTR_SET(buf, cmd.query, cmd.nquery);
        if (!Z_N1QL_QUERY_OBJ_P(query)->adhoc) {
            cmd.cmdflags |= LCB_CMDN1QL_F_PREPCACHE;
        }
        if (Z_N1QL_QUERY_OBJ_P(query)->cross_bucket) {
            cmd.cmdflags |= LCB_CMD_F_MULTIAUTH;
        }
        pcbc_log(LOGARGS(obj, TRACE), "N1QL: %*s", PCBC_SMARTSTR_TRACE(buf));
        pcbc_bucket_n1ql_request(obj, &cmd, 1, json_options, 0, return_value TSRMLS_CC);
        smart_str_free(&buf);
    } else if (instanceof_function(Z_OBJCE_P(query), pcbc_search_query_ce TSRMLS_CC)) {
        smart_str buf = {0};
        int last_error;
        lcb_CMDFTS cmd = {0};

        PCBC_JSON_ENCODE(&buf, query, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(obj, WARN), "Failed to encode FTS query as JSON: json_last_error=%d", last_error);
            smart_str_free(&buf);
            RETURN_NULL();
        }
        smart_str_0(&buf);
        PCBC_SMARTSTR_SET(buf, cmd.query, cmd.nquery);
        pcbc_log(LOGARGS(obj, TRACE), "FTS: %*s", PCBC_SMARTSTR_TRACE(buf));
        pcbc_bucket_cbft_request(obj, &cmd, 1, json_options, return_value TSRMLS_CC);
        smart_str_free(&buf);
    } else if (instanceof_function(Z_OBJCE_P(query), pcbc_analytics_query_ce TSRMLS_CC)) {
        smart_str buf = {0};
        int last_error;
        zval *options = NULL;
        lcb_CMDN1QL cmd = {0};
        pcbc_analytics_query_t *cbas = Z_ANALYTICS_QUERY_OBJ_P(query);

        PCBC_READ_PROPERTY(options, pcbc_analytics_query_ce, query, "options", 0);
        PCBC_JSON_ENCODE(&buf, options, 0, last_error);
        if (last_error != 0) {
            pcbc_log(LOGARGS(obj, WARN), "Failed to encode N1QL query as JSON: json_last_error=%d", last_error);
            smart_str_free(&buf);
            RETURN_NULL();
        }
        smart_str_0(&buf);
        cmd.cmdflags |= LCB_CMDN1QL_F_CBASQUERY;
        PCBC_SMARTSTR_SET(buf, cmd.query, cmd.nquery);
        cmd.host = cbas->hostname;
        pcbc_log(LOGARGS(obj, TRACE), "ANALYTICS: %*s", PCBC_SMARTSTR_TRACE(buf));
        pcbc_bucket_n1ql_request(obj, &cmd, 1, json_options, 1, return_value TSRMLS_CC);
        smart_str_free(&buf);
    } else if (instanceof_function(Z_OBJCE_P(query), pcbc_view_query_encodable_ce TSRMLS_CC)) {
        PCBC_ZVAL retval;
        PCBC_ZVAL fname;

        PCBC_ZVAL_ALLOC(fname);
        PCBC_STRING(fname, "encode");
        rv = call_user_function_ex(EG(function_table), PCBC_CP(query), PCBC_P(fname), &retval, 0, NULL, 1,
                                   NULL TSRMLS_CC);
        zval_ptr_dtor(&fname);
        if (rv == FAILURE || Z_ISUNDEF(retval)) {
            throw_pcbc_exception("failed to call encode() on view query", LCB_EINVAL);
            RETURN_NULL();
        }
        if (EG(exception)) {
            RETURN_NULL();
        }
        if (Z_TYPE_P(PCBC_P(retval)) == IS_ARRAY) {
            char *ddoc = NULL, *view = NULL, *optstr = NULL, *postdata = NULL;
            int ddoc_len = 0, view_len = 0, optstr_len = 0, postdata_len = 0;
            zend_bool ddoc_free = 0, view_free = 0, optstr_free = 0, postdata_free = 0;
            lcb_CMDVIEWQUERY cmd = {0};

            if (php_array_fetch_bool(PCBC_P(retval), "include_docs")) {
                cmd.cmdflags |= LCB_CMDVIEWQUERY_F_INCLUDE_DOCS;
                cmd.docs_concurrent_max = 20; /* sane default */
            }
            ddoc = php_array_fetch_string(PCBC_P(retval), "ddoc", &ddoc_len, &ddoc_free);
            if (ddoc) {
                cmd.nddoc = ddoc_len;
                cmd.ddoc = ddoc;
            }
            view = php_array_fetch_string(PCBC_P(retval), "view", &view_len, &view_free);
            if (view) {
                cmd.nview = view_len;
                cmd.view = view;
            }
            optstr = php_array_fetch_string(PCBC_P(retval), "optstr", &optstr_len, &optstr_free);
            if (optstr) {
                cmd.noptstr = optstr_len;
                cmd.optstr = optstr;
            }
            postdata = php_array_fetch_string(PCBC_P(retval), "postdata", &postdata_len, &postdata_free);
            if (postdata) {
                cmd.npostdata = postdata_len;
                cmd.postdata = postdata;
            }
            if (ddoc && view) {
                pcbc_bucket_view_request(obj, &cmd, 1, json_options, return_value TSRMLS_CC);
            }
            if (ddoc && ddoc_free) {
                efree(ddoc);
            }
            if (view && view_free) {
                efree(view);
            }
            if (optstr && optstr_free) {
                efree(optstr);
            }
            if (postdata && postdata_free) {
                efree(postdata);
            }
        }
        zval_ptr_dtor(&retval);
    } else {
        throw_pcbc_exception("Unknown type of Query object", LCB_EINVAL);
        RETURN_NULL();
    }
} /* }}} */

/* {{{ proto mixed Bucket::mapSize($id) */
PHP_METHOD(Bucket, mapSize)
{
    pcbc_bucket_t *obj;
    zval *id = NULL;
    int rv;
    pcbc_pp_state pp_state = {0};
    pcbc_pp_id pp_id = {0};

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &id);
    if (rv == FAILURE) {
        return;
    }
    PCBC_CHECK_ZVAL_STRING(id, "id must be a string");
    obj = Z_BUCKET_OBJ_P(getThis());

    pp_state.arg_req = 1;
#if PHP_VERSION_ID >= 70000
    pp_state.zids = *id;
#else
    pp_state.zids = id;
#endif
    memcpy(pp_state.args[0].name, "id", sizeof("id"));
    pp_state.args[0].ptr = (zval **)&pp_id;
#if PHP_VERSION_ID >= 70000
    pp_state.args[0].val = *id;
#else
    pp_state.args[0].val = id;
#endif
    pcbc_bucket_get(obj, &pp_state, &pp_id, NULL, NULL, NULL, return_value TSRMLS_CC);
    if(!EG(exception)) {
        zval *val;
        long size = 0;

        PCBC_READ_PROPERTY(val, pcbc_document_ce, return_value, "value", 0);
        if (val) {
            switch (Z_TYPE_P(val)) {
            case IS_ARRAY:
                size = zend_hash_num_elements(Z_ARRVAL_P(val));
                break;
            case IS_OBJECT:
                size = zend_hash_num_elements(Z_OBJ_HT_P(val)->get_properties(val TSRMLS_CC));
                break;
            }
        }
        zval_dtor(return_value);
        RETURN_LONG(size);
    }
    RETURN_LONG(0);
} /* }}} */

/* {{{ proto mixed Bucket::mapAdd($id, string $key, mixed $value) */
PHP_METHOD(Bucket, mapAdd)
{
    pcbc_bucket_t *obj;
    char *id = NULL, *key = NULL;
    pcbc_str_arg_size id_len = 0, key_len = 0;
    int rv;
    zval *val;
    PCBC_ZVAL builder;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssz", &id, &id_len, &key, &key_len, &val);
    if (rv == FAILURE) {
        return;
    }

    obj = Z_BUCKET_OBJ_P(getThis());

    PCBC_ZVAL_ALLOC(builder);
    pcbc_mutate_in_builder_init(PCBC_P(builder), getThis(), id, id_len, 0 TSRMLS_CC);
    pcbc_mutate_in_builder_upsert(Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), key, key_len, val, LCB_SDSPEC_F_MKINTERMEDIATES TSRMLS_CC);
    pcbc_bucket_subdoc_request(obj, Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), 0, return_value TSRMLS_CC);
    zval_ptr_dtor(&builder);
    RETURN_NULL();
} /* }}} */

/* {{{ proto mixed Bucket::mapRemove($id, string $key) */
PHP_METHOD(Bucket, mapRemove)
{
    pcbc_bucket_t *obj;
    char *id = NULL, *key = NULL;
    pcbc_str_arg_size id_len = 0, key_len = 0;
    int rv;
    PCBC_ZVAL builder;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &id, &id_len, &key, &key_len);
    if (rv == FAILURE) {
        return;
    }

    obj = Z_BUCKET_OBJ_P(getThis());

    PCBC_ZVAL_ALLOC(builder);
    pcbc_mutate_in_builder_init(PCBC_P(builder), getThis(), id, id_len, 0 TSRMLS_CC);
    pcbc_mutate_in_builder_remove(Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), key, key_len, 0 TSRMLS_CC);
    pcbc_bucket_subdoc_request(obj, Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), 0, return_value TSRMLS_CC);
    zval_ptr_dtor(&builder);
    RETURN_NULL();
} /* }}} */

/* {{{ proto mixed Bucket::mapGet($id, string $key) */
PHP_METHOD(Bucket, mapGet)
{
    pcbc_bucket_t *obj;
    char *id = NULL, *key = NULL;
    pcbc_str_arg_size id_len = 0, key_len = 0;
    int rv;
    zval *val;
    PCBC_ZVAL builder;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &id, &id_len, &key, &key_len);
    if (rv == FAILURE) {
        return;
    }

    obj = Z_BUCKET_OBJ_P(getThis());

    PCBC_ZVAL_ALLOC(builder);
    pcbc_lookup_in_builder_init(PCBC_P(builder), getThis(), id, id_len, NULL, 0 TSRMLS_CC);
    pcbc_lookup_in_builder_get(Z_LOOKUP_IN_BUILDER_OBJ_P(PCBC_P(builder)), key, key_len, NULL TSRMLS_CC);
    pcbc_bucket_subdoc_request(obj, Z_LOOKUP_IN_BUILDER_OBJ_P(PCBC_P(builder)), 1, return_value TSRMLS_CC);
    zval_ptr_dtor(&builder);

    PCBC_READ_PROPERTY(val, pcbc_document_fragment_ce, return_value, "value", 0);
    if (!val || Z_TYPE_P(val) != IS_ARRAY) {
        RETURN_NULL();
    }
    val = php_array_fetchn(val, 0);
    if (!val || Z_TYPE_P(val) != IS_ARRAY) {
        RETURN_NULL();
    }
    val = php_array_fetch(val, "value");
    if (!val) {
        RETURN_NULL();
    }
    RETURN_ZVAL(val, 1, 0);
} /* }}} */

/* {{{ proto mixed Bucket::listPush($id, mixed $value) */
PHP_METHOD(Bucket, listPush)
{
    pcbc_bucket_t *obj;
    char *id = NULL;
    pcbc_str_arg_size id_len = 0;
    int rv;
    zval *val;
    PCBC_ZVAL builder;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &id, &id_len, &val);
    if (rv == FAILURE) {
        return;
    }

    obj = Z_BUCKET_OBJ_P(getThis());

    PCBC_ZVAL_ALLOC(builder);
    pcbc_mutate_in_builder_init(PCBC_P(builder), getThis(), id, id_len, 0 TSRMLS_CC);
    pcbc_mutate_in_builder_array_append(Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), NULL, 0, val, LCB_SDSPEC_F_MKINTERMEDIATES TSRMLS_CC);
    pcbc_bucket_subdoc_request(obj, Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), 0, return_value TSRMLS_CC);
    zval_ptr_dtor(&builder);
    RETURN_NULL();
} /* }}} */

/* {{{ proto mixed Bucket::listShift($id, mixed $value) */
PHP_METHOD(Bucket, listShift)
{
    pcbc_bucket_t *obj;
    char *id = NULL;
    pcbc_str_arg_size id_len = 0;
    int rv;
    zval *val;
    PCBC_ZVAL builder;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &id, &id_len, &val);
    if (rv == FAILURE) {
        return;
    }

    obj = Z_BUCKET_OBJ_P(getThis());

    PCBC_ZVAL_ALLOC(builder);
    pcbc_mutate_in_builder_init(PCBC_P(builder), getThis(), id, id_len, 0 TSRMLS_CC);
    pcbc_mutate_in_builder_array_prepend(Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), NULL, 0, val, LCB_SDSPEC_F_MKINTERMEDIATES TSRMLS_CC);
    pcbc_bucket_subdoc_request(obj, Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), 0, return_value TSRMLS_CC);
    zval_ptr_dtor(&builder);
    RETURN_NULL();
} /* }}} */

/* {{{ proto mixed Bucket::listRemove($id, int $index) */
PHP_METHOD(Bucket, listRemove)
{
    pcbc_bucket_t *obj;
    char *id = NULL, *path = NULL;
    pcbc_str_arg_size id_len = 0;
    long index = 0;
    int rv, path_len;
    PCBC_ZVAL builder;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl", &id, &id_len, &index);
    if (rv == FAILURE) {
        return;
    }

    obj = Z_BUCKET_OBJ_P(getThis());

    PCBC_ZVAL_ALLOC(builder);
    pcbc_mutate_in_builder_init(PCBC_P(builder), getThis(), id, id_len, 0 TSRMLS_CC);
    path_len = spprintf(&path, 0, "[%ld]", index);
    pcbc_mutate_in_builder_remove(Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), path, path_len, 0 TSRMLS_CC);
    pcbc_bucket_subdoc_request(obj, Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), 0, return_value TSRMLS_CC);
    efree(path);
    zval_ptr_dtor(&builder);
    RETURN_NULL();
} /* }}} */

/* {{{ proto mixed Bucket::listGet($id, int $index) */
PHP_METHOD(Bucket, listGet)
{
    pcbc_bucket_t *obj;
    char *id = NULL, *path = NULL;
    pcbc_str_arg_size id_len = 0;
    long index = 0;
    int rv, path_len;
    zval *val;
    PCBC_ZVAL builder;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl", &id, &id_len, &index);
    if (rv == FAILURE) {
        return;
    }

    obj = Z_BUCKET_OBJ_P(getThis());

    PCBC_ZVAL_ALLOC(builder);
    pcbc_lookup_in_builder_init(PCBC_P(builder), getThis(), id, id_len, NULL, 0 TSRMLS_CC);
    path_len = spprintf(&path, 0, "[%ld]", index);
    pcbc_lookup_in_builder_get(Z_LOOKUP_IN_BUILDER_OBJ_P(PCBC_P(builder)), path, path_len, NULL TSRMLS_CC);
    pcbc_bucket_subdoc_request(obj, Z_LOOKUP_IN_BUILDER_OBJ_P(PCBC_P(builder)), 1, return_value TSRMLS_CC);
    efree(path);
    zval_ptr_dtor(&builder);
    PCBC_READ_PROPERTY(val, pcbc_document_fragment_ce, return_value, "value", 0);
    if (!val || Z_TYPE_P(val) != IS_ARRAY) {
        RETURN_NULL();
    }
    val = php_array_fetchn(val, 0);
    if (!val || Z_TYPE_P(val) != IS_ARRAY) {
        RETURN_NULL();
    }
    val = php_array_fetch(val, "value");
    if (!val) {
        RETURN_NULL();
    }
    RETURN_ZVAL(val, 1, 0);
} /* }}} */

/* {{{ proto mixed Bucket::listSet($id, int $index, mixed $value) */
PHP_METHOD(Bucket, listSet)
{
    pcbc_bucket_t *obj;
    char *id = NULL, *path = NULL;
    pcbc_str_arg_size id_len = 0;
    long index = 0;
    int rv, path_len;
    zval *val;
    PCBC_ZVAL builder;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "slz", &id, &id_len, &index, &val);
    if (rv == FAILURE) {
        return;
    }

    obj = Z_BUCKET_OBJ_P(getThis());

    PCBC_ZVAL_ALLOC(builder);
    pcbc_mutate_in_builder_init(PCBC_P(builder), getThis(), id, id_len, 0 TSRMLS_CC);
    path_len = spprintf(&path, 0, "[%ld]", index);
    pcbc_mutate_in_builder_replace(Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), path, path_len, val, 0 TSRMLS_CC);
    pcbc_bucket_subdoc_request(obj, Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), 0, return_value TSRMLS_CC);
    efree(path);
    zval_ptr_dtor(&builder);
    RETURN_NULL();
} /* }}} */

/* {{{ proto mixed Bucket::setAdd($id, mixed $value) */
PHP_METHOD(Bucket, setAdd)
{
    pcbc_bucket_t *obj;
    char *id = NULL;
    pcbc_str_arg_size id_len = 0;
    int rv;
    zval *val;
    PCBC_ZVAL builder;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &id, &id_len, &val);
    if (rv == FAILURE) {
        return;
    }

    obj = Z_BUCKET_OBJ_P(getThis());

    PCBC_ZVAL_ALLOC(builder);
    pcbc_mutate_in_builder_init(PCBC_P(builder), getThis(), id, id_len, 0 TSRMLS_CC);
    pcbc_mutate_in_builder_array_add_unique(Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), NULL, 0, val, LCB_SDSPEC_F_MKINTERMEDIATES TSRMLS_CC);
    pcbc_bucket_subdoc_request(obj, Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), 0, return_value TSRMLS_CC);
    zval_ptr_dtor(&builder);
    RETURN_NULL();
} /* }}} */

/* {{{ proto mixed Bucket::setExists($id, mixed $value) */
PHP_METHOD(Bucket, setExists)
{
    pcbc_bucket_t *obj;
    zval *id = NULL, *val = NULL;
    int rv;
    pcbc_pp_state pp_state = {0};
    pcbc_pp_id pp_id = {0};

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &id, &val);
    if (rv == FAILURE) {
        return;
    }
    PCBC_CHECK_ZVAL_STRING(id, "id must be a string");
    obj = Z_BUCKET_OBJ_P(getThis());

    pp_state.arg_req = 1;
#if PHP_VERSION_ID >= 70000
    pp_state.zids = *id;
#else
    pp_state.zids = id;
#endif
    memcpy(pp_state.args[0].name, "id", sizeof("id"));
    pp_state.args[0].ptr = (zval **)&pp_id;
#if PHP_VERSION_ID >= 70000
    pp_state.args[0].val = *id;
#else
    pp_state.args[0].val = id;
#endif
    pcbc_bucket_get(obj, &pp_state, &pp_id, NULL, NULL, NULL, return_value TSRMLS_CC);
    if(!EG(exception)) {
        zval *array;
        zend_bool found = 0;

        PCBC_READ_PROPERTY(array, pcbc_document_ce, return_value, "value", 0);
        if (val && Z_TYPE_P(array) == IS_ARRAY) {
#if PHP_VERSION_ID >= 70000
            zval *entry;

            ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(array), entry)
            {
                if (zend_is_identical(val, entry)) {
                    found = 1;
                    break;
                }
            }
            ZEND_HASH_FOREACH_END();
#else
            HashPosition pos;
            zval **entry, res;

            zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(array), &pos);
            while (zend_hash_get_current_data_ex(Z_ARRVAL_P(array), (void **)&entry, &pos) == SUCCESS) {
                is_identical_function(&res, val, *entry TSRMLS_CC);
                if (Z_LVAL(res)) {
                    found = 1;
                    break;
                }
                zend_hash_move_forward_ex(Z_ARRVAL_P(array), &pos);
            }
#endif
        }
        zval_dtor(return_value);
        RETURN_BOOL(found);
    }
    RETURN_FALSE;
} /* }}} */

/* {{{ proto mixed Bucket::setRemove($id, mixed $value) */
PHP_METHOD(Bucket, setRemove)
{
    pcbc_bucket_t *obj;
    zval *id = NULL, *val = NULL;
    int rv;
    pcbc_pp_state pp_state = {0};
    pcbc_pp_id pp_id = {0};

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &id, &val);
    if (rv == FAILURE) {
        return;
    }
    PCBC_CHECK_ZVAL_STRING(id, "id must be a string");
    obj = Z_BUCKET_OBJ_P(getThis());

    pp_state.arg_req = 1;
#if PHP_VERSION_ID >= 70000
    pp_state.zids = *id;
#else
    pp_state.zids = id;
#endif
    memcpy(pp_state.args[0].name, "id", sizeof("id"));
    pp_state.args[0].ptr = (zval **)&pp_id;
#if PHP_VERSION_ID >= 70000
    pp_state.args[0].val = *id;
#else
    pp_state.args[0].val = id;
#endif
    pcbc_bucket_get(obj, &pp_state, &pp_id, NULL, NULL, NULL, return_value TSRMLS_CC);
    if(!EG(exception)) {
        zval *array, *casval;
        lcb_cas_t cas = 0;

        PCBC_READ_PROPERTY(array, pcbc_document_ce, return_value, "value", 0);
        PCBC_READ_PROPERTY(casval, pcbc_document_ce, return_value, "cas", 0);
        if (casval && Z_TYPE_P(casval) == IS_STRING) {
            cas = pcbc_cas_decode(casval TSRMLS_CC);
        }
        if (val && Z_TYPE_P(array) == IS_ARRAY) {
            int index = 0, found = -1;
#if PHP_VERSION_ID >= 70000
            zval *entry;

            ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(array), entry)
            {
                if (zend_is_identical(val, entry)) {
                    found = index;
                    break;
                }
                index++;
            }
            ZEND_HASH_FOREACH_END();
#else
            HashPosition pos;
            zval **entry, res;

            zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(array), &pos);
            while (zend_hash_get_current_data_ex(Z_ARRVAL_P(array), (void **)&entry, &pos) == SUCCESS) {
                is_identical_function(&res, val, *entry TSRMLS_CC);
                if (Z_LVAL(res)) {
                    found = index;
                    break;
                }
                zend_hash_move_forward_ex(Z_ARRVAL_P(array), &pos);
                index++;
            }
#endif
            zval_dtor(return_value);
            if (found >= 0) {
                PCBC_ZVAL builder;
                char *path = NULL;
                int path_len;
                zval *exc = NULL;
                zend_bool has_error = 0;

                PCBC_ZVAL_ALLOC(builder);
                pcbc_mutate_in_builder_init(PCBC_P(builder), getThis(), Z_STRVAL_P(id), Z_STRLEN_P(id), cas TSRMLS_CC);
                path_len = spprintf(&path, 0, "[%ld]", (long)found);
                pcbc_mutate_in_builder_remove(Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), path, path_len, 0 TSRMLS_CC);
                pcbc_bucket_subdoc_request(obj, Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), 0, return_value TSRMLS_CC);
                efree(path);
                zval_ptr_dtor(&builder);
                PCBC_READ_PROPERTY(exc, pcbc_document_ce, return_value, "error", 0);
                has_error = exc && (Z_TYPE_P(exc) == IS_OBJECT) &&
                            instanceof_function(Z_OBJCE_P(exc), pcbc_exception_ce TSRMLS_CC);
                zval_dtor(return_value);
                RETURN_BOOL(!has_error);
            }
        }
    }
    RETURN_FALSE;
} /* }}} */

/* {{{ proto mixed Bucket::queueRemove($id) */
PHP_METHOD(Bucket, queueRemove)
{
    pcbc_bucket_t *obj;
    char *id = NULL, *path = NULL;
    pcbc_str_arg_size id_len = 0, path_len;
    int rv;
    zval *val;
    PCBC_ZVAL builder;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &id, &id_len);
    if (rv == FAILURE) {
        return;
    }

    obj = Z_BUCKET_OBJ_P(getThis());

    PCBC_ZVAL_ALLOC(builder);
    pcbc_lookup_in_builder_init(PCBC_P(builder), getThis(), id, id_len, NULL, 0 TSRMLS_CC);
    path = "[-1]";
    path_len = strlen(path);
    pcbc_lookup_in_builder_get(Z_LOOKUP_IN_BUILDER_OBJ_P(PCBC_P(builder)), path, path_len, NULL TSRMLS_CC);
    pcbc_bucket_subdoc_request(obj, Z_LOOKUP_IN_BUILDER_OBJ_P(PCBC_P(builder)), 1, return_value TSRMLS_CC);
    zval_ptr_dtor(&builder);
    PCBC_READ_PROPERTY(val, pcbc_document_fragment_ce, return_value, "value", 0);
    if (!val || Z_TYPE_P(val) != IS_ARRAY) {
        RETURN_NULL();
    }
    val = php_array_fetchn(val, 0);
    if (!val || Z_TYPE_P(val) != IS_ARRAY) {
        RETURN_NULL();
    }
    val = php_array_fetch(val, "value");
    if (!val) {
        RETURN_NULL();
    }
    {
        zval *casval;
        lcb_cas_t cas = 0;
        PCBC_ZVAL builder;
        zval *exc = NULL;

        PCBC_READ_PROPERTY(casval, pcbc_document_fragment_ce, return_value, "cas", 0);
        if (casval && Z_TYPE_P(casval) == IS_STRING) {
            cas = pcbc_cas_decode(casval TSRMLS_CC);
        }
        PCBC_ZVAL_ALLOC(builder);
        pcbc_mutate_in_builder_init(PCBC_P(builder), getThis(), id, id_len, cas TSRMLS_CC);
        pcbc_mutate_in_builder_remove(Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), path, path_len, 0 TSRMLS_CC);
        pcbc_bucket_subdoc_request(obj, Z_MUTATE_IN_BUILDER_OBJ_P(PCBC_P(builder)), 0, return_value TSRMLS_CC);
        zval_ptr_dtor(&builder);
        PCBC_READ_PROPERTY(exc, pcbc_document_ce, return_value, "error", 0);
        if (exc && Z_TYPE_P(exc) == IS_OBJECT && instanceof_function(Z_OBJCE_P(exc), pcbc_exception_ce TSRMLS_CC)) {
            RETURN_NULL();
        }
    }

    RETURN_ZVAL(val, 1, 0);
} /* }}} */

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket___get, 0, 0, 1)
ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket___set, 0, 0, 2)
ZEND_ARG_INFO(0, name)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_setTranscoder, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, encoder, IS_CALLABLE, 0)
ZEND_ARG_TYPE_INFO(0, decoder, IS_CALLABLE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_get, 0, 0, 2)
ZEND_ARG_INFO(0, ids)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_getAndLock, 0, 0, 3)
ZEND_ARG_INFO(0, ids)
ZEND_ARG_INFO(0, lockTime)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_getAndTouch, 0, 0, 3)
ZEND_ARG_INFO(0, ids)
ZEND_ARG_INFO(0, expiry)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_getFromReplica, 0, 0, 2)
ZEND_ARG_INFO(0, ids)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_upsert, 0, 0, 3)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, val)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_remove, 0, 0, 2)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_unlock, 0, 0, 2)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_touch, 0, 0, 3)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, expiry)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_counter, 0, 0, 3)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, delta)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_lookupIn, 0, 0, 1)
ZEND_ARG_INFO(0, id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_retrieveIn, 0, 0, 2)
ZEND_ARG_INFO(0, id)
PCBC_ARG_VARIADIC_INFO(0, paths)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_mutateIn, 0, 0, 2)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, cas)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_query, 0, 0, 2)
ZEND_ARG_INFO(0, query)
ZEND_ARG_INFO(0, jsonAsArray)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_mapSize, 0, 0, 1)
ZEND_ARG_INFO(0, id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_mapAdd, 0, 0, 3)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_mapRemove, 0, 0, 2)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_mapGet, 0, 0, 2)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_listPush, 0, 0, 2)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_listShift, 0, 0, 2)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_listRemove, 0, 0, 2)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, index)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_listGet, 0, 0, 2)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, index)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_listSet, 0, 0, 3)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, index)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_setAdd, 0, 0, 2)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_setExists, 0, 0, 2)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_setRemove, 0, 0, 2)
ZEND_ARG_INFO(0, id)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_Bucket_queueRemove, 0, 0, 1)
ZEND_ARG_INFO(0, id)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry bucket_methods[] = {
    PHP_ME(Bucket, __construct, ai_Bucket_none, ZEND_ACC_PRIVATE | ZEND_ACC_FINAL | ZEND_ACC_CTOR)
    PHP_ME(Bucket, __get, ai_Bucket___get, ZEND_ACC_PRIVATE | ZEND_ACC_FINAL)
    PHP_ME(Bucket, __set, ai_Bucket___set, ZEND_ACC_PRIVATE | ZEND_ACC_FINAL)
    PHP_ME(Bucket, setTranscoder, ai_Bucket_setTranscoder, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, get, ai_Bucket_get, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, getAndLock, ai_Bucket_getAndLock, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, getAndTouch, ai_Bucket_getAndTouch, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, getFromReplica, ai_Bucket_getFromReplica, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, upsert, ai_Bucket_upsert, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, insert, ai_Bucket_upsert, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, replace, ai_Bucket_upsert, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, append, ai_Bucket_upsert, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, prepend, ai_Bucket_upsert, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, remove, ai_Bucket_remove, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, unlock, ai_Bucket_unlock, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, touch, ai_Bucket_touch, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, counter, ai_Bucket_counter, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, lookupIn, ai_Bucket_lookupIn, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, retrieveIn, ai_Bucket_retrieveIn, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, mutateIn, ai_Bucket_mutateIn, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, manager, ai_Bucket_none, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, query, ai_Bucket_query, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, mapSize, ai_Bucket_mapSize, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, mapAdd, ai_Bucket_mapAdd, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, mapRemove, ai_Bucket_mapRemove, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, mapGet, ai_Bucket_mapGet, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, setAdd, ai_Bucket_setAdd, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, setExists, ai_Bucket_setExists, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, setRemove, ai_Bucket_setRemove, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_MALIAS(Bucket, listSize, mapSize, ai_Bucket_mapSize, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, listPush, ai_Bucket_listPush, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, listShift, ai_Bucket_listShift, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, listRemove, ai_Bucket_listRemove, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, listGet, ai_Bucket_listGet, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, listSet, ai_Bucket_listSet, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_MALIAS(Bucket, listExists, setExists, ai_Bucket_setExists, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_MALIAS(Bucket, setSize, mapSize, ai_Bucket_mapSize, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_MALIAS(Bucket, queueSize, mapSize, ai_Bucket_mapSize, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_MALIAS(Bucket, queueAdd, listShift, ai_Bucket_listShift, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_MALIAS(Bucket, queueExists, setExists, ai_Bucket_setExists, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_ME(Bucket, queueRemove, ai_Bucket_queueRemove, ZEND_ACC_PUBLIC | ZEND_ACC_FINAL)
    PHP_FE_END
};
// clang-format on

zend_object_handlers pcbc_bucket_handlers;

static void pcbc_bucket_free_object(pcbc_free_object_arg *object TSRMLS_DC) /* {{{ */
{
    pcbc_bucket_t *obj = Z_BUCKET_OBJ(object);

    pcbc_connection_delref(obj->conn TSRMLS_CC);
    if (!Z_ISUNDEF(obj->encoder)) {
        zval_ptr_dtor(&obj->encoder);
        ZVAL_UNDEF(PCBC_P(obj->encoder));
    }
    if (!Z_ISUNDEF(obj->decoder)) {
        zval_ptr_dtor(&obj->decoder);
        ZVAL_UNDEF(PCBC_P(obj->decoder));
    }

    zend_object_std_dtor(&obj->std TSRMLS_CC);
#if PHP_VERSION_ID < 70000
    efree(obj);
#endif
} /* }}} */

static pcbc_create_object_retval pcbc_bucket_create_object(zend_class_entry *class_type TSRMLS_DC)
{
    pcbc_bucket_t *obj = NULL;

    obj = PCBC_ALLOC_OBJECT_T(pcbc_bucket_t, class_type);

    zend_object_std_init(&obj->std, class_type TSRMLS_CC);
    object_properties_init(&obj->std, class_type);

#if PHP_VERSION_ID >= 70000
    obj->std.handlers = &pcbc_bucket_handlers;
    return &obj->std;
#else
    {
        zend_object_value ret;
        ret.handle = zend_objects_store_put(obj, (zend_objects_store_dtor_t)zend_objects_destroy_object,
                                            pcbc_bucket_free_object, NULL TSRMLS_CC);
        ret.handlers = &pcbc_bucket_handlers;
        return ret;
    }
#endif
}

static HashTable *pcbc_bucket_get_debug_info(zval *object, int *is_temp TSRMLS_DC)
{
    pcbc_bucket_t *obj = NULL;
#if PHP_VERSION_ID >= 70000
    zval retval;
#else
    zval retval = zval_used_for_init;
#endif

    *is_temp = 1;
    obj = Z_BUCKET_OBJ_P(object);

    array_init(&retval);
    ADD_ASSOC_STRING(&retval, "connstr", obj->conn->connstr);
    ADD_ASSOC_STRING(&retval, "bucket", obj->conn->bucketname);
    ADD_ASSOC_STRING(&retval, "auth", obj->conn->auth_hash);
    if (!Z_ISUNDEF(obj->encoder)) {
        ADD_ASSOC_ZVAL_EX(&retval, "encoder", PCBC_P(obj->encoder));
        PCBC_ADDREF_P(PCBC_P(obj->encoder));
    } else {
        ADD_ASSOC_NULL_EX(&retval, "encoder");
    }
    if (!Z_ISUNDEF(obj->decoder)) {
        ADD_ASSOC_ZVAL_EX(&retval, "decoder", PCBC_P(obj->decoder));
        PCBC_ADDREF_P(PCBC_P(obj->decoder));
    } else {
        ADD_ASSOC_NULL_EX(&retval, "decoder");
    }

    return Z_ARRVAL(retval);
}

void pcbc_bucket_init(zval *return_value, pcbc_cluster_t *cluster, const char *bucketname,
                      const char *password TSRMLS_DC)
{
    pcbc_bucket_t *bucket;
    pcbc_connection_t *conn;
    lcb_error_t err;
    pcbc_classic_authenticator_t *authenticator = NULL;
    pcbc_credential_t extra_creds = {0};
    lcb_AUTHENTICATOR *auth = NULL;
    char *auth_hash = NULL;

    if (!Z_ISUNDEF(cluster->auth)) {
        if (instanceof_function(Z_OBJCE_P(PCBC_P(cluster->auth)), pcbc_classic_authenticator_ce TSRMLS_CC)) {
            pcbc_generate_classic_lcb_auth(Z_CLASSIC_AUTHENTICATOR_OBJ_P(PCBC_P(cluster->auth)), &auth, LCB_TYPE_BUCKET, bucketname, password, &auth_hash TSRMLS_CC);
        } else if (instanceof_function(Z_OBJCE_P(PCBC_P(cluster->auth)), pcbc_password_authenticator_ce TSRMLS_CC)) {
            pcbc_generate_password_lcb_auth(Z_PASSWORD_AUTHENTICATOR_OBJ_P(PCBC_P(cluster->auth)), &auth, LCB_TYPE_BUCKET, bucketname, password, &auth_hash TSRMLS_CC);
        }
    }
    if (!auth) {
        pcbc_generate_classic_lcb_auth(NULL, &auth, LCB_TYPE_BUCKET, bucketname, password, &auth_hash TSRMLS_CC);
    }
    err = pcbc_connection_get(&conn, LCB_TYPE_BUCKET, cluster->connstr, bucketname, auth, auth_hash TSRMLS_CC);
    efree(auth_hash);
    if (err) {
        throw_lcb_exception(err);
        return;
    }

    object_init_ex(return_value, pcbc_bucket_ce);
    bucket = Z_BUCKET_OBJ_P(return_value);
    bucket->conn = conn;
    PCBC_ZVAL_ALLOC(bucket->encoder);
    PCBC_ZVAL_ALLOC(bucket->decoder);
    PCBC_STRING(bucket->encoder, "\\Couchbase\\defaultEncoder");
    PCBC_STRING(bucket->decoder, "\\Couchbase\\defaultDecoder");
}

zval *bop_get_return_doc(zval *return_value, const char *key, int key_len, int is_mapped TSRMLS_DC)
{
    zval *doc = return_value;
    if (is_mapped) {
        PCBC_ZVAL new_doc;
        if (Z_TYPE_P(return_value) != IS_ARRAY) {
            array_init(return_value);
        }
        PCBC_ZVAL_ALLOC(new_doc);
        ZVAL_NULL(PCBC_P(new_doc));
#if PHP_VERSION_ID >= 70000
        doc = zend_hash_str_update(Z_ARRVAL_P(return_value), key, key_len, PCBC_P(new_doc) TSRMLS_CC);
#else
        zend_hash_update(Z_ARRVAL_P(return_value), key, key_len + 1, &new_doc, sizeof(new_doc), NULL);
        doc = new_doc;
#endif
    }
    return doc;
}

PHP_MINIT_FUNCTION(Bucket)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "Bucket", bucket_methods);
    pcbc_bucket_ce = zend_register_internal_class(&ce TSRMLS_CC);
    pcbc_bucket_ce->create_object = pcbc_bucket_create_object;
    PCBC_CE_FLAGS_FINAL(pcbc_bucket_ce);
    PCBC_CE_DISABLE_SERIALIZATION(pcbc_bucket_ce);

    memcpy(&pcbc_bucket_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    pcbc_bucket_handlers.get_debug_info = pcbc_bucket_get_debug_info;
#if PHP_VERSION_ID >= 70000
    pcbc_bucket_handlers.free_obj = pcbc_bucket_free_object;
    pcbc_bucket_handlers.offset = XtOffsetOf(pcbc_bucket_t, std);
#endif

    zend_register_class_alias("\\CouchbaseBucket", pcbc_bucket_ce);
    return SUCCESS;
}
