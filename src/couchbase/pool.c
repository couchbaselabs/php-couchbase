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
#include <ext/standard/url.h>

static int pcbc_res_couchbase;

extern struct pcbc_logger_st pcbc_logger;
#define LOGARGS(conn, lvl) LCB_LOG_##lvl, conn, "pcbc/pool", __FILE__, __LINE__

char *pcbc_client_string = "PCBC/" PHP_COUCHBASE_VERSION " (PHP/" PHP_VERSION
#if ZTS
                           " ZTS"
#else
                           " NTS"
#endif
                           ")";

void get_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb);
void store_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb);
void unlock_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb);
void remove_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb);
void touch_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb);
void counter_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb);
void subdoc_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb);
void http_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb);
void durability_callback(lcb_t instance, const void *cookie, lcb_error_t error, const lcb_durability_resp_t *resp);
void ping_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb);
void diag_callback(lcb_t instance, int cbtype, const lcb_RESPBASE *rb);

static lcb_error_t pcbc_establish_connection(lcb_type_t type, lcb_t *result, const char *connstr,
                                             lcb_AUTHENTICATOR *auth, char *auth_hash TSRMLS_DC)
{
    struct lcb_create_st create_options;
    lcb_error_t err;
    lcb_t conn;

    memset(&create_options, 0, sizeof(create_options));
    create_options.version = 4;
    create_options.v.v4.connstr = connstr;
    create_options.v.v4.type = type;
    create_options.v.v4.logger = &pcbc_logger;
    err = lcb_create(&conn, &create_options);
    if (err != LCB_SUCCESS) {
        pcbc_log(LOGARGS(NULL, ERROR), "Failed to initialize LCB connection: %s", pcbc_lcb_strerror(err));
        return err;
    }
    pcbc_log(LOGARGS(conn, INFO), "New lcb_t instance has been initialized");
    lcb_set_auth(conn, auth);
    lcbauth_unref(auth);
    pcbc_log(LOGARGS(conn, INFO), "Using authenticator. md5=\"%s\"", auth_hash);
    err = lcb_cntl(conn, LCB_CNTL_SET, LCB_CNTL_CLIENT_STRING, pcbc_client_string);
    if (err != LCB_SUCCESS) {
        pcbc_log(LOGARGS(conn, ERROR), "Failed to configure LCB client string: %s", pcbc_lcb_strerror(err));
        lcb_destroy(conn);
        return err;
    }

#if LCB_VERSION == 0x020800
    // versions higher than 2.8.0 will have error maps enabled by default
    if (strstr(connstr, "enable_errmap") == NULL) {
        int enabled = 1;
        err = lcb_cntl(conn, LCB_CNTL_SET, LCB_CNTL_ENABLE_ERRMAP, &enabled);
        if (err != LCB_SUCCESS) {
            pcbc_log(LOGARGS(conn, ERROR), "Failed to enable error maps: %s", pcbc_lcb_strerror(err));
            lcb_destroy(conn);
            return err;
        }
    }
#endif

    lcb_install_callback3(conn, LCB_CALLBACK_GET, get_callback);
    lcb_install_callback3(conn, LCB_CALLBACK_GETREPLICA, get_callback);
    lcb_install_callback3(conn, LCB_CALLBACK_STORE, store_callback);
    lcb_install_callback3(conn, LCB_CALLBACK_STOREDUR, store_callback);
    lcb_install_callback3(conn, LCB_CALLBACK_UNLOCK, unlock_callback);
    lcb_install_callback3(conn, LCB_CALLBACK_REMOVE, remove_callback);
    lcb_install_callback3(conn, LCB_CALLBACK_TOUCH, touch_callback);
    lcb_install_callback3(conn, LCB_CALLBACK_COUNTER, counter_callback);
    lcb_install_callback3(conn, LCB_CALLBACK_SDLOOKUP, subdoc_callback);
    lcb_install_callback3(conn, LCB_CALLBACK_SDMUTATE, subdoc_callback);
    lcb_install_callback3(conn, LCB_CALLBACK_HTTP, http_callback);
    lcb_install_callback3(conn, LCB_CALLBACK_PING, ping_callback);
    lcb_install_callback3(conn, LCB_CALLBACK_DIAG, diag_callback);

    err = lcb_connect(conn);
    if (err != LCB_SUCCESS) {
        pcbc_log(LOGARGS(conn, ERROR), "Failed to connect LCB connection: %s", pcbc_lcb_strerror(err));
        lcb_destroy(conn);
        return err;
    }
    // We use lcb_wait here as no callbacks are invoked by connect.
    lcb_wait(conn);
    err = lcb_get_bootstrap_status(conn);
    if (err != LCB_SUCCESS) {
        pcbc_log(LOGARGS(conn, ERROR), "Failed to bootstrap LCB connection: %s", pcbc_lcb_strerror(err));
        lcb_destroy(conn);
        return err;
    }

    *result = conn;
    return LCB_SUCCESS;
}

static lcb_error_t pcbc_normalize_connstr(lcb_type_t type, char *connstr, const char *bucketname,
                                          char **normalized TSRMLS_DC)
{
    php_url *url;
    zend_bool need_free = 0;

    if (type != LCB_TYPE_BUCKET && type != LCB_TYPE_CLUSTER) {
        return LCB_EINVAL;
    }

    url = php_url_parse(connstr);
    if (!url) {
        return LCB_EINVAL;
    }
    if (url->scheme == NULL && url->host == NULL) {
        // hosts has gone into path section,
        // explicitly prepend schema to workaround it
        smart_str buf = {0};
        char *with_schema = NULL;
        smart_str_appendl(&buf, "couchbase://", 12);
        smart_str_appends(&buf, connstr);
        smart_str_0(&buf);
        PCBC_SMARTSTR_DUP(buf, with_schema);
        smart_str_free(&buf);
        pcbc_log(LOGARGS(NULL, DEBUG), "Rewrite connection string from \"%s\" to \"%s\"", connstr, with_schema);
        need_free = 1;
        connstr = with_schema;
        php_url_free(url);
        url = php_url_parse(connstr);
        if (!url) {
            efree(with_schema);
            return LCB_EINVAL;
        }
    }
    switch (type) {
    case LCB_TYPE_BUCKET:
        if (bucketname && bucketname[0] != '\0') {
            // rebuild connection string with username as the bucket
            smart_str buf = {0};
            if (url->scheme) {
#if PHP_VERSION_ID < 70300
                smart_str_appends(&buf, url->scheme);
#else
                smart_str_appendl(&buf, ZSTR_VAL(url->scheme), ZSTR_LEN(url->scheme));
#endif
                smart_str_appendl(&buf, "://", 3);
            }
            if (url->host) {
#if PHP_VERSION_ID < 70300
                smart_str_appends(&buf, url->host);
#else
                smart_str_appendl(&buf, ZSTR_VAL(url->host), ZSTR_LEN(url->host));
#endif
            }
            if (url->port) {
                smart_str_appendc(&buf, ':');
                smart_str_append_long(&buf, (long)url->port);
            }
            smart_str_appendc(&buf, '/');
            smart_str_appends(&buf, bucketname);
            if (url->query) {
                smart_str_appendc(&buf, '?');
#if PHP_VERSION_ID < 70300
                smart_str_appends(&buf, url->query);
#else
                smart_str_appendl(&buf, ZSTR_VAL(url->query), ZSTR_LEN(url->query));
#endif
            }
            smart_str_0(&buf);
            PCBC_SMARTSTR_DUP(buf, *normalized);
            smart_str_free(&buf);
            pcbc_log(LOGARGS(NULL, DEBUG), "Rewrite connection string from \"%s\" to \"%s\"", connstr, *normalized);
        } else {
            *normalized = estrdup(connstr);
        }
        break;
    case LCB_TYPE_CLUSTER:
#if PHP_VERSION_ID < 70300
        if (url->path != NULL && url->path[0] != '\0') {
#else
        if (url->path != NULL && ZSTR_VAL(url->path)[0] != '\0') {
#endif
            // strip bucket from the connection string
            smart_str buf = {0};
            if (url->scheme) {
#if PHP_VERSION_ID < 70300
                smart_str_appends(&buf, url->scheme);
#else
                smart_str_appendl(&buf, ZSTR_VAL(url->scheme), ZSTR_LEN(url->scheme));
#endif
                smart_str_appendl(&buf, "://", 3);
            }
            if (url->host) {
#if PHP_VERSION_ID < 70300
                smart_str_appends(&buf, url->host);
#else
                smart_str_appendl(&buf, ZSTR_VAL(url->host), ZSTR_LEN(url->host));
#endif
            }
            if (url->port) {
                smart_str_appendc(&buf, ':');
                smart_str_append_long(&buf, (long)url->port);
            }
            if (url->query) {
                smart_str_appendc(&buf, '?');
#if PHP_VERSION_ID < 70300
                smart_str_appends(&buf, url->query);
#else
                smart_str_appendl(&buf, ZSTR_VAL(url->query), ZSTR_LEN(url->query));
#endif
            }
            smart_str_0(&buf);
            PCBC_SMARTSTR_DUP(buf, *normalized);
            smart_str_free(&buf);
            pcbc_log(LOGARGS(NULL, DEBUG), "Rewrite connection string from \"%s\" to \"%s\"", connstr, *normalized);
        } else {
            *normalized = estrdup(connstr);
        }
        break;
    }
    php_url_free(url);
    if (need_free) {
        efree(connstr);
    }
    return LCB_SUCCESS;
}

void pcbc_connection_addref(pcbc_connection_t *conn TSRMLS_DC)
{
    if (conn) {
        conn->refs++;
        conn->idle_at = 0;
    }
}

void pcbc_connection_delref(pcbc_connection_t *conn TSRMLS_DC)
{
    if (conn) {
        conn->refs--;
        pcbc_log(LOGARGS(conn->lcb, DEBUG),
                 "cachedel: type=%d, connstr=%s, bucketname=%s, auth_hash=%s, lcb=%p, refs=%d", conn->type,
                 conn->connstr, conn->bucketname, conn->auth_hash, conn->lcb, conn->refs);
        if (conn->refs == 0) {
            conn->idle_at = time(NULL);
        }
    }
}

#if PHP_VERSION_ID >= 70000
static zend_resource *pcbc_connection_lookup(smart_str *plist_key TSRMLS_DC)
{
    zend_resource *res;
    res = zend_hash_find_ptr(&EG(persistent_list), plist_key->s);
    if (res != NULL && res->type == pcbc_res_couchbase) {
        return res;
    }
    return NULL;
}

static lcb_error_t pcbc_connection_cache(smart_str *plist_key, pcbc_connection_t *conn TSRMLS_DC)
{
    zend_resource res;
    res.type = pcbc_res_couchbase;
    res.ptr = conn;
#if PHP_VERSION_ID < 70300
    GC_REFCOUNT(&res) = 1;
#else
    GC_SET_REFCOUNT(&res, 1);
#endif

    if (zend_hash_str_update_mem(&EG(persistent_list), PCBC_SMARTSTR_VAL(*plist_key), PCBC_SMARTSTR_LEN(*plist_key),
                                 &res, sizeof(res)) == NULL) {
        pcbc_log(LOGARGS(NULL, ERROR), "failed to register persistent connection");
        return LCB_EINVAL;
    }
    pcbc_log(LOGARGS(conn->lcb, DEBUG),
             "cachenew: ptr=%p, type=%d, connstr=%s, bucketname=%s, auth_hash=%s, lcb=%p, refs=%d", conn, conn->type,
             conn->connstr, conn->bucketname, conn->auth_hash, conn->lcb, conn->refs);
    return LCB_SUCCESS;
}
#else
static zend_rsrc_list_entry *pcbc_connection_lookup(smart_str *plist_key TSRMLS_DC)
{
    zend_rsrc_list_entry *res = NULL;
    int rv;

    rv = zend_hash_find(&EG(persistent_list), plist_key->c, plist_key->len, (void *)&res);
    if (rv == SUCCESS && res->type == pcbc_res_couchbase) {
        return res;
    }
    return NULL;
}
static lcb_error_t pcbc_connection_cache(smart_str *plist_key, pcbc_connection_t *conn TSRMLS_DC)
{
    zend_rsrc_list_entry res;
    int rv;

    res.type = pcbc_res_couchbase;
    res.ptr = conn;
    rv = zend_hash_update(&EG(persistent_list), plist_key->c, plist_key->len, (void *)&res, sizeof(res), NULL);
    if (rv == FAILURE) {
        pcbc_log(LOGARGS(NULL, ERROR), "failed to register persistent connection");
        return LCB_EINVAL;
    }
    return LCB_SUCCESS;
}
#endif

static void pcbc_destroy_connection_resource(
#if PHP_VERSION_ID >= 70000
    zend_resource *res
#else
    zend_rsrc_list_entry *res
#endif
    )
{
    if (res->ptr) {
        pcbc_connection_t *conn = res->ptr;
        pcbc_log(LOGARGS(NULL, DEBUG), "cachedtor: ptr=%p", conn);
        if (conn->lcb) {
            pefree(conn->connstr, 1);
            if (conn->bucketname) {
                pefree(conn->bucketname, 1);
                conn->bucketname = NULL;
            }
            if (conn->auth_hash) {
                pefree(conn->auth_hash, 1);
                conn->auth_hash = NULL;
            }
            lcb_destroy(conn->lcb);
            conn->lcb = NULL;
        }
        pefree(conn, 1);
        res->ptr = NULL;
    }
}

lcb_error_t pcbc_connection_get(pcbc_connection_t **result, lcb_type_t type, const char *connstr,
                                const char *bucketname, lcb_AUTHENTICATOR *auth, char *auth_hash TSRMLS_DC)
{
    char *cstr = NULL;
    lcb_error_t rv;
    lcb_t lcb;
    pcbc_connection_t *conn = NULL;
    smart_str plist_key = {0};
    zend_bool is_persistent = 1; // always persistent connections
#if PHP_VERSION_ID >= 70000
    zend_resource *res = NULL;
#else
    zend_rsrc_list_entry *res = NULL;
#endif

    rv = pcbc_normalize_connstr(type, (char *)connstr, bucketname, &cstr TSRMLS_CC);
    if (rv != LCB_SUCCESS) {
        pcbc_log(LOGARGS(NULL, ERROR), "Failed to normalize connection string: %s", connstr);
        return rv;
    }

    smart_str_append_long(&plist_key, type);
    smart_str_appendc(&plist_key, '|');
    smart_str_appends(&plist_key, cstr);
    smart_str_appendc(&plist_key, '|');
    smart_str_appends(&plist_key, auth_hash);
    res = pcbc_connection_lookup(&plist_key TSRMLS_CC);
    if (res) {
        conn = res->ptr;
        if (conn) {
            if (lcb_is_waiting(conn->lcb)) {
                pcbc_log(LOGARGS(conn->lcb, DEBUG),
                         "cachestale: type=%d, connstr=%s, bucketname=%s, auth_hash=%s, lcb=%p, refs=%d", conn->type,
                         conn->connstr, conn->bucketname, conn->auth_hash, conn->lcb, conn->refs);
                pcbc_destroy_connection_resource(res);
            } else {
                efree(cstr);
                smart_str_free(&plist_key);
                pcbc_connection_addref(conn TSRMLS_CC);
                pcbc_log(LOGARGS(conn->lcb, DEBUG),
                         "cachehit: type=%d, connstr=%s, bucketname=%s, auth_hash=%s, lcb=%p, refs=%d", conn->type,
                         conn->connstr, conn->bucketname, conn->auth_hash, conn->lcb, conn->refs);
                *result = conn;
                return LCB_SUCCESS;
            }
        }
    }

    rv = pcbc_establish_connection(type, &lcb, cstr, auth, auth_hash TSRMLS_CC);
    if (rv != LCB_SUCCESS) {
        efree(cstr);
        smart_str_free(&plist_key);
        return rv;
    }

    conn = pemalloc(sizeof(pcbc_connection_t), is_persistent);
    conn->refs = 1;
    conn->idle_at = 0;
    conn->type = type;
    conn->connstr = pestrdup(cstr, is_persistent);
    efree(cstr);
    conn->bucketname = NULL;
    conn->auth_hash = pestrdup(auth_hash, is_persistent);
    if (type == LCB_TYPE_BUCKET) {
        char *tmp;
        lcb_cntl(lcb, LCB_CNTL_GET, LCB_CNTL_BUCKETNAME, &tmp);
        if (tmp) {
            conn->bucketname = pestrdup(tmp, is_persistent);
        }
    }
    conn->lcb = lcb;
    rv = pcbc_connection_cache(&plist_key, conn TSRMLS_CC);
    smart_str_free(&plist_key);
    if (rv != LCB_SUCCESS) {
        return rv;
    }
    *result = conn;

    return LCB_SUCCESS;
}

static int pcbc_destroy_idle_connections(
#if PHP_VERSION_ID >= 70000
    zval *el
#else
    zend_rsrc_list_entry *res TSRMLS_DC
#endif
    )
{
#if PHP_VERSION_ID >= 70000
    zend_resource *res = Z_RES_P(el);

    if (res->type != pcbc_res_couchbase) {
        return 0;
    }
#else
    if (Z_TYPE_P(res) != pcbc_res_couchbase) {
        return 0;
    }
#endif

    if (res->ptr) {
        pcbc_connection_t *conn = res->ptr;
        time_t now;

        if (conn->refs > 0) {
            return 0;
        }
        if (conn->idle_at == 0) {
            return 0;
        }
        now = time(NULL);
        if ((now - conn->idle_at) > PCBCG(pool_max_idle_time)) {
            pcbc_destroy_connection_resource(res);
        }
    }
    return 0;
}

#if PHP_VERSION_ID >= 70000
void pcbc_connection_cleanup()
{
    zend_hash_apply(&EG(persistent_list), (apply_func_t)pcbc_destroy_idle_connections);
}
#else
void pcbc_connection_cleanup(TSRMLS_D)
{
    zend_hash_apply(&EG(persistent_list), (apply_func_t)pcbc_destroy_idle_connections TSRMLS_CC);
}
#endif

ZEND_RSRC_DTOR_FUNC(pcbc_connection_dtor)
{
#if PHP_VERSION_ID >= 70000
    pcbc_destroy_connection_resource(res);
#else
    pcbc_destroy_connection_resource(rsrc);
#endif
}

PHP_MINIT_FUNCTION(CouchbasePool)
{
    pcbc_res_couchbase =
        zend_register_list_destructors_ex(NULL, pcbc_connection_dtor, "Couchbase persistent connection", module_number);
    return SUCCESS;
}
