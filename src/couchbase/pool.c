/**
 *     Copyright 2017-2019 Couchbase, Inc.
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

void get_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPGET *rb);
void getreplica_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPGETREPLICA *resp);
void exists_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPEXISTS *resp);
void store_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPSTORE *rb);
void unlock_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPUNLOCK *rb);
void remove_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPREMOVE *rb);
void touch_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPTOUCH *rb);
void counter_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPCOUNTER *rb);
void subdoc_lookup_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPSUBDOC *rb);
void subdoc_mutate_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPSUBDOC *rb);
void http_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPHTTP *rb);
void ping_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPPING *rb);
void diag_callback(lcb_INSTANCE *instance, int cbtype, const lcb_RESPDIAG *rb);

static lcb_STATUS pcbc_establish_connection(lcb_INSTANCE_TYPE type, lcb_INSTANCE **result, const char *connstr,
                                            const char *username, const char *password)
{
    lcb_LOGGER *logger = NULL;
    lcb_logger_create(&logger, &pcbc_logger);
    lcb_logger_callback(logger, pcbc_logger.callback);

    lcb_CREATEOPTS *options = NULL;
    lcb_createopts_create(&options, type);
    lcb_createopts_connstr(options, connstr, strlen(connstr));
    lcb_createopts_logger(options, logger);
    lcb_createopts_credentials(options, username, strlen(username), password, strlen(password));

    lcb_INSTANCE *conn;
    lcb_STATUS err;
    err = lcb_create(&conn, options);
    if (err != LCB_SUCCESS) {
        pcbc_log(LOGARGS(NULL, ERROR), "Failed to initialize LCB connection: %s", lcb_strerror_short(err));
        lcb_logger_destroy(logger);
        return err;
    }
    lcb_set_cookie(conn, logger);
    pcbc_log(LOGARGS(conn, INFO), "New lcb_INSTANCE * instance has been initialized");
    err = lcb_cntl(conn, LCB_CNTL_SET, LCB_CNTL_CLIENT_STRING, pcbc_client_string);
    if (err != LCB_SUCCESS) {
        pcbc_log(LOGARGS(conn, ERROR), "Failed to configure LCB client string: %s", lcb_strerror_short(err));
        lcb_destroy(conn);
        lcb_logger_destroy(logger);
        return err;
    }

    lcb_install_callback(conn, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)get_callback);
    lcb_install_callback(conn, LCB_CALLBACK_GETREPLICA, (lcb_RESPCALLBACK)getreplica_callback);
    lcb_install_callback(conn, LCB_CALLBACK_EXISTS, (lcb_RESPCALLBACK)exists_callback);
    lcb_install_callback(conn, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)store_callback);
    lcb_install_callback(conn, LCB_CALLBACK_STOREDUR, (lcb_RESPCALLBACK)store_callback);
    lcb_install_callback(conn, LCB_CALLBACK_UNLOCK, (lcb_RESPCALLBACK)unlock_callback);
    lcb_install_callback(conn, LCB_CALLBACK_REMOVE, (lcb_RESPCALLBACK)remove_callback);
    lcb_install_callback(conn, LCB_CALLBACK_TOUCH, (lcb_RESPCALLBACK)touch_callback);
    lcb_install_callback(conn, LCB_CALLBACK_COUNTER, (lcb_RESPCALLBACK)counter_callback);
    lcb_install_callback(conn, LCB_CALLBACK_SDLOOKUP, (lcb_RESPCALLBACK)subdoc_lookup_callback);
    lcb_install_callback(conn, LCB_CALLBACK_SDMUTATE, (lcb_RESPCALLBACK)subdoc_mutate_callback);
    lcb_install_callback(conn, LCB_CALLBACK_HTTP, (lcb_RESPCALLBACK)http_callback);
    lcb_install_callback(conn, LCB_CALLBACK_PING, (lcb_RESPCALLBACK)ping_callback);
    lcb_install_callback(conn, LCB_CALLBACK_DIAG, (lcb_RESPCALLBACK)diag_callback);

    err = lcb_connect(conn);
    if (err != LCB_SUCCESS) {
        pcbc_log(LOGARGS(conn, ERROR), "Failed to connect LCB connection: %s", lcb_strerror_short(err));
        lcb_destroy(conn);
        lcb_logger_destroy(logger);
        return err;
    }
    // We use lcb_wait here as no callbacks are invoked by connect.
    lcb_wait(conn, LCB_WAIT_DEFAULT);
    err = lcb_get_bootstrap_status(conn);
    if (err != LCB_SUCCESS) {
        pcbc_log(LOGARGS(conn, ERROR), "Failed to bootstrap LCB connection: %s", lcb_strerror_short(err));
        lcb_destroy(conn);
        lcb_logger_destroy(logger);
        return err;
    }

    *result = conn;
    return LCB_SUCCESS;
}

static lcb_STATUS pcbc_normalize_connstr(lcb_INSTANCE_TYPE type, char *connstr, const char *bucketname,
                                         char **normalized)
{
    php_url *url;
    zend_bool need_free = 0;

    if (type != LCB_TYPE_BUCKET && type != LCB_TYPE_CLUSTER) {
        return LCB_ERR_INVALID_ARGUMENT;
    }

    url = php_url_parse(connstr);
    if (!url) {
        return LCB_ERR_INVALID_ARGUMENT;
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
            return LCB_ERR_INVALID_ARGUMENT;
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

void pcbc_connection_addref(pcbc_connection_t *conn)
{
    if (conn) {
        conn->refs++;
        conn->idle_at = 0;
    }
}

void pcbc_connection_delref(pcbc_connection_t *conn)
{
    if (conn) {
        conn->refs--;
        pcbc_log(LOGARGS(conn->lcb, DEBUG),
                 "cachedel: type=%d, connstr=%s, bucketname=%s, username=%s, lcb=%p, refs=%d", conn->type,
                 conn->connstr, conn->bucketname, conn->username, conn->lcb, conn->refs);
        if (conn->refs == 0) {
            conn->idle_at = time(NULL);
        }
    }
}

static zend_resource *pcbc_connection_lookup(smart_str *plist_key)
{
    zend_resource *res;
    res = zend_hash_find_ptr(&EG(persistent_list), plist_key->s);
    if (res != NULL && res->type == pcbc_res_couchbase) {
        return res;
    }
    return NULL;
}

static lcb_STATUS pcbc_connection_cache(smart_str *plist_key, pcbc_connection_t *conn)
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
        return LCB_ERR_INVALID_ARGUMENT;
    }
    pcbc_log(LOGARGS(conn->lcb, DEBUG),
             "cachenew: ptr=%p, type=%d, connstr=%s, bucketname=%s, username=%s, lcb=%p, refs=%d", conn, conn->type,
             conn->connstr, conn->bucketname, conn->username, conn->lcb, conn->refs);
    return LCB_SUCCESS;
}

static void pcbc_destroy_connection_resource(zend_resource *res)
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
            if (conn->username) {
                pefree(conn->username, 1);
                conn->username = NULL;
            }
            lcb_LOGGER *logger = (lcb_LOGGER *)lcb_get_cookie(conn->lcb);
            lcb_destroy(conn->lcb);
            conn->lcb = NULL;
            if (logger) {
                lcb_logger_destroy(logger);
            }
        }
        pefree(conn, 1);
        res->ptr = NULL;
    }
}

lcb_STATUS pcbc_connection_get(pcbc_connection_t **result, lcb_INSTANCE_TYPE type, const char *connstr,
                               const char *bucketname, const char *username, const char *password)
{
    char *cstr = NULL;
    lcb_STATUS rv;
    lcb_INSTANCE *lcb;
    pcbc_connection_t *conn = NULL;
    smart_str plist_key = {0};
    zend_bool is_persistent = 1; // always persistent connections
    zend_resource *res = NULL;

    rv = pcbc_normalize_connstr(type, (char *)connstr, bucketname, &cstr);
    if (rv != LCB_SUCCESS) {
        pcbc_log(LOGARGS(NULL, ERROR), "Failed to normalize connection string: %s", connstr);
        return rv;
    }

    smart_str_append_long(&plist_key, type);
    smart_str_appendc(&plist_key, '|');
    smart_str_appends(&plist_key, cstr);
    smart_str_appendc(&plist_key, '|');
    smart_str_appends(&plist_key, username);
    res = pcbc_connection_lookup(&plist_key);
    if (res) {
        conn = res->ptr;
        if (conn) {
            if (lcb_is_waiting(conn->lcb)) {
                pcbc_log(LOGARGS(conn->lcb, DEBUG),
                         "cachestale: type=%d, connstr=%s, bucketname=%s, username=%s, lcb=%p, refs=%d", conn->type,
                         conn->connstr, conn->bucketname, conn->username, conn->lcb, conn->refs);
                pcbc_destroy_connection_resource(res);
            } else {
                efree(cstr);
                smart_str_free(&plist_key);
                pcbc_connection_addref(conn);
                pcbc_log(LOGARGS(conn->lcb, DEBUG),
                         "cachehit: type=%d, connstr=%s, bucketname=%s, username=%s, lcb=%p, refs=%d", conn->type,
                         conn->connstr, conn->bucketname, conn->username, conn->lcb, conn->refs);
                *result = conn;
                return LCB_SUCCESS;
            }
        }
    }

    rv = pcbc_establish_connection(type, &lcb, cstr, username, password);
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
    conn->username = pestrdup(username, is_persistent);
    if (type == LCB_TYPE_BUCKET) {
        char *tmp;
        lcb_cntl(lcb, LCB_CNTL_GET, LCB_CNTL_BUCKETNAME, &tmp);
        if (tmp) {
            conn->bucketname = pestrdup(tmp, is_persistent);
        }
    }
    conn->lcb = lcb;
    rv = pcbc_connection_cache(&plist_key, conn);
    smart_str_free(&plist_key);
    if (rv != LCB_SUCCESS) {
        return rv;
    }
    *result = conn;

    return LCB_SUCCESS;
}

static int pcbc_destroy_idle_connections(zval *el)
{
    zend_resource *res = Z_RES_P(el);

    if (res->type != pcbc_res_couchbase) {
        return 0;
    }

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
        if ((now - conn->idle_at) >= PCBCG(pool_max_idle_time)) {
            pcbc_destroy_connection_resource(res);
        }
    }
    return 0;
}

void pcbc_connection_cleanup()
{
    zend_hash_apply(&EG(persistent_list), (apply_func_t)pcbc_destroy_idle_connections);
}

ZEND_RSRC_DTOR_FUNC(pcbc_connection_dtor)
{
    pcbc_destroy_connection_resource(res);
}

PHP_MINIT_FUNCTION(CouchbasePool)
{
    pcbc_res_couchbase =
        zend_register_list_destructors_ex(NULL, pcbc_connection_dtor, "Couchbase persistent connection", module_number);
    return SUCCESS;
}
