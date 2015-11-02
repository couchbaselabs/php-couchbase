#include "couchbase.h"
#include "ext/standard/php_var.h"
#include "exception.h"
#include "datainfo.h"
#include "paramparser.h"
#include "phphelpers.h"
#include "bucket.h"
#include "cas.h"
#include "metadoc.h"
#include "transcoding.h"

#define PCBC_CHECK_ZVAL(v,t,m) \
	if (v && Z_TYPE_P(v) != t) { \
		throw_pcbc_exception(m, LCB_EINVAL); \
		RETURN_NULL(); \
	}

static inline struct bucket_object * php_bucket_object_fetch_object(zend_object *obj) {
      return (struct bucket_object *)((char *)obj - XtOffsetOf(struct bucket_object, std));
}
#define PHP_THISOBJ() php_bucket_object_fetch_object(Z_OBJ_P(getThis()));

typedef struct {
	int mapped;
	int remaining;
	zval *retval;
	bucket_object *owner;
} bopcookie;

bopcookie * bopcookie_init(bucket_object *bucketobj, zval *return_value, int ismapped) {
	bopcookie *cookie = emalloc(sizeof(bopcookie));
	cookie->owner = bucketobj;
	cookie->retval = return_value;
	if (ismapped) {
		array_init(cookie->retval);
	} else {
		ZVAL_NULL(cookie->retval);
	}
	return cookie;
}

void bopcookie_destroy(bopcookie *cookie) {
	efree(cookie);
}

zval * bopcookie_get_doc(const bopcookie *cookie, const char *key, uint key_len) {
	// Maximum server keylength is currently 250
	char tmpstr[251];

	zval *doc_out;
	if (Z_TYPE_P(cookie->retval) == IS_ARRAY && key != NULL) {
        memcpy(tmpstr, key, key_len);
        tmpstr[key_len] = '\0';

	    zval doc;
		ZVAL_NULL(&doc);

		add_assoc_zval_ex(cookie->retval, tmpstr, key_len + 1, &doc);

		HashTable *htretval = Z_ARRVAL_P(cookie->retval);
		doc_out = zend_hash_str_find(htretval, tmpstr, key_len + 1);
	} else {
	    doc_out = cookie->retval;
	}
	return doc_out;
}

void bopcookie_error(const bopcookie *cookie, bucket_object *data, zval *doc,
	lcb_error_t error TSRMLS_DC) {
	zval zerror;
	make_lcb_exception(&zerror, error TSRMLS_CC);
	if (Z_TYPE_P(cookie->retval) == IS_ARRAY) {
		metadoc_from_error(doc, &zerror TSRMLS_CC);
	} else {
		data->error = zerror;
	}
}

zend_object_handlers bucket_handlers;

void bucket_free_storage(zend_object *object TSRMLS_DC)
{
	bucket_object *obj = php_bucket_object_fetch_object(object);

	//zend_hash_destroy(obj->std.properties);
	//FREE_HASHTABLE(obj->std.properties);

	Z_TRY_DELREF_P(&obj->encoder);
	Z_TRY_DELREF_P(&obj->decoder);
	Z_TRY_DELREF_P(&obj->prefix);
}

zend_object * bucket_create_handler(zend_class_entry *type TSRMLS_DC)
{
    bucket_object *obj = ecalloc(1,
             sizeof(struct bucket_object) +
             zend_object_properties_size(type));
    memset(obj, 0, sizeof(bucket_object));

    zend_object_std_init(&obj->std, type TSRMLS_CC);

	obj->std.ce = type;
	obj->std.handlers = &bucket_handlers;

	phlp_object_properties_init(&obj->std, type);

	ZVAL_UNDEF(&obj->encoder);
	ZVAL_UNDEF(&obj->decoder);
	ZVAL_UNDEF(&obj->prefix);
	obj->conn = NULL;

	return &obj->std;
}

static void get_callback(lcb_t instance, const void *cookie, lcb_error_t error,
		const lcb_get_resp_t *resp)
{
	bopcookie *op = (bopcookie*)cookie;
	bucket_object *data = op->owner;
	zval *doc = bopcookie_get_doc(cookie, resp->v.v0.key, resp->v.v0.nkey);
	TSRMLS_FETCH();

	if (error == LCB_SUCCESS) {
		if (metadoc_from_bytes(data, doc, resp->v.v0.bytes, resp->v.v0.nbytes,
				resp->v.v0.cas, resp->v.v0.flags, resp->v.v0.datatype TSRMLS_CC) == FAILURE) {
			bopcookie_error(cookie, data, doc, LCB_ERROR TSRMLS_CC);
			return;
		}
	} else {
		bopcookie_error(cookie, data, doc, error TSRMLS_CC);
	}
}

static void store_callback(lcb_t instance, const void *cookie,
		lcb_storage_t operation, lcb_error_t error,
		const lcb_store_resp_t *resp) {
	bopcookie *op = (bopcookie*)cookie;
	bucket_object *data = op->owner;
	zval *doc = bopcookie_get_doc(cookie, resp->v.v0.key, resp->v.v0.nkey);
	TSRMLS_FETCH();

	if (error == LCB_SUCCESS) {
		if (metadoc_from_bytes(data, doc, NULL, 0, resp->v.v0.cas, 0, 0 TSRMLS_CC) == FAILURE) {
			bopcookie_error(cookie, data, doc, LCB_ERROR TSRMLS_CC);
			return;
		}
	} else {
		bopcookie_error(cookie, data, doc, error TSRMLS_CC);
	}
}

static void arithmetic_callback(lcb_t instance, const void *cookie,
		lcb_error_t error, const lcb_arithmetic_resp_t *resp) {
	bopcookie *op = (bopcookie*)cookie;
	bucket_object *data = op->owner;
	zval *doc = bopcookie_get_doc(cookie, resp->v.v0.key, resp->v.v0.nkey);
	TSRMLS_FETCH();

	if (error == LCB_SUCCESS) {
		if (metadoc_from_long(doc, resp->v.v0.value, resp->v.v0.cas, 0, 0 TSRMLS_CC) == FAILURE) {
			bopcookie_error(cookie, data, doc, LCB_ERROR TSRMLS_CC);
			return;
		}
	} else {
		bopcookie_error(cookie, data, doc, error TSRMLS_CC);
	}
}

static void remove_callback(lcb_t instance, const void *cookie,
		lcb_error_t error, const lcb_remove_resp_t *resp) {
	bopcookie *op = (bopcookie*)cookie;
	bucket_object *data = op->owner;
	zval *doc = bopcookie_get_doc(cookie, resp->v.v0.key, resp->v.v0.nkey);
	TSRMLS_FETCH();

	if (error == LCB_SUCCESS) {
		if (metadoc_create(doc, NULL, resp->v.v0.cas, 0, 0 TSRMLS_CC) == FAILURE) {
			bopcookie_error(cookie, data, doc, LCB_ERROR TSRMLS_CC);
			return;
		}
	} else {
		bopcookie_error(cookie, data, doc, error TSRMLS_CC);
	}
}

static void touch_callback(lcb_t instance, const void *cookie,
		lcb_error_t error, const lcb_touch_resp_t *resp) {
	bopcookie *op = (bopcookie*)cookie;
	bucket_object *data = op->owner;
	zval *doc = bopcookie_get_doc(cookie, resp->v.v0.key, resp->v.v0.nkey);
	TSRMLS_FETCH();

	if (error == LCB_SUCCESS) {
		if (metadoc_create(doc, NULL, resp->v.v0.cas, 0, 0 TSRMLS_CC) == FAILURE) {
			bopcookie_error(cookie, data, doc, LCB_ERROR TSRMLS_CC);
			return;
		}
	} else {
		bopcookie_error(cookie, data, doc, error TSRMLS_CC);
	}
}

static void http_complete_callback(lcb_http_request_t request, lcb_t instance,
			const void *cookie, lcb_error_t error,
			const lcb_http_resp_t *resp) {
	bopcookie *op = (bopcookie*)cookie;
	bucket_object *data = op->owner;
	zval *doc = bopcookie_get_doc(cookie, NULL, 0);
	TSRMLS_FETCH();

	if (error == LCB_SUCCESS) {
		ZVAL_STRINGL(doc, resp->v.v0.bytes, resp->v.v0.nbytes);
	} else {
		bopcookie_error(cookie, data, NULL, error TSRMLS_CC);
	}
}

static void durability_callback(lcb_t instance, const void *cookie,
			lcb_error_t error, const lcb_durability_resp_t *resp) {
	bopcookie *op = (bopcookie*)cookie;
	bucket_object *data = op->owner;
	zval *doc = bopcookie_get_doc(cookie, resp->v.v0.key, resp->v.v0.nkey);
	TSRMLS_FETCH();

	if (error == LCB_SUCCESS) {
		ZVAL_TRUE(doc);
	} else {
		bopcookie_error(cookie, data, doc, error TSRMLS_CC);
	}
}

static int pcbc_wait(bucket_object *obj TSRMLS_DC)
{
	lcb_t instance = obj->conn->lcb;
	ZVAL_UNDEF(&obj->error);

	lcb_wait(instance);

	if (Z_TYPE(obj->error) != IS_UNDEF) {
		zend_throw_exception_object(&obj->error TSRMLS_CC);
		ZVAL_UNDEF(&obj->error);
		return 0;
	}

	return 1;
}

zend_class_entry *bucket_ce;

PHP_METHOD(Bucket, __construct)
{
	bucket_object *data = PHP_THISOBJ();
	zval *zdsn = NULL;
	zval *zname = NULL;
	zval *zpassword = NULL;
	char *dsn = NULL;
	char *name = NULL;
	char *password = NULL;
	lcb_error_t err;
	lcb_t instance;
	struct lcb_create_st create_options;
	char *connkey = NULL;
	pcbc_lcb *conn_iter, *conn;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|zzz",
			&zdsn, &zname, &zpassword) == FAILURE) {
		RETURN_NULL();
	}

	if (zdsn && Z_TYPE_P(zdsn) != IS_UNDEF) {
        if (Z_TYPE_P(zdsn) == IS_STRING) {
            dsn = estrndup(Z_STRVAL_P(zdsn), Z_STRLEN_P(zdsn));
        } else {
            throw_pcbc_exception("Expected dsn as string", LCB_EINVAL);
            RETURN_NULL();
        }
	}

    if (zname && Z_TYPE_P(zname) != IS_UNDEF) {
        if (Z_TYPE_P(zname) == IS_STRING) {
            name = estrndup(Z_STRVAL_P(zname), Z_STRLEN_P(zname));
        } else {
            throw_pcbc_exception("Expected bucket name as string", LCB_EINVAL);
            if (dsn) efree(dsn);
            RETURN_NULL();
        }
    }

    if (zpassword && Z_TYPE_P(zpassword) != IS_UNDEF) {
        if (Z_TYPE_P(zpassword) == IS_STRING) {
            password = estrndup(Z_STRVAL_P(zpassword), Z_STRLEN_P(zpassword));
        } else {
            throw_pcbc_exception("Expected bucket password as string", LCB_EINVAL);
            if (dsn) efree(dsn);
            if (name) efree(name);
            RETURN_NULL();
        }
    }

	spprintf(&connkey, 512, "%s|%s|%s",
			dsn ? dsn : "",
			name ? name : "",
			password ? password : "");

	conn_iter = PCBCG(first_bconn);
	while (conn_iter) {
		if (strcmp(conn_iter->key, connkey) == 0) {
			break;
		}
		conn_iter = conn_iter->next;
	}

	if (!conn_iter)
	{
		memset(&create_options, 0, sizeof(create_options));
		create_options.version = 3;
		create_options.v.v3.connstr = dsn;
		create_options.v.v3.username = name;
		create_options.v.v3.passwd = password;
		create_options.v.v3.type = LCB_TYPE_BUCKET;
		err = lcb_create(&instance, &create_options);

		if (dsn) efree(dsn);
		if (name) efree(name);
		if (password) efree(password);

		if (err != LCB_SUCCESS) {
			efree(connkey);
			throw_lcb_exception(err);
			RETURN_NULL();
		}

		lcb_set_get_callback(instance, get_callback);
		lcb_set_store_callback(instance, store_callback);
		lcb_set_arithmetic_callback(instance, arithmetic_callback);
		lcb_set_remove_callback(instance, remove_callback);
		lcb_set_touch_callback(instance, touch_callback);
		lcb_set_http_complete_callback(instance, http_complete_callback);
		lcb_set_durability_callback(instance, durability_callback);

		err = lcb_connect(instance);
		if (err != LCB_SUCCESS) {
			efree(connkey);
			lcb_destroy(instance);
			throw_lcb_exception(err);
			RETURN_NULL();
		}

		// We use lcb_wait here as no callbacks are invoked by connect.
		lcb_wait(instance);

		err = lcb_get_bootstrap_status(instance);
		if (err != LCB_SUCCESS) {
			efree(connkey);
			lcb_destroy(instance);
			throw_lcb_exception(err);
			RETURN_NULL();
		}

		conn = pemalloc(sizeof(pcbc_lcb), 1);
		conn->key = pestrdup(connkey, 1);
		conn->lcb = instance;
		conn->next = NULL;
		data->conn = conn;

		if (PCBCG(last_bconn)) {
			PCBCG(last_bconn)->next = conn;
			PCBCG(last_bconn) = conn;
		} else {
			PCBCG(first_bconn) = conn;
			PCBCG(last_bconn) = conn;
		}
	} else {
		if (dsn) efree(dsn);
		if (name) efree(name);
		if (password) efree(password);

		data->conn = conn_iter;
	}

	efree(connkey);
}



// insert($id, $doc {, $expiry, $groupid}) : MetaDoc
PHP_METHOD(Bucket, insert)
{
	bucket_object *data = PHP_THISOBJ();
	lcb_store_cmd_t *cmd = NULL;
	lcb_store_cmd_t **cmds = NULL;
	int ii, num_cmds;
	pcbc_pp_state pp_state;
	zval *zid, *zvalue, *zexpiry, *zflags, *zgroupid;
	bopcookie *cookie;

  // Note that groupid is experimental here and should not be used.
	pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id|value|expiry,flags,groupid",
				  &zid, &zvalue, &zexpiry, &zflags, &zgroupid);

	num_cmds = pcbc_pp_keycount(&pp_state);
	cmd = emalloc(sizeof(lcb_store_cmd_t) * num_cmds);
	cmds = emalloc(sizeof(lcb_store_cmd_t*) * num_cmds);
	memset(cmd, 0, sizeof(lcb_store_cmd_t) * num_cmds);

	for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
		PCBC_CHECK_ZVAL(zid, IS_STRING, "id must be a string");
		PCBC_CHECK_ZVAL(zexpiry, IS_LONG, "expiry must be an integer");
		PCBC_CHECK_ZVAL(zflags, IS_LONG, "flags must be an integer");
		PCBC_CHECK_ZVAL(zgroupid, IS_STRING, "groupid must be a string");

		cmd[ii].version = 0;
		cmd[ii].v.v0.operation = LCB_ADD;
		cmd[ii].v.v0.key = Z_STRVAL_P(zid);
		cmd[ii].v.v0.nkey = Z_STRLEN_P(zid);

		pcbc_zval_to_bytes(data, zvalue, &cmd[ii].v.v0.bytes, &cmd[ii].v.v0.nbytes,
				&cmd[ii].v.v0.flags, &cmd[ii].v.v0.datatype TSRMLS_CC);

		if (zexpiry) {
			cmd[ii].v.v0.exptime = Z_LVAL_P(zexpiry);
		}
		if (zflags) {
			cmd[ii].v.v0.flags = Z_LVAL_P(zflags);
		}
		if (zgroupid) {
			cmd[ii].v.v0.hashkey = Z_STRVAL_P(zgroupid);
			cmd[ii].v.v0.nhashkey = Z_STRLEN_P(zgroupid);
		}

		cmds[ii] = &cmd[ii];
	}

	cookie = bopcookie_init(data, return_value, pcbc_pp_ismapped(&pp_state));

	lcb_store(data->conn->lcb, cookie,
	        num_cmds, (const lcb_store_cmd_t*const*)cmds);
	pcbc_wait(data TSRMLS_CC);

	bopcookie_destroy(cookie);
    for (ii = 0; ii < num_cmds; ++ii) {
        efree((void*)cmds[ii]->v.v0.bytes);
    }
	efree(cmds);
	efree(cmd);
}

// upsert($id, $doc {, $expiry, $groupid}) : MetaDoc
PHP_METHOD(Bucket, upsert)
{
	bucket_object *data = PHP_THISOBJ();
	lcb_store_cmd_t *cmd = NULL;
	lcb_store_cmd_t **cmds = NULL;
	int ii, num_cmds;
	pcbc_pp_state pp_state;
	zval *zid, *zvalue, *zexpiry, *zflags, *zgroupid;
	bopcookie *cookie;

  // Note that groupid is experimental here and should not be used.
	pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id|value|expiry,flags,groupid",
				  &zid, &zvalue, &zexpiry, &zflags, &zgroupid);

	num_cmds = pcbc_pp_keycount(&pp_state);
	cmd = emalloc(sizeof(lcb_store_cmd_t) * num_cmds);
	cmds = emalloc(sizeof(lcb_store_cmd_t*) * num_cmds);
	memset(cmd, 0, sizeof(lcb_store_cmd_t) * num_cmds);

	for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
		PCBC_CHECK_ZVAL(zid, IS_STRING, "id must be a string");
		PCBC_CHECK_ZVAL(zexpiry, IS_LONG, "expiry must be an integer");
		PCBC_CHECK_ZVAL(zflags, IS_LONG, "flags must be an integer");
		PCBC_CHECK_ZVAL(zgroupid, IS_STRING, "groupid must be a string");

		cmd[ii].version = 0;
		cmd[ii].v.v0.operation = LCB_SET;
		cmd[ii].v.v0.key = Z_STRVAL_P(zid);
		cmd[ii].v.v0.nkey = Z_STRLEN_P(zid);

		pcbc_zval_to_bytes(data, zvalue, &cmd[ii].v.v0.bytes, &cmd[ii].v.v0.nbytes,
				&cmd[ii].v.v0.flags, &cmd[ii].v.v0.datatype TSRMLS_CC);

		if (zexpiry) {
			cmd[ii].v.v0.exptime = Z_LVAL_P(zexpiry);
		}
		if (zflags) {
			cmd[ii].v.v0.flags = Z_LVAL_P(zflags);
		}
		if (zgroupid) {
			cmd[ii].v.v0.hashkey = Z_STRVAL_P(zgroupid);
			cmd[ii].v.v0.nhashkey = Z_STRLEN_P(zgroupid);
		}

		cmds[ii] = &cmd[ii];
	}

	cookie = bopcookie_init(data, return_value, pcbc_pp_ismapped(&pp_state));

	lcb_store(data->conn->lcb, cookie,
	        num_cmds, (const lcb_store_cmd_t*const*)cmds);
	pcbc_wait(data TSRMLS_CC);

	bopcookie_destroy(cookie);
	for (ii = 0; ii < num_cmds; ++ii) {
	    efree((void*)cmds[ii]->v.v0.bytes);
	}
	efree(cmds);
	efree(cmd);
}

// save($id, $doc {, $cas, $expiry, $groupid}) : MetaDoc
PHP_METHOD(Bucket, replace)
{
	bucket_object *data = PHP_THISOBJ();
	lcb_store_cmd_t *cmd = NULL;
	lcb_store_cmd_t **cmds = NULL;
	int ii, num_cmds;
	pcbc_pp_state pp_state;
	zval *zid, *zvalue, *zcas, *zexpiry, *zflags, *zgroupid;
	bopcookie *cookie;

  // Note that groupid is experimental here and should not be used.
	pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id|value|cas,expiry,flags,groupid",
				  &zid, &zvalue, &zcas, &zexpiry, &zflags, &zgroupid);

	num_cmds = pcbc_pp_keycount(&pp_state);
	cmd = emalloc(sizeof(lcb_store_cmd_t) * num_cmds);
	cmds = emalloc(sizeof(lcb_store_cmd_t*) * num_cmds);
	memset(cmd, 0, sizeof(lcb_store_cmd_t) * num_cmds);

	for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
		PCBC_CHECK_ZVAL(zid, IS_STRING, "id must be a string");
		PCBC_CHECK_ZVAL(zcas, IS_RESOURCE, "cas must be a CAS resource");
		PCBC_CHECK_ZVAL(zexpiry, IS_LONG, "expiry must be an integer");
		PCBC_CHECK_ZVAL(zflags, IS_LONG, "flags must be an integer");
		PCBC_CHECK_ZVAL(zgroupid, IS_STRING, "groupid must be a string");

		cmd[ii].version = 0;
		cmd[ii].v.v0.operation = LCB_REPLACE;
		cmd[ii].v.v0.key = Z_STRVAL_P(zid);
		cmd[ii].v.v0.nkey = Z_STRLEN_P(zid);

		pcbc_zval_to_bytes(data, zvalue, &cmd[ii].v.v0.bytes, &cmd[ii].v.v0.nbytes,
				&cmd[ii].v.v0.flags, &cmd[ii].v.v0.datatype TSRMLS_CC);

		if (zcas) {
			cmd[ii].v.v0.cas = cas_retrieve(zcas TSRMLS_CC);
		}
		if (zexpiry) {
			cmd[ii].v.v0.exptime = Z_LVAL_P(zexpiry);
		}
		if (zflags) {
			cmd[ii].v.v0.flags = Z_LVAL_P(zflags);
		}
		if (zgroupid) {
			cmd[ii].v.v0.hashkey = Z_STRVAL_P(zgroupid);
			cmd[ii].v.v0.nhashkey = Z_STRLEN_P(zgroupid);
		}

		cmds[ii] = &cmd[ii];
	}

	cookie = bopcookie_init(data, return_value, pcbc_pp_ismapped(&pp_state));

	lcb_store(data->conn->lcb, cookie,
	        num_cmds, (const lcb_store_cmd_t*const*)cmds);
	pcbc_wait(data TSRMLS_CC);

	bopcookie_destroy(cookie);
    for (ii = 0; ii < num_cmds; ++ii) {
        efree((void*)cmds[ii]->v.v0.bytes);
    }
	efree(cmds);
	efree(cmd);
}

// append($id, $doc {, $cas, $groupid}) : MetaDoc
PHP_METHOD(Bucket, append)
{
	bucket_object *data = PHP_THISOBJ();
	lcb_store_cmd_t *cmd = NULL;
	lcb_store_cmd_t **cmds = NULL;
	int ii, num_cmds;
	pcbc_pp_state pp_state;
	zval *zid, *zvalue, *zcas, *zgroupid;
	bopcookie *cookie;

  // Note that groupid is experimental here and should not be used.
	pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id|value|cas,groupid",
				  &zid, &zvalue, &zcas, &zgroupid);

	num_cmds = pcbc_pp_keycount(&pp_state);
	cmd = emalloc(sizeof(lcb_store_cmd_t) * num_cmds);
	cmds = emalloc(sizeof(lcb_store_cmd_t*) * num_cmds);
	memset(cmd, 0, sizeof(lcb_store_cmd_t) * num_cmds);

	for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
		PCBC_CHECK_ZVAL(zid, IS_STRING, "id must be a string");
		PCBC_CHECK_ZVAL(zcas, IS_RESOURCE, "cas must be a CAS resource");
		PCBC_CHECK_ZVAL(zgroupid, IS_STRING, "groupid must be a string");

		cmd[ii].version = 0;
		cmd[ii].v.v0.operation = LCB_APPEND;
		cmd[ii].v.v0.key = Z_STRVAL_P(zid);
		cmd[ii].v.v0.nkey = Z_STRLEN_P(zid);

		pcbc_zval_to_bytes(data, zvalue, &cmd[ii].v.v0.bytes, &cmd[ii].v.v0.nbytes,
				&cmd[ii].v.v0.flags, &cmd[ii].v.v0.datatype TSRMLS_CC);

		if (zcas) {
			cmd[ii].v.v0.cas = cas_retrieve(zcas TSRMLS_CC);
		}
		if (zgroupid) {
			cmd[ii].v.v0.hashkey = Z_STRVAL_P(zgroupid);
			cmd[ii].v.v0.nhashkey = Z_STRLEN_P(zgroupid);
		}

		// Flags ignored for this op, enforced by libcouchbase
        cmd[ii].v.v0.flags = 0;

		cmds[ii] = &cmd[ii];
	}

	cookie = bopcookie_init(data, return_value, pcbc_pp_ismapped(&pp_state));

	lcb_store(data->conn->lcb, cookie,
	        num_cmds, (const lcb_store_cmd_t*const*)cmds);
	pcbc_wait(data TSRMLS_CC);

	bopcookie_destroy(cookie);
    for (ii = 0; ii < num_cmds; ++ii) {
        efree((void*)cmds[ii]->v.v0.bytes);
    }
	efree(cmds);
	efree(cmd);
}

// append($id, $doc {, $cas, $groupid}) : MetaDoc
PHP_METHOD(Bucket, prepend)
{
	bucket_object *data = PHP_THISOBJ();
	lcb_store_cmd_t *cmd = NULL;
	lcb_store_cmd_t **cmds = NULL;
	int ii, num_cmds;
	pcbc_pp_state pp_state;
	zval *zid, *zvalue, *zcas, *zgroupid;
	bopcookie *cookie;

  // Note that groupid is experimental here and should not be used.
	pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id|value|cas,groupid",
				  &zid, &zvalue, &zcas, &zgroupid);

	num_cmds = pcbc_pp_keycount(&pp_state);
	cmd = emalloc(sizeof(lcb_store_cmd_t) * num_cmds);
	cmds = emalloc(sizeof(lcb_store_cmd_t*) * num_cmds);
	memset(cmd, 0, sizeof(lcb_store_cmd_t) * num_cmds);

	for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
		PCBC_CHECK_ZVAL(zid, IS_STRING, "id must be a string");
		PCBC_CHECK_ZVAL(zcas, IS_RESOURCE, "cas must be a CAS resource");
		PCBC_CHECK_ZVAL(zgroupid, IS_STRING, "groupid must be a string");

		cmd[ii].version = 0;
		cmd[ii].v.v0.operation = LCB_PREPEND;
		cmd[ii].v.v0.key = Z_STRVAL_P(zid);
		cmd[ii].v.v0.nkey = Z_STRLEN_P(zid);

		pcbc_zval_to_bytes(data, zvalue, &cmd[ii].v.v0.bytes, &cmd[ii].v.v0.nbytes,
				&cmd[ii].v.v0.flags, &cmd[ii].v.v0.datatype TSRMLS_CC);

		if (zcas) {
			cmd[ii].v.v0.cas = cas_retrieve(zcas TSRMLS_CC);
		}
		if (zgroupid) {
			cmd[ii].v.v0.hashkey = Z_STRVAL_P(zgroupid);
			cmd[ii].v.v0.nhashkey = Z_STRLEN_P(zgroupid);
		}

        // Flags ignored for this op, enforced by libcouchbase
        cmd[ii].v.v0.flags = 0;

		cmds[ii] = &cmd[ii];
	}

	cookie = bopcookie_init(data, return_value, pcbc_pp_ismapped(&pp_state));

	lcb_store(data->conn->lcb, cookie,
	        num_cmds, (const lcb_store_cmd_t*const*)cmds);
	pcbc_wait(data TSRMLS_CC);

	bopcookie_destroy(cookie);
    for (ii = 0; ii < num_cmds; ++ii) {
        efree((void*)cmds[ii]->v.v0.bytes);
    }
	efree(cmds);
	efree(cmd);
}

// remove($id {, $cas, $groupid}) : MetaDoc
PHP_METHOD(Bucket, remove)
{
	bucket_object *data = PHP_THISOBJ();
	lcb_remove_cmd_t *cmd = NULL;
	lcb_remove_cmd_t **cmds = NULL;
	int ii, num_cmds;
	pcbc_pp_state pp_state;
	bopcookie *cookie;
	zval *zid, *zcas, *zgroupid;

  // Note that groupid is experimental here and should not be used.
	pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id||cas,groupid",
				  &zid, &zcas, &zgroupid);

	num_cmds = pcbc_pp_keycount(&pp_state);
	cmd = emalloc(sizeof(lcb_remove_cmd_t) * num_cmds);
	cmds = emalloc(sizeof(lcb_remove_cmd_t*) * num_cmds);
	memset(cmd, 0, sizeof(lcb_remove_cmd_t) * num_cmds);

	for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
		PCBC_CHECK_ZVAL(zid, IS_STRING, "id must be a string");
		PCBC_CHECK_ZVAL(zcas, IS_RESOURCE, "cas must be a CAS resource");
		PCBC_CHECK_ZVAL(zgroupid, IS_STRING, "groupid must be a string");

		cmd[ii].version = 0;
		cmd[ii].v.v0.key = Z_STRVAL_P(zid);
		cmd[ii].v.v0.nkey = Z_STRLEN_P(zid);

		if (zcas) {
			cmd[ii].v.v0.cas = cas_retrieve(zcas TSRMLS_CC);
		}
		if (zgroupid) {
			cmd[ii].v.v0.hashkey = Z_STRVAL_P(zgroupid);
			cmd[ii].v.v0.nhashkey = Z_STRLEN_P(zgroupid);
		}

		cmds[ii] = &cmd[ii];
	}

	cookie = bopcookie_init(data, return_value, pcbc_pp_ismapped(&pp_state));

	lcb_remove(data->conn->lcb, cookie,
	        num_cmds, (const lcb_remove_cmd_t*const*)cmds);
	pcbc_wait(data TSRMLS_CC);

	bopcookie_destroy(cookie);
	efree(cmds);
	efree(cmd);
}

// touch($id {, $lock, $groupid}) : MetaDoc
PHP_METHOD(Bucket, touch)
{
    bucket_object *data = PHP_THISOBJ();
    lcb_touch_cmd_t *cmd = NULL;
    lcb_touch_cmd_t **cmds = NULL;
    int ii, num_cmds;
    pcbc_pp_state pp_state;
    zval *zid, *zexpiry, *zgroupid;
    bopcookie *cookie;

  // Note that groupid is experimental here and should not be used.
    pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state,
                  "id|expiry|groupid",
                  &zid, &zexpiry, &zgroupid);

    num_cmds = pcbc_pp_keycount(&pp_state);
    cmd = emalloc(sizeof(lcb_touch_cmd_t) * num_cmds);
    cmds = emalloc(sizeof(lcb_touch_cmd_t*) * num_cmds);
    memset(cmd, 0, sizeof(lcb_touch_cmd_t) * num_cmds);

    for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
        PCBC_CHECK_ZVAL(zid, IS_STRING, "id must be a string");
        PCBC_CHECK_ZVAL(zexpiry, IS_LONG, "expiry must be an integer");
        PCBC_CHECK_ZVAL(zgroupid, IS_STRING, "groupid must be a string");

        cmd[ii].version = 0;
        cmd[ii].v.v0.key = Z_STRVAL_P(zid);
        cmd[ii].v.v0.nkey = Z_STRLEN_P(zid);
        cmd[ii].v.v0.exptime = Z_LVAL_P(zexpiry);
        if (zgroupid) {
            cmd[ii].v.v0.hashkey = Z_STRVAL_P(zgroupid);
            cmd[ii].v.v0.nhashkey = Z_STRLEN_P(zgroupid);
        }

        cmds[ii] = &cmd[ii];
    }

    cookie = bopcookie_init(data, return_value, pcbc_pp_ismapped(&pp_state));

    lcb_touch(data->conn->lcb, cookie,
            num_cmds, (const lcb_touch_cmd_t*const*)cmds);
    pcbc_wait(data TSRMLS_CC);

    bopcookie_destroy(cookie);
    efree(cmds);
    efree(cmd);
}

// get($id {, $lock, $groupid}) : MetaDoc
PHP_METHOD(Bucket, get)
{
	bucket_object *data = PHP_THISOBJ();
	lcb_get_cmd_t *cmd = NULL;
	lcb_get_cmd_t **cmds = NULL;
	int ii, num_cmds;
	pcbc_pp_state pp_state;
	zval *zid, *zlock, *zexpiry, *zgroupid;
	bopcookie *cookie;

  // Note that groupid is experimental here and should not be used.
	pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state,
				  "id||lockTime,expiry,groupid",
				  &zid, &zlock, &zexpiry, &zgroupid);

	num_cmds = pcbc_pp_keycount(&pp_state);
	cmd = emalloc(sizeof(lcb_get_cmd_t) * num_cmds);
	cmds = emalloc(sizeof(lcb_get_cmd_t*) * num_cmds);
	memset(cmd, 0, sizeof(lcb_get_cmd_t) * num_cmds);

	for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
		PCBC_CHECK_ZVAL(zid, IS_STRING, "id must be a string");
		PCBC_CHECK_ZVAL(zlock, IS_LONG, "lock must be an integer");
		PCBC_CHECK_ZVAL(zexpiry, IS_LONG, "expiry must be an integer");
		PCBC_CHECK_ZVAL(zgroupid, IS_STRING, "groupid must be a string");

		cmd[ii].version = 0;
		cmd[ii].v.v0.key = Z_STRVAL_P(zid);
		cmd[ii].v.v0.nkey = Z_STRLEN_P(zid);
		if (zexpiry) {
			cmd[ii].v.v0.lock = 0;
			cmd[ii].v.v0.exptime = Z_LVAL_P(zexpiry);
		} else if (zlock) {
			cmd[ii].v.v0.lock = 1;
			cmd[ii].v.v0.exptime = Z_LVAL_P(zlock);
		}
		if (zgroupid) {
			cmd[ii].v.v0.hashkey = Z_STRVAL_P(zgroupid);
			cmd[ii].v.v0.nhashkey = Z_STRLEN_P(zgroupid);
		}

		cmds[ii] = &cmd[ii];
	}

	cookie = bopcookie_init(data, return_value, pcbc_pp_ismapped(&pp_state));

	lcb_get(data->conn->lcb, cookie,
	        num_cmds, (const lcb_get_cmd_t*const*)cmds);
	pcbc_wait(data TSRMLS_CC);

	bopcookie_destroy(cookie);
	efree(cmds);
	efree(cmd);
}

// get($id {, $lock, $groupid}) : MetaDoc
PHP_METHOD(Bucket, getFromReplica)
{
	bucket_object *data = PHP_THISOBJ();
	lcb_get_replica_cmd_t *cmd = NULL;
	lcb_get_replica_cmd_t **cmds = NULL;
	int ii, num_cmds;
	pcbc_pp_state pp_state;
	zval *zid, *zindex, *zgroupid;
	bopcookie *cookie;

	// Note that groupid is experimental here and should not be used.
	pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state,
				  "id||index,groupid",
				  &zid, &zindex, &zgroupid);

	num_cmds = pcbc_pp_keycount(&pp_state);
	cmd = emalloc(sizeof(lcb_get_replica_cmd_t) * num_cmds);
	cmds = emalloc(sizeof(lcb_get_replica_cmd_t*) * num_cmds);
	memset(cmd, 0, sizeof(lcb_get_replica_cmd_t) * num_cmds);

	for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
		PCBC_CHECK_ZVAL(zid, IS_STRING, "id must be a string");
		PCBC_CHECK_ZVAL(zindex, IS_LONG, "index must be an integer");
		PCBC_CHECK_ZVAL(zgroupid, IS_STRING, "groupid must be a string");

		cmd[ii].version = 1;
		cmd[ii].v.v1.key = Z_STRVAL_P(zid);
		cmd[ii].v.v1.nkey = Z_STRLEN_P(zid);
		if (zindex) {
			cmd[ii].v.v1.index = Z_LVAL_P(zindex);
			if (cmd[ii].v.v1.index >= 0) {
				cmd[ii].v.v1.strategy = LCB_REPLICA_SELECT;
			} else {
				cmd[ii].v.v1.strategy = LCB_REPLICA_FIRST;
			}
		}
		if (zgroupid) {
			cmd[ii].v.v0.hashkey = Z_STRVAL_P(zgroupid);
			cmd[ii].v.v0.nhashkey = Z_STRLEN_P(zgroupid);
		}

		cmds[ii] = &cmd[ii];
	}

	cookie = bopcookie_init(data, return_value, pcbc_pp_ismapped(&pp_state));

	lcb_get_replica(data->conn->lcb, cookie,
	        num_cmds, (const lcb_get_replica_cmd_t*const*)cmds);
	pcbc_wait(data TSRMLS_CC);

	bopcookie_destroy(cookie);
	efree(cmds);
	efree(cmd);
}

// unlock($id {, $cas, $groupid}) : MetaDoc
PHP_METHOD(Bucket, unlock)
{
	bucket_object *data = PHP_THISOBJ();
	lcb_unlock_cmd_t *cmd = NULL;
	lcb_unlock_cmd_t **cmds = NULL;
	int ii, num_cmds;
	pcbc_pp_state pp_state;
	zval *zid, *zcas, *zgroupid;
	bopcookie *cookie;

  // Note that groupid is experimental here and should not be used.
	pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id||cas,groupid",
				  &zid, &zcas, &zgroupid);

	num_cmds = pcbc_pp_keycount(&pp_state);
	cmd = emalloc(sizeof(lcb_unlock_cmd_t) * num_cmds);
	cmds = emalloc(sizeof(lcb_unlock_cmd_t*) * num_cmds);
	memset(cmd, 0, sizeof(lcb_unlock_cmd_t) * num_cmds);

	for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
		PCBC_CHECK_ZVAL(zid, IS_STRING, "id must be a string");
		PCBC_CHECK_ZVAL(zcas, IS_RESOURCE, "cas must be a CAS resource");
		PCBC_CHECK_ZVAL(zgroupid, IS_STRING, "groupid must be a string");

		cmd[ii].version = 0;
		cmd[ii].v.v0.key = Z_STRVAL_P(zid);
		cmd[ii].v.v0.nkey = Z_STRLEN_P(zid);
		if (zcas) {
			cmd[ii].v.v0.cas = cas_retrieve(zcas TSRMLS_CC);
		}
		if (zgroupid) {
			cmd[ii].v.v0.hashkey = Z_STRVAL_P(zgroupid);
			cmd[ii].v.v0.nhashkey = Z_STRLEN_P(zgroupid);
		}

		cmds[ii] = &cmd[ii];
	}

	cookie = bopcookie_init(data, return_value, pcbc_pp_ismapped(&pp_state));

	lcb_unlock(data->conn->lcb, cookie,
	        num_cmds, (const lcb_unlock_cmd_t*const*)cmds);
	pcbc_wait(data TSRMLS_CC);

	bopcookie_destroy(cookie);
	efree(cmds);
	efree(cmd);
}

// counter($id, $delta {, $initial, $expiry}) : MetaDoc
PHP_METHOD(Bucket, counter)
{
	bucket_object *data = PHP_THISOBJ();
	lcb_arithmetic_cmd_t *cmd = NULL;
	lcb_arithmetic_cmd_t **cmds = NULL;
	int ii, num_cmds;
	pcbc_pp_state pp_state;
	zval *zid, *zdelta, *zinitial, *zexpiry, *zgroupid;
	bopcookie *cookie;

  // Note that groupid is experimental here and should not be used.
	pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id|delta|initial,expiry,groupid",
				  &zid, &zdelta, &zinitial, &zexpiry, &zgroupid);

	num_cmds = pcbc_pp_keycount(&pp_state);
	cmd = emalloc(sizeof(lcb_arithmetic_cmd_t) * num_cmds);
	cmds = emalloc(sizeof(lcb_arithmetic_cmd_t*) * num_cmds);
	memset(cmd, 0, sizeof(lcb_arithmetic_cmd_t) * num_cmds);

	for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
		PCBC_CHECK_ZVAL(zid, IS_STRING, "id must be a string");
		PCBC_CHECK_ZVAL(zdelta, IS_LONG, "delta must be an integer");
		PCBC_CHECK_ZVAL(zinitial, IS_LONG, "initial must be an integer");
		PCBC_CHECK_ZVAL(zexpiry, IS_LONG, "expiry must be an integer");
		PCBC_CHECK_ZVAL(zgroupid, IS_STRING, "groupid must be a string");

		cmd[ii].version = 0;
		cmd[ii].v.v0.key = Z_STRVAL_P(zid);
		cmd[ii].v.v0.nkey = Z_STRLEN_P(zid);
		cmd[ii].v.v0.delta = Z_LVAL_P(zdelta);
		if (zinitial) {
			cmd[ii].v.v0.initial = Z_LVAL_P(zinitial);
			cmd[ii].v.v0.create = 1;
		}
		if (zexpiry) {
			cmd[ii].v.v0.exptime = Z_LVAL_P(zexpiry);
		}
		if (zgroupid) {
			cmd[ii].v.v0.hashkey = Z_STRVAL_P(zgroupid);
			cmd[ii].v.v0.nhashkey = Z_STRLEN_P(zgroupid);
		}

		cmds[ii] = &cmd[ii];
	}

	cookie = bopcookie_init(data, return_value, pcbc_pp_ismapped(&pp_state));

	lcb_arithmetic(data->conn->lcb, cookie,
	        num_cmds, (const lcb_arithmetic_cmd_t*const*)cmds);
	pcbc_wait(data TSRMLS_CC);

	bopcookie_destroy(cookie);
	efree(cmds);
	efree(cmd);
}

PHP_METHOD(Bucket, http_request)
{
	bucket_object *data = PHP_THISOBJ();
	lcb_http_cmd_t cmd = { 0 };
	bopcookie *cookie;
	lcb_http_type_t type;
	lcb_http_method_t method;
	const char *contenttype;
	zval *ztype, *zmethod, *zpath, *zbody, *zcontenttype;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zzzzz",
				&ztype, &zmethod, &zpath, &zbody, &zcontenttype) == FAILURE) {
		RETURN_NULL();
	}

	if (Z_LVAL_P(ztype) == 1) {
		type = LCB_HTTP_TYPE_VIEW;
	} else if (Z_LVAL_P(ztype) == 2) {
		type = LCB_HTTP_TYPE_MANAGEMENT;
	} else if (Z_LVAL_P(ztype) == 3) {
	    type = LCB_HTTP_TYPE_N1QL;
	} else {
		RETURN_NULL();
	}

	if (Z_LVAL_P(zmethod) == 1) {
		method = LCB_HTTP_METHOD_GET;
	} else if (Z_LVAL_P(zmethod) == 2) {
		method = LCB_HTTP_METHOD_POST;
	} else if (Z_LVAL_P(zmethod) == 3) {
		method = LCB_HTTP_METHOD_PUT;
	} else if (Z_LVAL_P(zmethod) == 4) {
		method = LCB_HTTP_METHOD_DELETE;
	} else {
		RETURN_NULL();
	}

	if (Z_LVAL_P(zcontenttype) == 1) {
		contenttype = "application/json";
	} else if (Z_LVAL_P(zcontenttype) == 2) {
		contenttype = "application/x-www-form-urlencoded";
	} else {
		RETURN_NULL();
	}

	if (Z_TYPE_P(zpath) == IS_STRING) {
	    cmd.v.v0.path = Z_STRVAL_P(zpath);
	    cmd.v.v0.npath = Z_STRLEN_P(zpath);
	}
	if (Z_TYPE_P(zbody) == IS_STRING) {
		cmd.v.v0.body = Z_STRVAL_P(zbody);
		cmd.v.v0.nbody = Z_STRLEN_P(zbody);
	}
	cmd.v.v0.method = method;
	cmd.v.v0.chunked = 0;
	cmd.v.v0.content_type = contenttype;

	cookie = bopcookie_init(data, return_value, 0);

	lcb_make_http_request(data->conn->lcb, cookie, type, &cmd, NULL);
	pcbc_wait(data TSRMLS_CC);

	bopcookie_destroy(cookie);
}


PHP_METHOD(Bucket, durability)
{
	bucket_object *data = PHP_THISOBJ();
	lcb_durability_cmd_t *cmd = NULL;
	lcb_durability_opts_t opts = { 0 };
	lcb_durability_cmd_t **cmds = NULL;
	int ii, num_cmds;
	pcbc_pp_state pp_state;
	zval *zid, *zcas, *zgroupid, *zpersist, *zreplica;
	bopcookie *cookie;

	pcbc_pp_begin(ZEND_NUM_ARGS() TSRMLS_CC, &pp_state, "id||cas,groupid,persist_to,replicate_to",
				  &zid, &zcas, &zgroupid, &zpersist, &zreplica);

	num_cmds = pcbc_pp_keycount(&pp_state);
	cmd = emalloc(sizeof(lcb_durability_cmd_t) * num_cmds);
	cmds = emalloc(sizeof(lcb_durability_cmd_t*) * num_cmds);
	memset(cmd, 0, sizeof(lcb_durability_cmd_t) * num_cmds);

	for (ii = 0; pcbc_pp_next(&pp_state); ++ii) {
		PCBC_CHECK_ZVAL(zid, IS_STRING, "id must be a string");
		PCBC_CHECK_ZVAL(zcas, IS_RESOURCE, "cas must be a CAS resource");
		PCBC_CHECK_ZVAL(zgroupid, IS_STRING, "groupid must be a string");
		PCBC_CHECK_ZVAL(zpersist, IS_LONG, "persist_to must be an integer");
		PCBC_CHECK_ZVAL(zreplica, IS_LONG, "replicate_to must be an integer");

		cmd[ii].version = 0;
		cmd[ii].v.v0.key = Z_STRVAL_P(zid);
		cmd[ii].v.v0.nkey = Z_STRLEN_P(zid);
		if (zcas) {
			cmd[ii].v.v0.cas = cas_retrieve(zcas TSRMLS_CC);
		}
		if (zgroupid) {
			cmd[ii].v.v0.hashkey = Z_STRVAL_P(zgroupid);
			cmd[ii].v.v0.nhashkey = Z_STRLEN_P(zgroupid);
		}

		// These are written through each iteration, but only used once.
		if (zpersist) {
			opts.v.v0.persist_to = (lcb_U16)Z_LVAL_P(zpersist);
		}
		if (zreplica) {
			opts.v.v0.replicate_to = (lcb_U16)Z_LVAL_P(zreplica);
		}

		cmds[ii] = &cmd[ii];
	}

	cookie = bopcookie_init(data, return_value, pcbc_pp_ismapped(&pp_state));

	lcb_durability_poll(data->conn->lcb, cookie, &opts,
	        num_cmds, (const lcb_durability_cmd_t*const*)cmds);
	pcbc_wait(data TSRMLS_CC);

	bopcookie_destroy(cookie);
	efree(cmds);
	efree(cmd);
}


PHP_METHOD(Bucket, setTranscoder)
{
	bucket_object *data = PHP_THISOBJ();
	zval *zencoder, *zdecoder;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &zencoder, &zdecoder) == FAILURE) {
		RETURN_NULL();
	}

	Z_TRY_DELREF_P(&data->encoder);
	ZVAL_COPY(&data->encoder, zencoder);

	Z_TRY_DELREF_P(&data->decoder);
    ZVAL_COPY(&data->decoder, zdecoder);

	RETURN_NULL();
}

PHP_METHOD(Bucket, setOption)
{
	bucket_object *data = PHP_THISOBJ();
	long type, val;
	lcb_uint32_t lcbval;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ll", &type, &val) == FAILURE) {
		RETURN_NULL();
	}

	lcbval = val;
	lcb_cntl(data->conn->lcb, LCB_CNTL_SET, type, &lcbval);

	RETURN_LONG(val);
}

PHP_METHOD(Bucket, getOption)
{
	bucket_object *data = PHP_THISOBJ();
	long type;
	lcb_uint32_t lcbval;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &type) == FAILURE) {
		RETURN_NULL();
	}

	lcb_cntl(data->conn->lcb, LCB_CNTL_GET, type, &lcbval);

	RETURN_LONG(lcbval);
}

zend_function_entry bucket_methods[] = {
	PHP_ME(Bucket,  __construct,     NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)

	PHP_ME(Bucket,  insert,          NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Bucket,  upsert,          NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Bucket,  replace,         NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Bucket,  append,          NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Bucket,  prepend,         NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Bucket,  remove,          NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Bucket,  get,             NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Bucket,  getFromReplica,  NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Bucket,  touch,           NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Bucket,  counter,         NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Bucket,  unlock,          NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Bucket,  http_request,    NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Bucket,  durability,      NULL, ZEND_ACC_PUBLIC)

	PHP_ME(Bucket,  setTranscoder,   NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Bucket,  setOption,       NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Bucket,  getOption,       NULL, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};

void couchbase_init_bucket(INIT_FUNC_ARGS) {
	zend_class_entry ce;

	INIT_CLASS_ENTRY(ce, "_CouchbaseBucket", bucket_methods);
	ce.create_object = bucket_create_handler;
	bucket_ce = zend_register_internal_class(&ce TSRMLS_CC);

	memcpy(&bucket_handlers,
		zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	bucket_handlers.offset = XtOffsetOf(struct bucket_object, std);
	bucket_handlers.clone_obj = NULL;
	bucket_handlers.free_obj = bucket_free_storage;
}

void couchbase_shutdown_bucket(SHUTDOWN_FUNC_ARGS) {
	pcbc_lcb *cur, *next;
	next = PCBCG(first_bconn);
	while (next) {
		cur = next;
		next = cur->next;
		lcb_destroy(cur->lcb);
		free(cur->key);
		free(cur);
	}
	PCBCG(first_bconn) = NULL;
	PCBCG(last_bconn) = NULL;
}
