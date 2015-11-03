#include <libcouchbase/couchbase.h>
#include "couchbase.h"
#include "phphelpers.h"
#include "exception.h"
#include "cluster.h"
#include "metadoc.h"

zend_object_handlers cluster_handlers;

static inline struct cluster_object * php_cluster_object_fetch_object(zend_object *obj) {
      return (struct cluster_object *)((char *)obj - XtOffsetOf(struct cluster_object, std));
}
#define PHP_THISOBJ() php_cluster_object_fetch_object(Z_OBJ_P(getThis()));

void cluster_free_storage(zend_object *object TSRMLS_DC)
{
    cluster_object *obj = php_cluster_object_fetch_object(object);

	//zend_hash_destroy(obj->std.properties);
	//FREE_HASHTABLE(obj->std.properties);
}

zend_object * cluster_create_handler(zend_class_entry *type TSRMLS_DC)
{
    cluster_object *obj = ecalloc(1,
             sizeof(struct cluster_object) +
             zend_object_properties_size(type));

    memset(obj, 0, sizeof(cluster_object));

    zend_object_std_init(&obj->std, type TSRMLS_CC);
	obj->std.ce = type;
	obj->std.handlers = &cluster_handlers;

    phlp_object_properties_init(&obj->std, type);

	return &obj->std;
}

typedef struct {
	zval *retval;
	cluster_object *owner;
} copcookie;

copcookie * copcookie_init(cluster_object *clusterobj, zval *return_value) {
	copcookie *cookie = emalloc(sizeof(copcookie));
	cookie->owner = clusterobj;
	cookie->retval = return_value;
	ZVAL_NULL(cookie->retval);
	return cookie;
}

void ccookie_error(const copcookie *cookie, cluster_object *data, zval *doc,
				  lcb_error_t error TSRMLS_DC) {
    make_lcb_exception(&data->error, error, NULL TSRMLS_CC);
}

static void http_complete_callback(lcb_http_request_t request, lcb_t instance,
			const void *cookie, lcb_error_t error,
			const lcb_http_resp_t *resp) {
	cluster_object *data = (cluster_object*)lcb_get_cookie(instance);
	zval *doc = ((copcookie*)cookie)->retval;
	TSRMLS_FETCH();

	if (error == LCB_SUCCESS) {
		ZVAL_STRINGL(doc, resp->v.v0.bytes, resp->v.v0.nbytes);
	} else {
		ccookie_error(cookie, data, NULL, error TSRMLS_CC);
	}
}

static int pcbc_wait(cluster_object *obj TSRMLS_DC)
{
	lcb_t instance = obj->lcb;
	ZVAL_UNDEF(&obj->error);

	lcb_wait(instance);

    if (Z_TYPE(obj->error) != IS_UNDEF) {
        zend_throw_exception_object(&obj->error TSRMLS_CC);
        ZVAL_UNDEF(&obj->error);
        return 0;
    }

	return 1;
}

zend_class_entry *cluster_ce;

PHP_METHOD(Cluster, __construct)
{
	cluster_object *data = PHP_THISOBJ();
	zval *zdsn = NULL;
	zval *zname = NULL;
	zval *zpassword = NULL;
	char *dsn = NULL;
	char *name = NULL;
	char *password = NULL;
	lcb_error_t err;
	lcb_t instance;
	struct lcb_create_st create_options;

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

	memset(&create_options, 0, sizeof(create_options));
	create_options.version = 3;
	create_options.v.v3.connstr = dsn;
	create_options.v.v3.username = name;
	create_options.v.v3.passwd = password;
	create_options.v.v3.type = LCB_TYPE_CLUSTER;
	err = lcb_create(&instance, &create_options);

	if (dsn) efree(dsn);
	if (name) efree(name);
	if (password) efree(password);

	if (err != LCB_SUCCESS) {
		throw_lcb_exception(err);
		RETURN_NULL();
	}

	lcb_set_http_complete_callback(instance, http_complete_callback);

	data->lcb = instance;
}

PHP_METHOD(Cluster, connect)
{
	cluster_object *data = PHP_THISOBJ();
	lcb_error_t err;

	err = lcb_connect(data->lcb);
	if (err != LCB_SUCCESS) {
		throw_lcb_exception(err);
		RETURN_NULL();
	}

	lcb_wait(data->lcb);

	err = lcb_get_bootstrap_status(data->lcb);
	if (err != LCB_SUCCESS) {
		throw_lcb_exception(err);
	}

	RETURN_NULL();
}

PHP_METHOD(Cluster, http_request)
{
	cluster_object *data = PHP_THISOBJ();
	lcb_http_cmd_t cmd = { 0 };
	copcookie *cookie;
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

	cmd.v.v0.path = Z_STRVAL_P(zpath);
	cmd.v.v0.npath = Z_STRLEN_P(zpath);
	if (Z_TYPE_P(zbody) == IS_STRING) {
		cmd.v.v0.body = Z_STRVAL_P(zbody);
		cmd.v.v0.nbody = Z_STRLEN_P(zbody);
	}
	cmd.v.v0.method = method;
	cmd.v.v0.chunked = 0;
	cmd.v.v0.content_type = contenttype;

	cookie = copcookie_init(data, return_value);

	lcb_make_http_request(data->lcb, cookie, type, &cmd, NULL);
	pcbc_wait(data TSRMLS_CC);

	efree(cookie);
}

zend_function_entry cluster_methods[] = {
	PHP_ME(Cluster,  __construct,     NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
	PHP_ME(Cluster,  connect,         NULL, ZEND_ACC_PUBLIC)
	PHP_ME(Cluster,  http_request,    NULL, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};

void couchbase_init_cluster(INIT_FUNC_ARGS) {
	zend_class_entry ce;
	INIT_CLASS_ENTRY(ce, "_CouchbaseCluster", cluster_methods);
	ce.create_object = cluster_create_handler;
	cluster_ce = zend_register_internal_class(&ce TSRMLS_CC);

	memcpy(&cluster_handlers,
			zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	cluster_handlers.offset = XtOffsetOf(struct cluster_object, std);
	cluster_handlers.clone_obj = NULL;
	cluster_handlers.free_obj = cluster_free_storage;
}
