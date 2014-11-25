#include <libcouchbase/couchbase.h>
#include "couchbase.h"
#include "exception.h"

zend_object_handlers cluster_handlers;

typedef struct cluster_object {
    zend_object std;
    lcb_t lcb;
    zval *error;
} cluster_object;

void cluster_free_storage(void *object TSRMLS_DC)
{
	cluster_object *obj = (cluster_object *)object;

    zend_hash_destroy(obj->std.properties);
    FREE_HASHTABLE(obj->std.properties);

    if(obj->lcb)
    {
        lcb_destroy(obj->lcb);    
    }

    efree(obj);
}

zend_object_value cluster_create_handler(zend_class_entry *type TSRMLS_DC)
{
    zval *tmp;
    zend_object_value retval;

    cluster_object *obj = (cluster_object *)emalloc(sizeof(cluster_object));
    memset(obj, 0, sizeof(cluster_object));
    obj->std.ce = type;

    ALLOC_HASHTABLE(obj->std.properties);
    zend_hash_init(obj->std.properties, 0, NULL, ZVAL_PTR_DTOR, 0);
#if PHP_VERSION_ID < 50399
    zend_hash_copy(obj->std.properties, &type->default_properties,
        (copy_ctor_func_t)zval_add_ref, (void *)&tmp, sizeof(zval *));
#else
    object_properties_init(&obj->std, type);
#endif

    retval.handle = zend_objects_store_put(obj, NULL,
        cluster_free_storage, NULL TSRMLS_CC);
    retval.handlers = &cluster_handlers;

    return retval;
}

extern zend_class_entry *metadoc_ce;

typedef struct {
    zval *retval;
} op_cookie;

#define MAKE_STD_COOKIE(cookie, return_value) { \
    cookie = emalloc(sizeof(op_cookie)); \
    cookie->retval = return_value; \
    ZVAL_NULL(cookie->retval); \
}

void ccookie_error(const op_cookie *cookie, cluster_object *data, zval *doc,
                  lcb_error_t error TSRMLS_DC) {
    if (Z_TYPE_P(cookie->retval) == IS_ARRAY) {
        zval *zerror = create_lcb_exception(error TSRMLS_CC);
        object_init_ex(doc, metadoc_ce);
        zend_update_property(metadoc_ce, doc, "error", sizeof("error")-1, zerror TSRMLS_CC);
    } else {
        data->error = create_lcb_exception(error TSRMLS_CC);
    }
}

static void error_callback(lcb_t instance, lcb_error_t error, const char *errinfo)
{
    cluster_object *data = (cluster_object*)lcb_get_cookie(instance);
    TSRMLS_FETCH();
    data->error = create_lcb_exception(error TSRMLS_CC);
}

static void http_complete_callback(lcb_http_request_t request, lcb_t instance,
            const void *cookie, lcb_error_t error,
            const lcb_http_resp_t *resp) {
    cluster_object *data = (cluster_object*)lcb_get_cookie(instance);
    zval *doc = ((op_cookie*)cookie)->retval;
    TSRMLS_FETCH();

    if (error == LCB_SUCCESS) {
        ZVAL_STRINGL(doc, resp->v.v0.bytes, resp->v.v0.nbytes, 1);
    } else {
        ccookie_error(cookie, data, NULL, error TSRMLS_CC);
    }
}

static int pcbc_wait(lcb_t instance TSRMLS_DC)
{
    cluster_object *data = (cluster_object*)lcb_get_cookie(instance);
    data->error = NULL;

    lcb_wait(instance);

    if (data->error) {
        zend_throw_exception_object(data->error TSRMLS_CC);
        data->error = NULL;
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

	if (zdsn) {
        if (Z_TYPE_P(zdsn) == IS_STRING) {
            dsn = estrndup(Z_STRVAL_P(zdsn), Z_STRLEN_P(zdsn));
        } else {
            php_printf("Expected dsn as string\n");
            RETURN_NULL();
        }
    }

    if (zname) {
        if (Z_TYPE_P(zname) == IS_STRING) {
            name = estrndup(Z_STRVAL_P(zname), Z_STRLEN_P(zname));
        } else {
            php_printf("Expected bucket name as string\n");
            if (dsn) efree(dsn);
            RETURN_NULL();
        }
    }

    if (zpassword) {
        if (Z_TYPE_P(zpassword) == IS_STRING) {
            password = estrndup(Z_STRVAL_P(zpassword), Z_STRLEN_P(zpassword));
        } else {
            php_printf("Expected bucket password as string\n");
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
        zend_throw_exception_object(create_lcb_exception(err TSRMLS_CC) TSRMLS_CC);
        RETURN_NULL();
    }

	lcb_set_cookie(instance, data);
	lcb_set_error_callback(instance, error_callback);
	lcb_set_http_complete_callback(instance, http_complete_callback);

	data->lcb = instance;
}

PHP_METHOD(Cluster, connect)
{
	cluster_object *data = PHP_THISOBJ();
	lcb_error_t err;

    err = lcb_connect(data->lcb);
    if (err != LCB_SUCCESS) {
        zend_throw_exception_object(create_lcb_exception(err TSRMLS_CC) TSRMLS_CC);
        RETURN_NULL();
    }

    pcbc_wait(data->lcb TSRMLS_CC);
}

PHP_METHOD(Cluster, http_request)
{
    cluster_object *data = PHP_THISOBJ();
    lcb_http_cmd_t cmd = { 0 };
    op_cookie *cookie;
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

    MAKE_STD_COOKIE(cookie, return_value);

    lcb_make_http_request(data->lcb, cookie, type, &cmd, NULL);
    pcbc_wait(data->lcb TSRMLS_CC);

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
    cluster_handlers.clone_obj = NULL;
}
