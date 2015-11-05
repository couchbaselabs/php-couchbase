#include "couchbase.h"
#include "cas.h"
#include "metadoc.h"
#include "phpstubstr.h"
#include <fastlz.h>

#if HAVE_ZLIB
#include <zlib.h>
#endif

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

ZEND_DECLARE_MODULE_GLOBALS(couchbase)

#define PCBC_LONG_CONSTANT(key, val) \
	REGISTER_LONG_CONSTANT("COUCHBASE_"key, val, CONST_CS | CONST_PERSISTENT)
#define PCBC_REGISTER_CONST(c) \
	REGISTER_LONG_CONSTANT("COUCHBASE_"#c, c, CONST_CS | CONST_PERSISTENT)
#define PCBC_REGISTER_LCBCONST(c) \
	REGISTER_LONG_CONSTANT("COUCHBASE_"#c, LCB_##c, CONST_CS | CONST_PERSISTENT)

static void php_extname_init_globals(zend_couchbase_globals *couchbase_globals)
{
	couchbase_globals->first_bconn = NULL;
	couchbase_globals->last_bconn = NULL;
}

PHP_MINIT_FUNCTION(couchbase)
{
	ZEND_INIT_MODULE_GLOBALS(couchbase, php_extname_init_globals, NULL);

	couchbase_init_exceptions(INIT_FUNC_ARGS_PASSTHRU);
	couchbase_init_cas(INIT_FUNC_ARGS_PASSTHRU);
	couchbase_init_metadoc(INIT_FUNC_ARGS_PASSTHRU);
	couchbase_init_cluster(INIT_FUNC_ARGS_PASSTHRU);
	couchbase_init_bucket(INIT_FUNC_ARGS_PASSTHRU);

	PCBC_REGISTER_CONST(PERSISTTO_MASTER);
	PCBC_REGISTER_CONST(PERSISTTO_ONE);
	PCBC_REGISTER_CONST(PERSISTTO_TWO);
	PCBC_REGISTER_CONST(PERSISTTO_THREE);
	PCBC_REGISTER_CONST(REPLICATETO_ONE);
	PCBC_REGISTER_CONST(REPLICATETO_TWO);
	PCBC_REGISTER_CONST(REPLICATETO_THREE);

	PCBC_REGISTER_LCBCONST(CNTL_OP_TIMEOUT);
	PCBC_REGISTER_LCBCONST(CNTL_VIEW_TIMEOUT);
	PCBC_REGISTER_LCBCONST(CNTL_DURABILITY_INTERVAL);
	PCBC_REGISTER_LCBCONST(CNTL_DURABILITY_TIMEOUT);
	PCBC_REGISTER_LCBCONST(CNTL_HTTP_TIMEOUT);
	PCBC_REGISTER_LCBCONST(CNTL_CONFIGURATION_TIMEOUT);
	PCBC_REGISTER_LCBCONST(CNTL_CONFDELAY_THRESH);
	PCBC_REGISTER_LCBCONST(CNTL_CONFIG_NODE_TIMEOUT);
	PCBC_REGISTER_LCBCONST(CNTL_HTCONFIG_IDLE_TIMEOUT);

	PCBC_LONG_CONSTANT("SUCCESS", LCB_SUCCESS);
	PCBC_LONG_CONSTANT("AUTH_CONTINUE", LCB_AUTH_CONTINUE);
	PCBC_LONG_CONSTANT("AUTH_ERROR", LCB_AUTH_ERROR);
	PCBC_LONG_CONSTANT("DELTA_BADVAL", LCB_DELTA_BADVAL);
	PCBC_LONG_CONSTANT("E2BIG", LCB_E2BIG);
	PCBC_LONG_CONSTANT("EBUSY", LCB_EBUSY);
	PCBC_LONG_CONSTANT("ENOMEM", LCB_ENOMEM);
	PCBC_LONG_CONSTANT("ERANGE", LCB_ERANGE);
	PCBC_LONG_CONSTANT("ERROR", LCB_ERROR);
	PCBC_LONG_CONSTANT("ETMPFAIL", LCB_ETMPFAIL);
	PCBC_LONG_CONSTANT("EINVAL", LCB_EINVAL);
	PCBC_LONG_CONSTANT("CLIENT_ETMPFAIL", LCB_CLIENT_ETMPFAIL);
	PCBC_LONG_CONSTANT("KEY_EEXISTS", LCB_KEY_EEXISTS);
	PCBC_LONG_CONSTANT("KEY_ENOENT", LCB_KEY_ENOENT);
	PCBC_LONG_CONSTANT("DLOPEN_FAILED", LCB_DLOPEN_FAILED);
	PCBC_LONG_CONSTANT("DLSYM_FAILED", LCB_DLSYM_FAILED);
	PCBC_LONG_CONSTANT("NETWORK_ERROR", LCB_NETWORK_ERROR);
	PCBC_LONG_CONSTANT("NOT_MY_VBUCKET", LCB_NOT_MY_VBUCKET);
	PCBC_LONG_CONSTANT("NOT_STORED", LCB_NOT_STORED);
	PCBC_LONG_CONSTANT("NOT_SUPPORTED", LCB_NOT_SUPPORTED);
	PCBC_LONG_CONSTANT("UNKNOWN_COMMAND", LCB_UNKNOWN_COMMAND);
	PCBC_LONG_CONSTANT("UNKNOWN_HOST", LCB_UNKNOWN_HOST);
	PCBC_LONG_CONSTANT("PROTOCOL_ERROR", LCB_PROTOCOL_ERROR);
	PCBC_LONG_CONSTANT("ETIMEDOUT", LCB_ETIMEDOUT);
	PCBC_LONG_CONSTANT("BUCKET_ENOENT", LCB_BUCKET_ENOENT);
	PCBC_LONG_CONSTANT("CLIENT_ENOMEM", LCB_CLIENT_ENOMEM);
	PCBC_LONG_CONSTANT("CONNECT_ERROR", LCB_CONNECT_ERROR);
	PCBC_LONG_CONSTANT("EBADHANDLE", LCB_EBADHANDLE);
	PCBC_LONG_CONSTANT("SERVER_BUG", LCB_SERVER_BUG);
	PCBC_LONG_CONSTANT("PLUGIN_VERSION_MISMATCH", LCB_PLUGIN_VERSION_MISMATCH);
	PCBC_LONG_CONSTANT("INVALID_HOST_FORMAT", LCB_INVALID_HOST_FORMAT);
	PCBC_LONG_CONSTANT("INVALID_CHAR", LCB_INVALID_CHAR);
	PCBC_LONG_CONSTANT("DURABILITY_ETOOMANY", LCB_DURABILITY_ETOOMANY);
	PCBC_LONG_CONSTANT("DUPLICATE_COMMANDS", LCB_DUPLICATE_COMMANDS);
	PCBC_LONG_CONSTANT("EINTERNAL", LCB_EINTERNAL);
	PCBC_LONG_CONSTANT("NO_MATCHING_SERVER", LCB_NO_MATCHING_SERVER);
	PCBC_LONG_CONSTANT("BAD_ENVIRONMENT", LCB_BAD_ENVIRONMENT);
	PCBC_LONG_CONSTANT("VALUE_F_JSON", LCB_VALUE_F_JSON);

	// TODO: Maybe not have these?
	PCBC_LONG_CONSTANT("TMPFAIL", LCB_ETMPFAIL);
	PCBC_LONG_CONSTANT("KEYALREADYEXISTS", LCB_KEY_EEXISTS);
	PCBC_LONG_CONSTANT("KEYNOTFOUND", LCB_KEY_ENOENT);

	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(couchbase)
{
	couchbase_shutdown_bucket(SHUTDOWN_FUNC_ARGS_PASSTHRU);

	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(couchbase)
{
	if (PG(last_error_message) && PG(last_error_type) == E_ERROR) {
		couchbase_shutdown_bucket(SHUTDOWN_FUNC_ARGS_PASSTHRU);
	}
	return SUCCESS;
}

PHP_RINIT_FUNCTION(couchbase)
{
	
	int stub_idx;
	for (stub_idx = 0; stub_idx < sizeof(PCBC_PHP_CODESTR) / sizeof(pcbc_stub_data); ++stub_idx) {
		pcbc_stub_data *this_stub = &PCBC_PHP_CODESTR[stub_idx];
		int retval = zend_eval_string((char*)this_stub->data, NULL, (char*)this_stub->filename TSRMLS_CC);
		if (retval != SUCCESS) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to inject Couchbase stubs.");
			return FAILURE;
		}
	}
	return SUCCESS;
}

PHP_FUNCTION(couchbase_zlib_compress)
{
#if HAVE_ZLIB
    zval *zdata;
    void *dataIn, *dataOut;
    unsigned long dataSize, dataOutSize;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
            "z", &zdata) == FAILURE) {
        RETURN_NULL();
    }

    dataIn = Z_STRVAL_P(zdata);
    dataSize = Z_STRLEN_P(zdata);
    dataOutSize = compressBound(dataSize);
    dataOut = emalloc(dataOutSize);
    compress((uint8_t*)dataOut + 4, &dataOutSize, dataIn, dataSize);
    *(uint32_t*)dataOut = dataSize;

    RETURN_STRINGL(dataOut, 4 + dataOutSize, 0);
#else
    zend_throw_exception(NULL, "The zlib library was not available when the couchbase extension was built.", 0 TSRMLS_CC);
    RETURN_NULL();
#endif
}

PHP_FUNCTION(couchbase_zlib_decompress)
{
#if HAVE_ZLIB
    zval *zdata;
    void *dataIn, *dataOut;
    unsigned long dataSize, dataOutSize;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
            "z", &zdata) == FAILURE) {
        RETURN_NULL();
    }

    dataIn = Z_STRVAL_P(zdata);
    dataSize = Z_STRLEN_P(zdata);
    dataOutSize = *(uint32_t*)dataIn;
    dataOut = emalloc(dataOutSize);
    uncompress(dataOut, &dataOutSize, (uint8_t*)dataIn + 4, dataSize - 4);

    RETURN_STRINGL(dataOut, dataOutSize, 0);
#else
    zend_throw_exception(NULL, "The zlib library was not available when the couchbase extension was built.", 0 TSRMLS_CC);
    RETURN_NULL();
#endif
}

PHP_FUNCTION(couchbase_fastlz_compress)
{
    zval *zdata;
    void *dataIn, *dataOut;
    unsigned long dataSize, dataOutSize;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
            "z", &zdata) == FAILURE) {
        RETURN_NULL();
    }

    dataIn = Z_STRVAL_P(zdata);
    dataSize = Z_STRLEN_P(zdata);
    dataOutSize = 4 + (dataSize * 1.05);
    dataOut = emalloc(dataOutSize);
    dataOutSize = fastlz_compress(dataIn, dataSize, (uint8_t*)dataOut + 4);
    *(uint32_t*)dataOut = dataSize;

    RETURN_STRINGL(dataOut, 4 + dataOutSize, 0);
}

PHP_FUNCTION(couchbase_fastlz_decompress)
{
    zval *zdata;
    void *dataIn, *dataOut;
    unsigned long dataSize, dataOutSize;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
            "z", &zdata) == FAILURE) {
        RETURN_NULL();
    }

    dataIn = Z_STRVAL_P(zdata);
    dataSize = Z_STRLEN_P(zdata);
    dataOutSize = *(uint32_t*)dataIn;
    dataOut = emalloc(dataOutSize);
    dataOutSize = fastlz_decompress(
            (uint8_t*)dataIn + 4, dataSize - 4, dataOut, dataOutSize);

    RETURN_STRINGL(dataOut, dataOutSize, 0);
}

static zend_function_entry couchbase_functions[] = {
    PHP_FE(couchbase_fastlz_compress, NULL)
    PHP_FE(couchbase_fastlz_decompress, NULL)
    PHP_FE(couchbase_zlib_compress, NULL)
    PHP_FE(couchbase_zlib_decompress, NULL)
    {NULL, NULL, NULL}
};

#if ZEND_MODULE_API_NO >= 220050617
static zend_module_dep php_couchbase_deps[] = {
		ZEND_MODULE_REQUIRED("json"),
		{NULL,NULL,NULL}
};
#endif

zend_module_entry couchbase_module_entry = {
#if ZEND_MODULE_API_NO >= 220050617
	STANDARD_MODULE_HEADER_EX,
	NULL,
	php_couchbase_deps,
#elif ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	PHP_COUCHBASE_EXTNAME,
	couchbase_functions,
	PHP_MINIT(couchbase),
	PHP_MSHUTDOWN(couchbase),
	PHP_RINIT(couchbase),
	PHP_RSHUTDOWN(couchbase),
	NULL,
#if ZEND_MODULE_API_NO >= 20010901
	PHP_COUCHBASE_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_COUCHBASE
ZEND_GET_MODULE(couchbase)
#endif

