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
#include <ext/standard/info.h>

#ifdef HAVE_FASTLZ_H
#include <fastlz.h>
#else
#include "fastlz/fastlz.h"
#endif

#if HAVE_COUCHBASE_ZLIB
#include <zlib.h>
#endif

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/ext", __FILE__, __LINE__

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

#ifdef ZTS
ts_rsrc_id *pcbc_json_globals_id;
#else
zend_json_globals *pcbc_json_globals;
#endif
zend_class_entry *pcbc_json_serializable_ce;

ZEND_DECLARE_MODULE_GLOBALS(couchbase)

#define COUCHBASE_SERTYPE_JSON 0
#define COUCHBASE_SERTYPE_IGBINARY 1
#define COUCHBASE_SERTYPE_PHP 2
#define DEFAULT_COUCHBASE_SERTYPE COUCHBASE_SERTYPE_JSON

#define COUCHBASE_CMPRTYPE_NONE 0
#define COUCHBASE_CMPRTYPE_ZLIB 1
#define COUCHBASE_CMPRTYPE_FASTLZ 2
#define DEFAULT_COUCHBASE_CMPRTYPE COUCHBASE_CMPRTYPE_NONE

#define DEFAULT_COUCHBASE_CMPRTHRESH 0
#define DEFAULT_COUCHBASE_CMPRFACTOR 0

#define COUCHBASE_VAL_MASK 0x1F
#define COUCHBASE_VAL_IS_STRING 0x00
#define COUCHBASE_VAL_IS_LONG 0x01
#define COUCHBASE_VAL_IS_DOUBLE 0x02
#define COUCHBASE_VAL_IS_BOOL 0x03
#define COUCHBASE_VAL_IS_SERIALIZED 0x04
#define COUCHBASE_VAL_IS_IGBINARY 0x05
#define COUCHBASE_VAL_IS_JSON 0x06

#define COUCHBASE_COMPRESSION_MASK 0x07 << 5
#define COUCHBASE_COMPRESSION_NONE 0x00 << 5
#define COUCHBASE_COMPRESSION_ZLIB 0x01 << 5
#define COUCHBASE_COMPRESSION_FASTLZ 0x02 << 5
#define COUCHBASE_COMPRESSION_MCISCOMPRESSED 0x01 << 4

#define COUCHBASE_CFFMT_MASK 0xFF << 24
#define COUCHBASE_CFFMT_EMPTY 0x0 /* special case when values created by tools or incr/decr commands */
#define COUCHBASE_CFFMT_PRIVATE 0x01 << 24
#define COUCHBASE_CFFMT_JSON 0x02 << 24
#define COUCHBASE_CFFMT_RAW 0x03 << 24
#define COUCHBASE_CFFMT_STRING 0x04 << 24

#define DEFAULT_COUCHBASE_JSONASSOC 0

extern struct pcbc_logger_st pcbc_logger;

static PHP_INI_MH(OnUpdateLogLevel)
{
    const char *str_val = ZSTR_VAL(new_value);
    if (!new_value) {
        pcbc_logger.minlevel = LCB_LOG_WARN;
    } else if (!strcmp(str_val, "TRACE") || !strcmp(str_val, "TRAC")) {
        pcbc_logger.minlevel = LCB_LOG_TRACE;
    } else if (!strcmp(str_val, "DEBUG") || !strcmp(str_val, "DEBG")) {
        pcbc_logger.minlevel = LCB_LOG_DEBUG;
    } else if (!strcmp(str_val, "INFO")) {
        pcbc_logger.minlevel = LCB_LOG_INFO;
    } else if (!strcmp(str_val, "WARN")) {
        pcbc_logger.minlevel = LCB_LOG_WARN;
    } else if (!strcmp(str_val, "ERROR") || !strcmp(str_val, "EROR")) {
        pcbc_logger.minlevel = LCB_LOG_ERROR;
    } else if (!strcmp(str_val, "FATAL") || !strcmp(str_val, "FATL")) {
        pcbc_logger.minlevel = LCB_LOG_FATAL;
    } else {
        return FAILURE;
    }

    return OnUpdateString(entry, new_value, mh_arg1, mh_arg2, mh_arg3, stage);
}

static PHP_INI_MH(OnUpdateFormat)
{
    const char *str_val = ZSTR_VAL(new_value);
    if (!new_value) {
        PCBCG(enc_format_i) = COUCHBASE_SERTYPE_JSON;
    } else if (!strcmp(str_val, "json") || !strcmp(str_val, "JSON")) {
        PCBCG(enc_format_i) = COUCHBASE_SERTYPE_JSON;
    } else if (!strcmp(str_val, "php") || !strcmp(str_val, "PHP")) {
        PCBCG(enc_format_i) = COUCHBASE_SERTYPE_PHP;
    } else {
        return FAILURE;
    }

    return OnUpdateString(entry, new_value, mh_arg1, mh_arg2, mh_arg3, stage);
}

static PHP_INI_MH(OnUpdateCmpr)
{
    const char *str_val = ZSTR_VAL(new_value);
    if (!new_value) {
        PCBCG(enc_cmpr_i) = COUCHBASE_CMPRTYPE_NONE;
    } else if (!strcmp(str_val, "off") || !strcmp(str_val, "none") || !strcmp(str_val, "OFF") ||
               !strcmp(str_val, "NONE")) {
        PCBCG(enc_cmpr_i) = COUCHBASE_CMPRTYPE_NONE;
#if HAVE_COUCHBASE_ZLIB
    } else if (!strcmp(str_val, "zlib") || !strcmp(str_val, "ZLIB")) {
        PCBCG(enc_cmpr_i) = COUCHBASE_CMPRTYPE_ZLIB;
#endif
    } else if (!strcmp(str_val, "fastlz") || !strcmp(str_val, "FASTLZ")) {
        PCBCG(enc_cmpr_i) = COUCHBASE_CMPRTYPE_FASTLZ;
    } else {
        return FAILURE;
    }

    return OnUpdateString(entry, new_value, mh_arg1, mh_arg2, mh_arg3, stage);
}
// clang-format off
PHP_INI_BEGIN()
STD_PHP_INI_ENTRY("couchbase.log_level",                     "WARN", PHP_INI_ALL, OnUpdateLogLevel,   log_level,           zend_couchbase_globals, couchbase_globals)
STD_PHP_INI_ENTRY("couchbase.encoder.format",                "json", PHP_INI_ALL, OnUpdateFormat,     enc_format,          zend_couchbase_globals, couchbase_globals)
STD_PHP_INI_ENTRY("couchbase.encoder.compression",           "off",  PHP_INI_ALL, OnUpdateCmpr,       enc_cmpr ,           zend_couchbase_globals, couchbase_globals)
STD_PHP_INI_ENTRY("couchbase.encoder.compression_threshold", "0",    PHP_INI_ALL, OnUpdateLongGEZero, enc_cmpr_threshold,  zend_couchbase_globals, couchbase_globals)
STD_PHP_INI_ENTRY("couchbase.encoder.compression_factor",    "0.0",  PHP_INI_ALL, OnUpdateReal,       enc_cmpr_factor,     zend_couchbase_globals, couchbase_globals)
STD_PHP_INI_ENTRY("couchbase.decoder.json_arrays",           "0",    PHP_INI_ALL, OnUpdateBool,       dec_json_array,      zend_couchbase_globals, couchbase_globals)
STD_PHP_INI_ENTRY("couchbase.pool.max_idle_time_sec",        "60",   PHP_INI_ALL, OnUpdateLongGEZero, pool_max_idle_time,  zend_couchbase_globals, couchbase_globals)

STD_PHP_INI_ENTRY("couchbase.allow_fallback_to_bucket_connection", "0", PHP_INI_ALL, OnUpdateBool, allow_fallback_to_bucket, zend_couchbase_globals, couchbase_globals)
PHP_INI_END()
// clang-format on

#define PCBC_LONG_CONSTANT(key, val) REGISTER_LONG_CONSTANT("COUCHBASE_" key, val, CONST_CS | CONST_PERSISTENT)
#define PCBC_REGISTER_CONST(c) REGISTER_LONG_CONSTANT("COUCHBASE_" #c, c, CONST_CS | CONST_PERSISTENT)
#define PCBC_REGISTER_CONST_RAW(c) REGISTER_LONG_CONSTANT(#c, c, CONST_CS | CONST_PERSISTENT)
#define PCBC_REGISTER_LCBCONST(c) REGISTER_LONG_CONSTANT("COUCHBASE_" #c, LCB_##c, CONST_CS | CONST_PERSISTENT)

#ifndef ZEND_TSRMLS_CACHE_DEFINE
#define ZEND_TSRMLS_CACHE_DEFINE()
#endif

#ifndef ZEND_TSRMLS_CACHE_UPDATE
#define ZEND_TSRMLS_CACHE_UPDATE()
#endif

static void php_extname_init_globals(zend_couchbase_globals *couchbase_globals)
{
#if defined(COMPILE_DL_COUCHBASE) && defined(ZTS)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif

    couchbase_globals->enc_format = "json";
    couchbase_globals->enc_format_i = COUCHBASE_SERTYPE_JSON;
    couchbase_globals->enc_cmpr = "off";
    couchbase_globals->enc_cmpr_i = COUCHBASE_CMPRTYPE_NONE;
    couchbase_globals->enc_cmpr_threshold = 0;
    couchbase_globals->enc_cmpr_factor = 0.0;
    couchbase_globals->dec_json_array = 0;
    couchbase_globals->pool_max_idle_time = 60;
    couchbase_globals->allow_fallback_to_bucket = 0;
}

PHP_MINIT_FUNCTION(Result);
PHP_MINIT_FUNCTION(CouchbasePool);
PHP_MINIT_FUNCTION(CouchbaseException);
PHP_MINIT_FUNCTION(Collection);
PHP_MINIT_FUNCTION(Cluster);
PHP_MINIT_FUNCTION(BucketManager);
PHP_MINIT_FUNCTION(UserManager);
PHP_MINIT_FUNCTION(CollectionManager);
PHP_MINIT_FUNCTION(UserSettings);
PHP_MINIT_FUNCTION(Bucket);
PHP_MINIT_FUNCTION(QueryIndexManager);
PHP_MINIT_FUNCTION(Authenticator);
PHP_MINIT_FUNCTION(CertAuthenticator);
PHP_MINIT_FUNCTION(PasswordAuthenticator);
PHP_MINIT_FUNCTION(MutationState);
PHP_MINIT_FUNCTION(AnalyticsQuery);
PHP_MINIT_FUNCTION(LookupInSpec);
PHP_MINIT_FUNCTION(MutateInSpec);
PHP_MINIT_FUNCTION(SearchOptions);
PHP_MINIT_FUNCTION(SearchQuery);
PHP_MINIT_FUNCTION(BooleanFieldSearchQuery);
PHP_MINIT_FUNCTION(BooleanSearchQuery);
PHP_MINIT_FUNCTION(ConjunctionSearchQuery);
PHP_MINIT_FUNCTION(DateRangeSearchQuery);
PHP_MINIT_FUNCTION(DisjunctionSearchQuery);
PHP_MINIT_FUNCTION(DocIdSearchQuery);
PHP_MINIT_FUNCTION(GeoBoundingBoxSearchQuery);
PHP_MINIT_FUNCTION(GeoDistanceSearchQuery);
PHP_MINIT_FUNCTION(GeoPolygonSearchQuery);
PHP_MINIT_FUNCTION(MatchAllSearchQuery);
PHP_MINIT_FUNCTION(MatchNoneSearchQuery);
PHP_MINIT_FUNCTION(MatchPhraseSearchQuery);
PHP_MINIT_FUNCTION(MatchSearchQuery);
PHP_MINIT_FUNCTION(NumericRangeSearchQuery);
PHP_MINIT_FUNCTION(PhraseSearchQuery);
PHP_MINIT_FUNCTION(PrefixSearchQuery);
PHP_MINIT_FUNCTION(QueryStringSearchQuery);
PHP_MINIT_FUNCTION(RegexpSearchQuery);
PHP_MINIT_FUNCTION(TermSearchQuery);
PHP_MINIT_FUNCTION(TermRangeSearchQuery);
PHP_MINIT_FUNCTION(WildcardSearchQuery);
PHP_MINIT_FUNCTION(SearchFacet);
PHP_MINIT_FUNCTION(TermSearchFacet);
PHP_MINIT_FUNCTION(DateRangeSearchFacet);
PHP_MINIT_FUNCTION(NumericRangeSearchFacet);
PHP_MINIT_FUNCTION(SearchSort);
PHP_MINIT_FUNCTION(SearchSortField);
PHP_MINIT_FUNCTION(SearchSortGeoDistance);
PHP_MINIT_FUNCTION(SearchSortId);
PHP_MINIT_FUNCTION(SearchSortScore);
PHP_MINIT_FUNCTION(CryptoProvider);
PHP_MINIT_FUNCTION(SearchIndexManager);
PHP_MINIT_FUNCTION(CollectionGet);
PHP_MINIT_FUNCTION(CollectionGetReplica);
PHP_MINIT_FUNCTION(CollectionExists);
PHP_MINIT_FUNCTION(CollectionUnlock);
PHP_MINIT_FUNCTION(CollectionStore);
PHP_MINIT_FUNCTION(CollectionTouch);
PHP_MINIT_FUNCTION(CollectionCounter);
PHP_MINIT_FUNCTION(CollectionRemove);
PHP_MINIT_FUNCTION(CollectionSubdoc);
PHP_MINIT_FUNCTION(BucketView);
PHP_MINIT_FUNCTION(N1qlQuery);
PHP_MINIT_FUNCTION(ViewIndexManager);
PHP_MINIT_FUNCTION(ClusterOptions);

PHP_MINIT_FUNCTION(couchbase)
{
    ZEND_INIT_MODULE_GLOBALS(couchbase, php_extname_init_globals, NULL);
    REGISTER_INI_ENTRIES();

    pcbc_json_serializable_ce = NULL;
    {
        pcbc_json_serializable_ce = zend_hash_str_find_ptr(CG(class_table), ZEND_STRL("jsonserializable"));
        if (pcbc_json_serializable_ce == NULL) {
            pcbc_log(LOGARGS(FATAL),
                     "failed to find JsonSerializable class. Make sure 'json' module is loaded before 'couchbase'");
            return FAILURE;
        }
    }
    PHP_MINIT(Result)(INIT_FUNC_ARGS_PASSTHRU);

    PHP_MINIT(CouchbasePool)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(CouchbaseException)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(Cluster)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(Collection)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(BucketManager)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(UserManager)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(Bucket)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(CollectionManager)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(QueryIndexManager)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(Authenticator)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(CertAuthenticator)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(PasswordAuthenticator)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(MutationState)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(AnalyticsQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(LookupInSpec)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(MutateInSpec)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(SearchOptions)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(SearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(BooleanFieldSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(BooleanSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(ConjunctionSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(DateRangeSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(DisjunctionSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(DocIdSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(GeoBoundingBoxSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(GeoDistanceSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(GeoPolygonSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(MatchAllSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(MatchNoneSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(MatchPhraseSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(MatchSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(NumericRangeSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(PhraseSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(PrefixSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(QueryStringSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(RegexpSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(TermSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(TermRangeSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(WildcardSearchQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(SearchFacet)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(TermSearchFacet)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(NumericRangeSearchFacet)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(DateRangeSearchFacet)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(SearchSort)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(SearchSortField)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(SearchSortGeoDistance)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(SearchSortId)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(SearchSortScore)(INIT_FUNC_ARGS_PASSTHRU);
    //  PHP_MINIT(CryptoProvider)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(SearchIndexManager)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(CollectionGet)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(CollectionGetReplica)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(CollectionExists)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(CollectionUnlock)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(CollectionStore)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(CollectionTouch)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(CollectionCounter)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(CollectionRemove)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(CollectionSubdoc)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(BucketView)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(N1qlQuery)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(ViewIndexManager)(INIT_FUNC_ARGS_PASSTHRU);
    PHP_MINIT(ClusterOptions)(INIT_FUNC_ARGS_PASSTHRU);

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

    PCBC_LONG_CONSTANT("VALUE_F_JSON", LCB_VALUE_F_JSON);

    PCBC_REGISTER_LCBCONST(N1XSPEC_T_DEFAULT);
    PCBC_REGISTER_LCBCONST(N1XSPEC_T_GSI);
    PCBC_REGISTER_LCBCONST(N1XSPEC_T_VIEW);

    {
        char buf[128];

#define PCBC_CONST_LENGTH(buf) (strlen(buf))
#define X(name, value, cls, f, s)                                                                                      \
    {                                                                                                                  \
        ap_php_snprintf(buf, sizeof(buf), "COUCHBASE_%s", #name + 4);                                                  \
        zend_register_long_constant(buf, PCBC_CONST_LENGTH(buf), value, CONST_CS | CONST_PERSISTENT,                   \
                                    module_number);                                                          \
    }

        LCB_XERROR(X)
#undef X
#undef PCBC_CONST_LENGTH
    }

    // TODO: Maybe not have these?
    PCBC_LONG_CONSTANT("TMPFAIL", LCB_ERR_TEMPORARY_FAILURE);
    PCBC_LONG_CONSTANT("KEYALREADYEXISTS", LCB_ERR_DOCUMENT_EXISTS);
    PCBC_LONG_CONSTANT("KEYNOTFOUND", LCB_ERR_DOCUMENT_NOT_FOUND);

    PCBC_REGISTER_CONST_RAW(COUCHBASE_VAL_MASK);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_VAL_IS_STRING);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_VAL_IS_LONG);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_VAL_IS_DOUBLE);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_VAL_IS_BOOL);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_VAL_IS_SERIALIZED);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_VAL_IS_JSON);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_COMPRESSION_MASK);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_COMPRESSION_NONE);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_COMPRESSION_ZLIB);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_COMPRESSION_FASTLZ);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_COMPRESSION_MCISCOMPRESSED);

    PCBC_REGISTER_CONST_RAW(COUCHBASE_SERTYPE_JSON);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_SERTYPE_PHP);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_CMPRTYPE_NONE);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_CMPRTYPE_ZLIB);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_CMPRTYPE_FASTLZ);

    PCBC_REGISTER_CONST_RAW(COUCHBASE_CFFMT_MASK);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_CFFMT_PRIVATE);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_CFFMT_JSON);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_CFFMT_RAW);
    PCBC_REGISTER_CONST_RAW(COUCHBASE_CFFMT_STRING);

    REGISTER_NS_LONG_CONSTANT("Couchbase", "ENCODER_FORMAT_JSON", COUCHBASE_SERTYPE_JSON, CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Couchbase", "ENCODER_FORMAT_PHP", COUCHBASE_SERTYPE_PHP, CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Couchbase", "ENCODER_COMPRESSION_NONE", COUCHBASE_CMPRTYPE_NONE,
                              CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Couchbase", "ENCODER_COMPRESSION_ZLIB", COUCHBASE_CMPRTYPE_ZLIB,
                              CONST_CS | CONST_PERSISTENT);
    REGISTER_NS_LONG_CONSTANT("Couchbase", "ENCODER_COMPRESSION_FASTLZ", COUCHBASE_CMPRTYPE_FASTLZ,
                              CONST_CS | CONST_PERSISTENT);

    REGISTER_NS_LONG_CONSTANT("Couchbase", "HAVE_IGBINARY", 0, CONST_CS | CONST_PERSISTENT);

#ifdef HAVE_COUCHBASE_ZLIB
    REGISTER_NS_LONG_CONSTANT("Couchbase", "HAVE_ZLIB", 1, CONST_CS | CONST_PERSISTENT);
#else
    REGISTER_NS_LONG_CONSTANT("Couchbase", "HAVE_ZLIB", 0, CONST_CS | CONST_PERSISTENT);
#endif
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(couchbase)
{
    UNREGISTER_INI_ENTRIES();

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(couchbase)
{
    pcbc_connection_cleanup();
    return SUCCESS;
}

PHP_RINIT_FUNCTION(couchbase)
{
    return SUCCESS;
}

static void basic_encoder_v1(zval *value, int sertype, int cmprtype, long cmprthresh, double cmprfactor,
                             zval *return_value)
{
    zval res;
    zval flg;
    zval dtype;
    unsigned int flags = 0;

    ZVAL_UNDEF(&res);

    switch (Z_TYPE_P(value)) {
    case IS_STRING:
        flags = COUCHBASE_VAL_IS_STRING | COUCHBASE_CFFMT_STRING;
        PCBC_STRINGL(res, PCBC_STRVAL_ZP(value), PCBC_STRLEN_ZP(value));
        break;
    case IS_LONG:
        flags = COUCHBASE_VAL_IS_LONG | COUCHBASE_CFFMT_JSON;
        {
            zval strval;
            int use_copy;
            pcbc_make_printable_zval(value, &strval, &use_copy);
            if (use_copy) {
                PCBC_STRINGL(res, Z_STRVAL(strval), Z_STRLEN(strval));
                zval_dtor(&strval);
            } else {
                pcbc_log(LOGARGS(ERROR), "Expected long number to allocate new value during string conversion");
            }
        }
        break;
    case IS_DOUBLE:
        flags = COUCHBASE_VAL_IS_DOUBLE | COUCHBASE_CFFMT_JSON;
        {
            zval strval;
            int use_copy;
            pcbc_make_printable_zval(value, &strval, &use_copy);
            if (use_copy) {
                PCBC_STRINGL(res, Z_STRVAL(strval), Z_STRLEN(strval));
                zval_dtor(&strval);
            } else {
                pcbc_log(LOGARGS(ERROR), "Expected double number to allocate new value during string conversion");
            }
        }
        break;
    case IS_TRUE:
        flags = COUCHBASE_VAL_IS_BOOL | COUCHBASE_CFFMT_JSON;
        PCBC_STRING(res, "true");
        break;
    case IS_FALSE:
        flags = COUCHBASE_VAL_IS_BOOL | COUCHBASE_CFFMT_JSON;
        PCBC_STRING(res, "false");
        break;
    default:
        switch (sertype) {
        case COUCHBASE_SERTYPE_JSON:
            flags = COUCHBASE_VAL_IS_JSON | COUCHBASE_CFFMT_JSON;
            {
                smart_str buf = {0};
                int last_error;

                PCBC_JSON_ENCODE(&buf, value, 0, last_error);
                if (last_error != 0) {
                    pcbc_log(LOGARGS(WARN), "Failed to encode value as JSON: json_last_error=%d", last_error);
                    ZVAL_NULL(&res);
                } else {
                    smart_str_0(&buf);
                    PCBC_STRINGS(res, buf);
                }
                smart_str_free(&buf);
            }
            break;
        case COUCHBASE_SERTYPE_PHP:
            flags = COUCHBASE_VAL_IS_SERIALIZED | COUCHBASE_CFFMT_PRIVATE;
            {
                php_serialize_data_t var_hash;
                smart_str buf = {0};

                PHP_VAR_SERIALIZE_INIT(var_hash);
                php_var_serialize(&buf, value, &var_hash);
                PHP_VAR_SERIALIZE_DESTROY(var_hash);

                if (EG(exception)) {
                    pcbc_log(LOGARGS(WARN), "Failed to serialize value");
                } else {
                    PCBC_STRINGS(res, buf);
                }
                smart_str_free(&buf);
            }
            break;
        }
    }

    do {
        size_t datalen = 0;
        if (Z_TYPE_P(&res) == IS_NULL) {
            break;
        }
        datalen = PCBC_STRLEN_P(res);
        if (datalen < cmprthresh) {
            cmprtype = COUCHBASE_CMPRTYPE_NONE;
        }
        if (cmprtype != COUCHBASE_CMPRTYPE_NONE) {
            int cmprflags = COUCHBASE_COMPRESSION_NONE;
            zval compressed;
            if (cmprtype == COUCHBASE_CMPRTYPE_ZLIB) {
#if HAVE_COUCHBASE_ZLIB
                void *input, *output;
                unsigned long input_size, output_size;
                int rv;

                input_size = datalen;
                input = PCBC_STRVAL_P(res);
                /* 4 bytes for original size in preamble and 1 byte for zero terminator */
                output_size = 4 + compressBound(input_size) + 1;
                output = emalloc(output_size);

                rv = compress((uint8_t *)output + 4, &output_size, input, input_size);
                if (rv != Z_OK) {
                    efree(output);
                    pcbc_log(LOGARGS(WARN), "Failed to compress data with zlib. rv=%d", rv);
                    break;
                }
                *((uint32_t *)output) = input_size;
                output_size += 4;
                *((uint8_t *)output + output_size) = '\0';
                cmprflags = COUCHBASE_COMPRESSION_ZLIB;
                ZVAL_UNDEF(&compressed);
                PCBC_STRINGL(compressed, output, output_size);
                efree(output);
#else
                pcbc_log(LOGARGS(WARN), "The zlib library was not available when the couchbase extension was built.");
                break;
#endif
            } else if (cmprtype == COUCHBASE_CMPRTYPE_FASTLZ) {
                void *input, *output;
                unsigned long input_size, output_size;

                input_size = (unsigned long)datalen;
                input = PCBC_STRVAL_P(res);
                /* The output buffer must be at least 5% larger than the input buffer and can not be smaller than 66
                 * bytes. */
                output_size = input_size + input_size / 20;
                /* 4 bytes for original size in preamble and 1 byte for zero terminator */
                output_size = 4 + (output_size > 66 ? output_size : 66) + 1;
                output = emalloc(output_size);
                output_size = fastlz_compress(input, input_size, (uint8_t *)output + 4);
                *(uint32_t *)output = input_size;
                output_size += 4;
                *((uint8_t *)output + output_size) = '\0';
                cmprflags = COUCHBASE_COMPRESSION_FASTLZ;
                ZVAL_UNDEF(&compressed);
                PCBC_STRINGL(compressed, output, output_size);
                efree(output);
            } else {
                pcbc_log(LOGARGS(WARN), "Unsupported compression method: %d", cmprtype);
                break;
            }
            if (cmprflags != COUCHBASE_COMPRESSION_NONE) {
                if (PCBC_STRLEN_P(res) > PCBC_STRLEN_P(compressed) * cmprfactor) {
                    zval_dtor(&res);
                    res = compressed;

                    flags |= cmprflags;
                    flags |= COUCHBASE_COMPRESSION_MCISCOMPRESSED;

                    /* compression considered private format */
                    flags &= ~((unsigned int)COUCHBASE_CFFMT_MASK);
                    flags |= COUCHBASE_CFFMT_PRIVATE;
                } else {
                    zval_dtor(&compressed);
                }
            }
        }
    } while (0);

    array_init_size(return_value, 3);
    add_index_zval(return_value, 0, &res);

    ZVAL_UNDEF(&flg);
    ZVAL_LONG(&flg, flags);
    add_index_zval(return_value, 1, &flg);

    ZVAL_UNDEF(&dtype);
    ZVAL_LONG(&dtype, 0);
    add_index_zval(return_value, 2, &dtype);
}

static void basic_decoder_v1(char *bytes, size_t bytes_len, unsigned long flags, unsigned long datatype,
                             zend_bool jsonassoc, zval *return_value)
{
    zval res;
    int rv;
    unsigned int cffmt = 0; /* common flags */
    unsigned int sertype = 0;
    unsigned int cmprtype = 0;
    int need_free = 0; /* free buffer after uncompression */

    cffmt = flags & COUCHBASE_CFFMT_MASK;
    sertype = flags & COUCHBASE_VAL_MASK;
    cmprtype = flags & COUCHBASE_COMPRESSION_MASK;

    ZVAL_UNDEF(&res);

#define DECODE_JSON                                                                                                    \
    do {                                                                                                               \
        int last_error;                                                                                                \
        int options = 0;                                                                                               \
                                                                                                                       \
        if (jsonassoc) {                                                                                               \
            options |= PHP_JSON_OBJECT_AS_ARRAY;                                                                       \
        }                                                                                                              \
        PCBC_JSON_COPY_DECODE(&res, bytes, bytes_len, options, last_error);                                            \
        if (last_error != 0) {                                                                                         \
            pcbc_log(LOGARGS(WARN), "Failed to decode value as JSON: json_last_error=%d", last_error);                 \
            ZVAL_NULL(&res);                                                                                           \
        }                                                                                                              \
    } while (0)

    switch (cffmt) {
    case COUCHBASE_CFFMT_PRIVATE:
    case COUCHBASE_CFFMT_EMPTY:
        if (sertype & COUCHBASE_COMPRESSION_MCISCOMPRESSED) {
            sertype &= ~((unsigned int)COUCHBASE_COMPRESSION_MCISCOMPRESSED);
            if (cmprtype == COUCHBASE_COMPRESSION_ZLIB) {
#if HAVE_COUCHBASE_ZLIB
                unsigned long output_size = *(uint32_t *)bytes;
                char *output = emalloc(output_size);
                rv = uncompress((uint8_t *)output, &output_size, (uint8_t *)bytes + 4, bytes_len - 4);
                if (rv != Z_OK) {
                    efree(output);
                    pcbc_log(LOGARGS(WARN), "Failed to uncompress data with zlib. rv=%d", rv);
                    break;
                }
                need_free = 1;
                bytes = output;
                bytes_len = output_size;
#else
                pcbc_log(LOGARGS(WARN), "The zlib library was not available when the couchbase extension was built.");
                break;
#endif
            } else if (cmprtype == COUCHBASE_COMPRESSION_FASTLZ) {
                unsigned long output_size = *(uint32_t *)bytes;
                char *output = emalloc(output_size);
                output_size = fastlz_decompress((uint8_t *)bytes + 4, (int)bytes_len - 4, output, (int)output_size);
                if (output_size == 0) {
                    efree(output);
                    pcbc_log(LOGARGS(WARN), "Failed to uncompress data with fastlz");
                    break;
                }
                need_free = 1;
                bytes = output;
                bytes_len = output_size;
            } else if (cmprtype != 0) {
                pcbc_log(LOGARGS(WARN), "Unsupported compression method: %d", cmprtype);
                RETURN_NULL();
            }
        }
        switch (sertype) {
        case COUCHBASE_VAL_IS_STRING:
            if (flags == 0) {
                /* try to deserialize string as JSON with fallback to bytestring */
                int options = 0;
                int last_error;

                if (jsonassoc) {
                    options |= PHP_JSON_OBJECT_AS_ARRAY;
                }
                PCBC_JSON_COPY_DECODE(&res, bytes, bytes_len, options, last_error);
                if (last_error == 0) {
                    break;
                }
            }
            PCBC_STRINGL(res, bytes, bytes_len);
            break;
        case COUCHBASE_VAL_IS_LONG:
            ZVAL_LONG(&res, strtol(bytes, NULL, 10));
            break;
        case COUCHBASE_VAL_IS_DOUBLE:
            ZVAL_DOUBLE(&res, zend_strtod(bytes, NULL));
            break;
        case COUCHBASE_VAL_IS_BOOL:
            if (bytes_len == 0) {
                ZVAL_FALSE(&res);
            } else {
                ZVAL_TRUE(&res);
            }
            break;
        case COUCHBASE_VAL_IS_JSON:
            DECODE_JSON;
            break;
        case COUCHBASE_VAL_IS_SERIALIZED: {
            php_unserialize_data_t var_hash;
            const unsigned char *p = (const unsigned char *)bytes;
            PHP_VAR_UNSERIALIZE_INIT(var_hash);
            rv = php_var_unserialize(&res, &p, p + bytes_len, &var_hash);
            if (!rv) {
                if (!EG(exception)) {
                    pcbc_log(LOGARGS(WARN), "Failed to unserialize value at offset %ld of %d bytes",
                             (long)((char *)p - bytes), bytes_len);
                }
                ZVAL_NULL(&res);
            }
            PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
        } break;
        case COUCHBASE_VAL_IS_IGBINARY:
            pcbc_log(LOGARGS(WARN), "The igbinary serialization is not supported.");
            RETURN_NULL();
        default:
            pcbc_log(LOGARGS(WARN), "Unknown serialization type: %d", cffmt);
            ZVAL_NULL(&res);
        }
        break;
    case COUCHBASE_CFFMT_JSON:
        DECODE_JSON;
        break;
    case COUCHBASE_CFFMT_STRING:
    case COUCHBASE_CFFMT_RAW:
        PCBC_STRINGL(res, bytes, bytes_len);
        break;
    default:
        pcbc_log(LOGARGS(WARN), "Unknown format specification: %d", cffmt);
        ZVAL_NULL(&res);
    }
#undef DECODE_JSON
    if (need_free) {
        efree(bytes);
    }

    RETURN_ZVAL(&res, 1, 1);
}

/* {{{ proto \Couchbase\couchbase_basic_encoder_v1(string $value, array $options = [
                                                                    "sertype" => COUCHBASE_SERTYPE_JSON,
                                                                    "cmprtype" => COUCHBASE_CMPRTYPE_NONE,
                                                                    "cmprthresh" => 0,
                                                                    "cmprfactor" => 0])
   Performs encoding of the user provided types into binary form for server */
PHP_FUNCTION(basicEncoderV1)
{
    zval *value = NULL;
    zval *options = NULL;
    int rv;
    int sertype = DEFAULT_COUCHBASE_SERTYPE;
    int cmprtype = DEFAULT_COUCHBASE_CMPRTYPE;
    long cmprthresh = DEFAULT_COUCHBASE_CMPRTHRESH;
    double cmprfactor = DEFAULT_COUCHBASE_CMPRFACTOR;

    rv = zend_parse_parameters(ZEND_NUM_ARGS(), "z|a", &value, &options);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    sertype = PCBCG(enc_format_i);
    cmprtype = PCBCG(enc_cmpr_i);
    cmprthresh = PCBCG(enc_cmpr_threshold);
    cmprfactor = PCBCG(enc_cmpr_factor);
    if (options != NULL) {
        HashTable *marr = Z_ARRVAL_P(options);
        zval *tmp;
        tmp = zend_symtable_str_find(marr, ZEND_STRL("sertype"));
        if (tmp && Z_TYPE_P(tmp) == IS_LONG) {
            if (Z_LVAL_P(tmp) <= COUCHBASE_SERTYPE_PHP && Z_LVAL_P(tmp) >= COUCHBASE_SERTYPE_JSON) {
                sertype = Z_LVAL_P(tmp);
            }
        }
        tmp = zend_symtable_str_find(marr, ZEND_STRL("cmprtype"));
        if (tmp && Z_TYPE_P(tmp) == IS_LONG) {
            if (Z_LVAL_P(tmp) <= COUCHBASE_CMPRTYPE_NONE && Z_LVAL_P(tmp) >= COUCHBASE_CMPRTYPE_FASTLZ) {
                cmprtype = Z_LVAL_P(tmp);
            }
        }
        tmp = zend_symtable_str_find(marr, ZEND_STRL("cmprthresh"));
        if (tmp && Z_TYPE_P(tmp) == IS_LONG) {
            cmprthresh = Z_LVAL_P(tmp);
        }
        tmp = zend_symtable_str_find(marr, ZEND_STRL("cmprthresh"));
        if (tmp && Z_TYPE_P(tmp) == IS_DOUBLE) {
            cmprfactor = Z_DVAL_P(tmp);
        }
    }

    basic_encoder_v1(value, sertype, cmprtype, cmprthresh, cmprfactor, return_value);
}

/* {{{ proto \Couchbase\couchbase_basic_decoder_v1(string $bytes, int $flags, int $datatype, array $options =
   ["jsonassoc" => false])
   Performs decoding of the server provided binary data into PHP types according to the original PHP SDK specification
   */
PHP_FUNCTION(basicDecoderV1)
{
    char *bytes = NULL;
    size_t bytes_len = -1;
    unsigned long flags = 0, datatype = 0;
    zval *options = NULL;
    zend_bool json_array = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS(), "sll|a", &bytes, &bytes_len, &flags, &datatype, &options);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    json_array = PCBCG(dec_json_array);
    if (options) {
        HashTable *marr = Z_ARRVAL_P(options);
        zval *tmp;
        tmp = zend_symtable_str_find(marr, ZEND_STRL("jsonassoc"));
        json_array = tmp && Z_TYPE_P(tmp) == IS_TRUE;
    }

    basic_decoder_v1(bytes, (int)bytes_len, flags, datatype, json_array, return_value);
}

PHP_FUNCTION(passthruEncoder)
{
    zval *value;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &value) == FAILURE) {
        RETURN_NULL();
    }

    array_init_size(return_value, 3);
    add_index_zval(return_value, 0, value);
    PCBC_ADDREF_P(value);
    add_index_long(return_value, 1, 0);
    add_index_long(return_value, 2, 0);
}

PHP_FUNCTION(passthruDecoder)
{
    zval *value, *flags, *datatype;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "zzz", &value, &flags, &datatype) == FAILURE) {
        RETURN_NULL();
    }

    RETURN_ZVAL(value, 1, 0);
}

/**
 * The default encoder for the client.  Currently invokes the
 * v1 encoder directly with the default set of encoding options.
 *
 * @internal
 */
PHP_FUNCTION(defaultEncoder)
{
    zval *value = NULL;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS(), "z|a", &value);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    basic_encoder_v1(value, PCBCG(enc_format_i), PCBCG(enc_cmpr_i), PCBCG(enc_cmpr_threshold), PCBCG(enc_cmpr_factor),
                     return_value);
}

/**
 * The default decoder for the client.  Currently invokes the
 * v1 decoder directly.
 *
 * @internal
 */
PHP_FUNCTION(defaultDecoder)
{
    char *bytes = NULL;
    size_t bytes_len = -1;
    unsigned long flags = 0, datatype = 0;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS(), "sll|a", &bytes, &bytes_len, &flags, &datatype);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    basic_decoder_v1(bytes, (int)bytes_len, flags, datatype, PCBCG(dec_json_array), return_value);
}

PHP_FUNCTION(zlibCompress)
{
#if HAVE_COUCHBASE_ZLIB
    zval *zdata;
    void *dataIn, *dataOut;
    unsigned long dataSize, dataOutSize;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zdata) == FAILURE) {
        RETURN_NULL();
    }

    dataIn = PCBC_STRVAL_ZP(zdata);
    dataSize = PCBC_STRLEN_ZP(zdata);
    dataOutSize = compressBound(dataSize);
    dataOut = emalloc(dataOutSize);
    compress((uint8_t *)dataOut + 4, &dataOutSize, dataIn, dataSize);
    *(uint32_t *)dataOut = dataSize;

    ZVAL_STRINGL(return_value, dataOut, 4 + dataOutSize);
    efree(dataOut);
#else
    zend_throw_exception(NULL, "The zlib library was not available when the couchbase extension was built.",
                         0);
#endif
}

PHP_FUNCTION(zlibDecompress)
{
#if HAVE_COUCHBASE_ZLIB
    zval *zdata;
    void *dataIn, *dataOut;
    unsigned long dataSize, dataOutSize;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zdata) == FAILURE) {
        RETURN_NULL();
    }

    dataIn = PCBC_STRVAL_ZP(zdata);
    dataSize = PCBC_STRLEN_ZP(zdata);
    dataOutSize = *(uint32_t *)dataIn;
    dataOut = emalloc(dataOutSize);
    uncompress(dataOut, &dataOutSize, (uint8_t *)dataIn + 4, dataSize - 4);

    ZVAL_STRINGL(return_value, dataOut, dataOutSize);
    efree(dataOut);
#else
    zend_throw_exception(NULL, "The zlib library was not available when the couchbase extension was built.",
                         0);
#endif
}

PHP_FUNCTION(fastlzCompress)
{
    zval *zdata;
    void *dataIn, *dataOut;
    unsigned long dataSize, dataOutSize;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zdata) == FAILURE) {
        RETURN_NULL();
    }

    dataIn = PCBC_STRVAL_ZP(zdata);
    dataSize = (unsigned long)PCBC_STRLEN_ZP(zdata);
    dataOutSize = 4 + (dataSize + dataSize / 20);
    dataOut = emalloc(dataOutSize);
    dataOutSize = fastlz_compress(dataIn, dataSize, (uint8_t *)dataOut + 4);
    *(uint32_t *)dataOut = dataSize;

    ZVAL_STRINGL(return_value, dataOut, 4 + dataOutSize);

    efree(dataOut);
}

PHP_FUNCTION(fastlzDecompress)
{
    zval *zdata;
    void *dataIn, *dataOut;
    unsigned long dataSize, dataOutSize;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &zdata) == FAILURE) {
        RETURN_NULL();
    }

    dataIn = PCBC_STRVAL_ZP(zdata);
    dataSize = (unsigned long)PCBC_STRLEN_ZP(zdata);
    dataOutSize = *(uint32_t *)dataIn;
    dataOut = emalloc(dataOutSize);
    dataOutSize = fastlz_decompress((uint8_t *)dataIn + 4, dataSize - 4, dataOut, dataOutSize);

    ZVAL_STRINGL(return_value, dataOut, dataOutSize);

    efree(dataOut);
}

static PHP_MINFO_FUNCTION(couchbase)
{
    char buf[128];
    const char *changeset;
    lcb_STATUS err;

    err = lcb_cntl(NULL, LCB_CNTL_GET, LCB_CNTL_CHANGESET, (void *)&changeset);
    if (err != LCB_SUCCESS) {
        changeset = "UNKNOWN";
    }
    ap_php_snprintf(buf, sizeof(buf), "%s (git: %s)", lcb_get_version(NULL), changeset);

    php_info_print_table_start();
    php_info_print_table_row(2, "couchbase support", "enabled");
    php_info_print_table_row(2, "extension version", PHP_COUCHBASE_VERSION);
    php_info_print_table_row(2, "libcouchbase runtime version", buf);
    php_info_print_table_row(2, "libcouchbase headers version", LCB_VERSION_STRING " (git: " LCB_VERSION_CHANGESET ")");
#ifdef HAVE_COUCHBASE_ZLIB
    php_info_print_table_row(2, "zlib compressor", "enabled");
#else
    php_info_print_table_row(2, "zlib compressor", "disabled (install zlib headers and rebuild pecl/couchbase)");
#endif
    php_info_print_table_end();
    DISPLAY_INI_ENTRIES();
}

ZEND_BEGIN_ARG_INFO_EX(ai_Couchbase_compress, 0, 0, 1)
ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_Couchbase_decompress, 0, 0, 1)
ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_Couchbase_passthruEncoder, 0, 0, 1)
ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_Couchbase_passthruDecoder, 0, 0, 3)
ZEND_ARG_INFO(0, bytes)
ZEND_ARG_INFO(0, flags)
ZEND_ARG_INFO(0, datatype)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_Couchbase_basicEncoder, 0, 0, 2)
ZEND_ARG_INFO(0, value)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(ai_Couchbase_basicDecoder, 0, 0, 4)
ZEND_ARG_INFO(0, bytes)
ZEND_ARG_INFO(0, flags)
ZEND_ARG_INFO(0, datatype)
ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO();

// clang-format off
static zend_function_entry couchbase_functions[] = {
    ZEND_NS_FE("Couchbase", fastlzCompress, ai_Couchbase_compress)
    ZEND_NS_FE("Couchbase", fastlzDecompress, ai_Couchbase_decompress)
    ZEND_NS_FE("Couchbase", zlibCompress, ai_Couchbase_compress)
    ZEND_NS_FE("Couchbase", zlibDecompress, ai_Couchbase_decompress)
    ZEND_NS_FE("Couchbase", passthruEncoder, ai_Couchbase_passthruEncoder)
    ZEND_NS_FE("Couchbase", passthruDecoder, ai_Couchbase_passthruDecoder)
    ZEND_NS_FE("Couchbase", defaultEncoder, ai_Couchbase_passthruEncoder)
    ZEND_NS_FE("Couchbase", defaultDecoder, ai_Couchbase_passthruDecoder)
    ZEND_NS_FE("Couchbase", basicEncoderV1, ai_Couchbase_basicEncoder)
    ZEND_NS_FE("Couchbase", basicDecoderV1, ai_Couchbase_basicDecoder)

    PHP_FALIAS(couchbase_fastlz_compress, fastlzCompress, ai_Couchbase_compress)
    PHP_FALIAS(couchbase_fastlz_decompress, fastlzDecompress, ai_Couchbase_decompress)
    PHP_FALIAS(couchbase_zlib_compress, zlibCompress, ai_Couchbase_compress)
    PHP_FALIAS(couchbase_zlib_decompress, zlibDecompress, ai_Couchbase_decompress)
    PHP_FALIAS(couchbase_passthru_encoder, passthruEncoder, ai_Couchbase_passthruEncoder)
    PHP_FALIAS(couchbase_passthru_decoder, passthruDecoder, ai_Couchbase_passthruDecoder)
    PHP_FALIAS(couchbase_default_encoder, defaultEncoder, ai_Couchbase_passthruEncoder)
    PHP_FALIAS(couchbase_default_decoder, defaultDecoder, ai_Couchbase_passthruDecoder)
    PHP_FALIAS(couchbase_basic_encoder_v1, basicEncoderV1, ai_Couchbase_basicEncoder)
    PHP_FALIAS(couchbase_basic_decoder_v1, basicDecoderV1, ai_Couchbase_basicDecoder)

    PHP_FE_END
};

#if ZEND_MODULE_API_NO >= 20050617
static zend_module_dep php_couchbase_deps[] = {
    ZEND_MOD_REQUIRED("json")
    ZEND_MOD_END
};
#endif

zend_module_entry couchbase_module_entry = {
#if ZEND_MODULE_API_NO >= 20050617
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
    PHP_MINFO(couchbase),
#if ZEND_MODULE_API_NO >= 20010901
    PHP_COUCHBASE_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};
// clang-format on

#ifdef COMPILE_DL_COUCHBASE
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
#endif
ZEND_GET_MODULE(couchbase)
#endif
