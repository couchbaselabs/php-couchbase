/**
 *     Copyright 2016-2017 Couchbase, Inc.
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
#include <Zend/zend_alloc.h>

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/mutation_state", __FILE__, __LINE__

zend_class_entry *pcbc_mutation_state_ce;

/* {{{ proto void MutationState::__construct() Should not be called directly */
PHP_METHOD(MutationState, __construct)
{
    throw_pcbc_exception("Accessing private constructor.", LCB_EINVAL);
}
/* }}} */

static void pcbc_add_token(pcbc_mutation_state_t *state, pcbc_mutation_token_t *token TSRMLS_DC)
{
    pcbc_mutation_token_t *new_token = NULL, *t;

    t = state->head;
    while (t) {
        if (PCBC_MUTATION_TOKEN_VB(t) == PCBC_MUTATION_TOKEN_VB(t) && strcmp(t->bucket, token->bucket) == 0) {
            if (PCBC_MUTATION_TOKEN_SEQ(t) < PCBC_MUTATION_TOKEN_SEQ(token)) {
                new_token = t;
            }
            if (PCBC_MUTATION_TOKEN_SEQ(t) == PCBC_MUTATION_TOKEN_SEQ(token) &&
                PCBC_MUTATION_TOKEN_ID(t) == PCBC_MUTATION_TOKEN_ID(token)) {
                return;
            }
        }
        t = t->next;
    }
    if (new_token == NULL) {
        new_token = ecalloc(1, sizeof(pcbc_mutation_token_t));
        new_token->next = NULL;
        new_token->bucket = estrdup(token->bucket);
        if (state->tail) {
            state->tail->next = new_token;
        }
        state->tail = new_token;
        if (state->head == NULL) {
            state->head = state->tail;
        }
        state->ntokens++;
    }
    PCBC_MUTATION_TOKEN_ID(new_token) = PCBC_MUTATION_TOKEN_ID(token);
    PCBC_MUTATION_TOKEN_SEQ(new_token) = PCBC_MUTATION_TOKEN_SEQ(token);
    PCBC_MUTATION_TOKEN_VB(new_token) = PCBC_MUTATION_TOKEN_VB(token);
}

#define ADD_TOKEN_FROM_ZVAL(source)                                                                                    \
    if (instanceof_function(Z_OBJCE_P(source), pcbc_mutation_token_ce TSRMLS_CC)) {                                    \
        pcbc_add_token(state, Z_MUTATION_TOKEN_OBJ_P(source) TSRMLS_CC);                                               \
    } else if (instanceof_function(Z_OBJCE_P(source), pcbc_document_ce TSRMLS_CC)) {                                   \
        zval *val;                                                                                                     \
        PCBC_READ_PROPERTY(val, pcbc_document_ce, source, "token", 0);                                                 \
        if (val && Z_TYPE_P(val) == IS_OBJECT &&                                                                       \
            instanceof_function(Z_OBJCE_P(val), pcbc_mutation_token_ce TSRMLS_CC)) {                                   \
            pcbc_add_token(state, Z_MUTATION_TOKEN_OBJ_P(val) TSRMLS_CC);                                              \
        }                                                                                                              \
    } else if (instanceof_function(Z_OBJCE_P(source), pcbc_document_fragment_ce TSRMLS_CC)) {                          \
        zval *val;                                                                                                     \
        PCBC_READ_PROPERTY(val, pcbc_document_fragment_ce, source, "token", 0);                                        \
        if (val && Z_TYPE_P(val) == IS_OBJECT &&                                                                       \
            instanceof_function(Z_OBJCE_P(val), pcbc_mutation_token_ce TSRMLS_CC)) {                                   \
            pcbc_add_token(state, Z_MUTATION_TOKEN_OBJ_P(val) TSRMLS_CC);                                              \
        }                                                                                                              \
    } else {                                                                                                           \
        throw_pcbc_exception("Object with mutation token expected (Document, DocumentFragment or MutationToken)",      \
                             LCB_EINVAL);                                                                              \
    }

/* {{{ proto \Couchbase\MutationState MutationState::from(array $source = []) */
PHP_METHOD(MutationState, from)
{
    zval *source = NULL;
    pcbc_mutation_state_t *state;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &source);
    if (rv == FAILURE) {
        RETURN_NULL();
    }

    pcbc_mutation_state_init(return_value, source TSRMLS_CC);
    state = Z_MUTATION_STATE_OBJ_P(return_value);

    switch (Z_TYPE_P(source)) {
    case IS_OBJECT:
        ADD_TOKEN_FROM_ZVAL(source);
        break;
    case IS_ARRAY: {
#if PHP_VERSION_ID >= 70000
        zval *entry;

        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(source), entry)
        {
            ADD_TOKEN_FROM_ZVAL(entry);
        }
        ZEND_HASH_FOREACH_END();
#else
        HashPosition pos;
        zval **entry;

        zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(source), &pos);
        while (zend_hash_get_current_data_ex(Z_ARRVAL_P(source), (void **)&entry, &pos) == SUCCESS) {
            ADD_TOKEN_FROM_ZVAL(*entry);
            zend_hash_move_forward_ex(Z_ARRVAL_P(source), &pos);
        }
#endif
    } break;
    default:
        throw_pcbc_exception(
            "Array or object with mutation state expected (Document, DocumentFragment or MutationToken)", LCB_EINVAL);
    }
} /* }}} */

/* {{{ proto \Couchbase\MutationState MutationState::add(array $source) */
PHP_METHOD(MutationState, add)
{
    pcbc_mutation_state_t *state;
    zval *source;
    int rv;

    rv = zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &source);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    state = Z_MUTATION_STATE_OBJ_P(getThis());

    switch (Z_TYPE_P(source)) {
    case IS_OBJECT:
        ADD_TOKEN_FROM_ZVAL(source);
        break;
    case IS_ARRAY: {
#if PHP_VERSION_ID >= 70000
        zval *entry;

        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(source), entry)
        {
            ADD_TOKEN_FROM_ZVAL(entry);
        }
        ZEND_HASH_FOREACH_END();
#else
        HashPosition pos;
        zval **entry;

        zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(source), &pos);
        while (zend_hash_get_current_data_ex(Z_ARRVAL_P(source), (void **)&entry, &pos) == SUCCESS) {
            ADD_TOKEN_FROM_ZVAL(*entry);
            zend_hash_move_forward_ex(Z_ARRVAL_P(source), &pos);
        }
#endif
    } break;
    default:
        throw_pcbc_exception(
            "Array or object with mutation state expected (Document, DocumentFragment or MutationToken)", LCB_EINVAL);
    }

    RETURN_ZVAL(getThis(), 1, 0);
} /* }}} */

#undef ADD_TOKEN_FROM_ZVAL

void pcbc_mutation_state_export_for_n1ql(pcbc_mutation_state_t *obj, zval *scan_vectors TSRMLS_DC)
{
    pcbc_mutation_token_t *token;
    array_init(scan_vectors);
    token = obj->head;
    while (token) {
        PCBC_ZVAL new_group;
        zval *bucket_group;
        bucket_group = php_array_fetch(scan_vectors, token->bucket);
        if (!bucket_group) {
            PCBC_ZVAL_ALLOC(new_group);
            array_init(PCBC_P(new_group));
#if PHP_VERSION_ID >= 70000
            add_assoc_zval_ex(scan_vectors, token->bucket, strlen(token->bucket), PCBC_P(new_group));
#else
            add_assoc_zval_ex(scan_vectors, token->bucket, strlen(token->bucket) + 1, PCBC_P(new_group));
#endif
            bucket_group = PCBC_P(new_group);
        }
        {
            PCBC_ZVAL pair;
            char buf[22] = {0};

            PCBC_ZVAL_ALLOC(pair);
            array_init_size(PCBC_P(pair), 2);
            add_next_index_long(PCBC_P(pair), PCBC_MUTATION_TOKEN_SEQ(token));
            snprintf(buf, 21, "%llu", (unsigned long long)PCBC_MUTATION_TOKEN_ID(token));
            ADD_NEXT_INDEX_STRING(PCBC_P(pair), buf);
            snprintf(buf, 21, "%d", (int)PCBC_MUTATION_TOKEN_VB(token));
#if PHP_VERSION_ID >= 70000
            zend_hash_str_update(Z_ARRVAL_P(bucket_group), buf, strlen(buf), PCBC_P(pair) TSRMLS_CC);
#else
            zend_hash_update(Z_ARRVAL_P(bucket_group), buf, strlen(buf) + 1, &pair, sizeof(pair), NULL);
#endif
        }
        token = token->next;
    }
}

void pcbc_mutation_state_export_for_search(pcbc_mutation_state_t *obj, zval *scan_vectors TSRMLS_DC)
{
    pcbc_mutation_token_t *token;
    array_init(scan_vectors);
    token = obj->head;
    while (token) {
        char *token_key = NULL;
        int token_key_len;

        token_key_len = spprintf(&token_key, 0, "%d/%llu", PCBC_MUTATION_TOKEN_VB(token),
                                 (unsigned long long)PCBC_MUTATION_TOKEN_ID(token));
        add_assoc_long_ex(scan_vectors, token_key, token_key_len + 1, PCBC_MUTATION_TOKEN_SEQ(token));
        efree(token_key);
        token = token->next;
    }
}

ZEND_BEGIN_ARG_INFO_EX(ai_MutationState_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_MutationState_fromString, 0, 0, 1)
ZEND_ARG_INFO(0, statement)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_MutationState_add, 0, 0, 1)
ZEND_ARG_INFO(0, source)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry mutation_state_methods[] = {
    PHP_ME(MutationState, __construct, ai_MutationState_none, ZEND_ACC_PRIVATE | ZEND_ACC_FINAL | ZEND_ACC_CTOR)
    PHP_ME(MutationState, from, ai_MutationState_add, ZEND_ACC_STATIC | ZEND_ACC_PUBLIC)
    PHP_ME(MutationState, add, ai_MutationState_add, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

zend_object_handlers pcbc_mutation_state_handlers;

void pcbc_mutation_state_init(zval *return_value, zval *source TSRMLS_DC)
{
    pcbc_mutation_state_t *state;

    object_init_ex(return_value, pcbc_mutation_state_ce);
    state = Z_MUTATION_STATE_OBJ_P(return_value);
    state->head = NULL;
    state->tail = NULL;
    state->ntokens = 0;
}

static void mutation_state_free_object(pcbc_free_object_arg *object TSRMLS_DC) /* {{{ */
{
    pcbc_mutation_state_t *obj = Z_MUTATION_STATE_OBJ(object);
    pcbc_mutation_token_t *token;

    token = obj->head;
    while (token) {
        pcbc_mutation_token_t *tmp = token;
        token = token->next;
        efree(tmp->bucket);
        efree(tmp);
    }
    obj->head = obj->tail = NULL;

    zend_object_std_dtor(&obj->std TSRMLS_CC);
#if PHP_VERSION_ID < 70000
    efree(obj);
#endif
} /* }}} */

static pcbc_create_object_retval mutation_state_create_object(zend_class_entry *class_type TSRMLS_DC)
{
    pcbc_mutation_state_t *obj = NULL;

    obj = PCBC_ALLOC_OBJECT_T(pcbc_mutation_state_t, class_type);

    zend_object_std_init(&obj->std, class_type TSRMLS_CC);
    object_properties_init(&obj->std, class_type);

#if PHP_VERSION_ID >= 70000
    obj->std.handlers = &pcbc_mutation_state_handlers;
    return &obj->std;
#else
    {
        zend_object_value ret;
        ret.handle = zend_objects_store_put(obj, (zend_objects_store_dtor_t)zend_objects_destroy_object,
                                            mutation_state_free_object, NULL TSRMLS_CC);
        ret.handlers = &pcbc_mutation_state_handlers;
        return ret;
    }
#endif
}

static HashTable *mutation_state_get_debug_info(zval *object, int *is_temp TSRMLS_DC) /* {{{ */
{
    pcbc_mutation_state_t *obj = NULL;
#if PHP_VERSION_ID >= 70000
    zval retval;
#else
    zval retval = zval_used_for_init;
#endif
    pcbc_mutation_token_t *token;

    *is_temp = 1;
    obj = Z_MUTATION_STATE_OBJ_P(object);

    array_init_size(&retval, obj->ntokens);
    token = obj->head;
    while (token) {
        PCBC_ZVAL t;
        char *num36;

        PCBC_ZVAL_ALLOC(t);
        array_init_size(PCBC_P(t), 4);

        ADD_ASSOC_STRING(PCBC_P(t), "bucket", token->bucket);
        ADD_ASSOC_LONG_EX(PCBC_P(t), "vbucketId", PCBC_MUTATION_TOKEN_VB(token));
        num36 = pcbc_base36_encode_str(PCBC_MUTATION_TOKEN_ID(token));
        ADD_ASSOC_STRING(PCBC_P(t), "vbucketUuid", num36);
        efree(num36);
        num36 = pcbc_base36_encode_str(PCBC_MUTATION_TOKEN_SEQ(token));
        ADD_ASSOC_STRING(PCBC_P(t), "sequenceNumber", num36);
        efree(num36);
        add_next_index_zval(&retval, PCBC_P(t));
        token = token->next;
    }
    return Z_ARRVAL(retval);
} /* }}} */

PHP_MINIT_FUNCTION(MutationState)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutationState", mutation_state_methods);
    pcbc_mutation_state_ce = zend_register_internal_class(&ce TSRMLS_CC);
    pcbc_mutation_state_ce->create_object = mutation_state_create_object;
    PCBC_CE_DISABLE_SERIALIZATION(pcbc_mutation_state_ce);

    memcpy(&pcbc_mutation_state_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    pcbc_mutation_state_handlers.get_debug_info = mutation_state_get_debug_info;
#if PHP_VERSION_ID >= 70000
    pcbc_mutation_state_handlers.free_obj = mutation_state_free_object;
    pcbc_mutation_state_handlers.offset = XtOffsetOf(pcbc_mutation_state_t, std);
#endif

    zend_register_class_alias("\\CouchbaseMutationState", pcbc_mutation_state_ce);
    return SUCCESS;
}
