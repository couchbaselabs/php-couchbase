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

#if PHP_VERSION_ID >= 70000
// int param_count, PCBC_ZVAL *args
#define PCBC_GET_PARAMETERS_ARRAY_EX(__pcbc_param_count, __pcbc_param_args)                                            \
    _zend_get_parameters_array_ex((__pcbc_param_count), (__pcbc_param_args)TSRMLS_CC)
#else
static zend_always_inline int pcbc_get_parameters_array_ex(int param_count, PCBC_ZVAL *args TSRMLS_DC)
{
    if (param_count <= 16) {
        int i;
        zval **_args[16];
        int retval = _zend_get_parameters_array_ex(param_count, _args TSRMLS_CC);
        for (i = 0; i < param_count; ++i) {
            args[i] = *_args[i];
        }
        return retval;
    } else {
        int i;
        zval ***_args = emalloc(param_count * sizeof(zval **));
        int retval = _zend_get_parameters_array_ex(param_count, _args TSRMLS_CC);
        for (i = 0; i < param_count; ++i) {
            args[i] = *_args[i];
        }
        efree(_args);
        return retval;
    }
}
#define PCBC_GET_PARAMETERS_ARRAY_EX(__pcbc_param_count, __pcbc_param_args)                                            \
    pcbc_get_parameters_array_ex((__pcbc_param_count), (__pcbc_param_args)TSRMLS_CC)
#endif

#if PHP_VERSION_ID >= 70000
#define PCBC_HASH_GET_CURRENT_DATA_EX(ht, pos) zend_hash_get_current_data_ex(ht, pos)
static zend_always_inline int pcbc_hash_str_get_current_key_ex(HashTable *ht, char **str, unsigned *len,
                                                               zend_ulong *num_index, HashPosition *pos)
{
    zend_string *zstr = NULL;
    int key_type = zend_hash_get_current_key_ex(ht, &zstr, num_index, pos);
    if (zstr != NULL) {
        *str = zstr->val;
        *len = zstr->len;
    } else {
        *str = NULL;
        *len = 0;
    }
    return key_type;
}
#else
static zend_always_inline PCBC_ZVAL *pcbc_hash_get_current_data_ex(HashTable *ht, HashPosition *pos)
{
    zval **result;
    if (zend_hash_get_current_data_ex(ht, (void **)&result, pos) != SUCCESS) {
        return NULL;
    }
    return result;
}
#define PCBC_HASH_GET_CURRENT_DATA_EX(ht, pos) pcbc_hash_get_current_data_ex(ht, pos)
static zend_always_inline int pcbc_hash_str_get_current_key_ex(HashTable *ht, char **str, unsigned *len,
                                                               zend_ulong *num_index, HashPosition *pos)
{
    unsigned len_out = 0;
    int key_type = zend_hash_get_current_key_ex(ht, str, &len_out, num_index, 0, pos);
    if (len != NULL) {
        *len = len_out - 1;
    }
    return key_type;
}
#endif

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/params", __FILE__, __LINE__

// assumes first parameter in the spec is the ids (`id|`).
int pcbc_pp_begin(int param_count TSRMLS_DC, pcbc_pp_state *state, const char *spec, ...)
{
    PCBC_ZVAL args[PCBC_PP_MAX_ARGS];
    char arg_name[16];
    const char *spec_iter = spec;
    char *arg_iter = arg_name;
    int arg_type = 0;
    int arg_num = 0;
    PCBC_ZVAL *znamed;
    int arg_unnamed;
    int ii;
    va_list vl;
    va_start(vl, spec);

    if (PCBC_GET_PARAMETERS_ARRAY_EX(param_count, args) != SUCCESS) {
        return FAILURE;
    }

    state->zids = args[0];
    state->cur_idx = 0;
    state->arg_req = 0;
    state->arg_opt = 0;
    state->arg_named = 0;

    do {
        if (*spec_iter == 0 || *spec_iter == ',' || *spec_iter == '|') {
            if (arg_iter != arg_name) {
                pcbc_pp_state_arg *arg = &state->args[arg_num];
                *arg_iter = 0;

                // First argument (id) is a special case...
                if (arg_num == 0) {
                    // First arguement (id) is a special case...
                    if (strcmp(arg_name, "id") != 0) {
                        pcbc_log(LOGARGS(ERROR), "First argument must be ID.");
                        return FAILURE;
                    }
                }

                memcpy(arg->name, arg_name, 16);

                arg->ptr = va_arg(vl, zval **);

                if (arg_num > 0 && arg_num < param_count && arg_type < 2) {
                    arg->val = args[arg_num];
                } else {
                    ZVAL_UNDEF(PCBC_P(arg->val));
                }

                if (arg_type == 0) {
                    state->arg_req++;
                } else if (arg_type == 1) {
                    state->arg_opt++;
                } else if (arg_type == 2) {
                    state->arg_named++;
                }

                arg_num++;
            }

            if (*spec_iter == '|') {
                if (arg_type < 2) {
                    arg_type++;
                }
            }
            if (*spec_iter == 0) {
                break;
            }
            arg_iter = arg_name;
        } else {
            *arg_iter++ = *spec_iter;
        }

        spec_iter++;
    } while (1);

    if (param_count < state->arg_req) {
        pcbc_log(LOGARGS(ERROR), "Less than required number of args.");
        return FAILURE;
    }

    arg_unnamed = state->arg_req + state->arg_opt;

    if (param_count > arg_unnamed) {
        znamed = &args[arg_unnamed];

        // Ensure that it is an options array!
        if (Z_TYPE_P(PCBC_P(*znamed)) != IS_ARRAY) {
            pcbc_log(LOGARGS(ERROR), "Options argument must be an associative array.\n");
            return FAILURE;
        }
    } else {
        znamed = NULL;
    }

    for (ii = 0; ii < state->arg_named; ++ii) {
        int aii = arg_unnamed + ii;
        pcbc_pp_state_arg *arg = &state->args[aii];

        if (znamed) {
            zval *zvalue = php_array_fetch(PCBC_P(*znamed), arg->name);

            if (zvalue) {
                arg->val = PCBC_D(zvalue);
            } else {
                ZVAL_UNDEF(PCBC_P(arg->val));
            }
        } else {
            ZVAL_UNDEF(PCBC_P(arg->val));
        }
    }

    switch (Z_TYPE_P(PCBC_P(state->zids))) {
    case IS_ARRAY:
        // If this is an array, make sure its internal pointer is the start.
        zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(PCBC_P(state->zids)), &state->hash_pos);
        break;
    case IS_STRING:
        // Nothing to configure for basic string
        break;
    default:
        // Definitely an error
        return FAILURE;
    }

    return SUCCESS;
}

int pcbc_pp_ismapped(pcbc_pp_state *state)
{
    return Z_TYPE_P(PCBC_P(state->zids)) != IS_STRING;
}

int pcbc_pp_keycount(pcbc_pp_state *state)
{
    switch (Z_TYPE_P(PCBC_P(state->zids))) {
    case IS_STRING:
        return 1;
    case IS_ARRAY:
        return php_array_count(PCBC_P(state->zids));
    }
    return 0;
}

int pcbc_pp_next(pcbc_pp_state *state)
{
    int ii;
    int arg_total = state->arg_req + state->arg_opt + state->arg_named;
    pcbc_pp_id *id_ptr = (pcbc_pp_id *)state->args[0].ptr;

    // Set everything to 'base' values
    for (ii = 1; ii < arg_total; ++ii) {
        if (Z_ISUNDEF(state->args[ii].val)) {
            *(state->args[ii].ptr) = NULL;
        } else {
            *(state->args[ii].ptr) = PCBC_P(state->args[ii].val);
        }
    }

    switch (Z_TYPE_P(PCBC_P(state->zids))) {
    case IS_ARRAY: {
        HashTable *hash = Z_ARRVAL_P(PCBC_P(state->zids));
        PCBC_ZVAL *data;
        zend_ulong keyidx, key_type;
        char *keystr;
        unsigned keystr_len;

        data = PCBC_HASH_GET_CURRENT_DATA_EX(hash, &state->hash_pos);
        if (data == 0) {
            return 0;
        }

        key_type = pcbc_hash_str_get_current_key_ex(hash, &keystr, &keystr_len, &keyidx, &state->hash_pos);

        if (key_type == HASH_KEY_IS_STRING) {
            id_ptr->str = keystr;
            id_ptr->len = keystr_len;

            if (Z_TYPE_P(PCBC_P(*data)) == IS_ARRAY) {
                zval *zvalue;

                for (ii = 1; ii < arg_total; ++ii) {
                    pcbc_pp_state_arg *arg = &state->args[ii];

                    zvalue = php_array_fetch(PCBC_P(*data), arg->name);
                    if (zvalue != NULL) {
                        *(arg->ptr) = zvalue;
                    }
                }
            }
        } else if (key_type == HASH_KEY_IS_LONG) {
            id_ptr->str = Z_STRVAL_P(PCBC_N(data));
            id_ptr->len = Z_STRLEN_P(PCBC_N(data));
        }

        zend_hash_move_forward_ex(hash, &state->hash_pos);
        return 1;
    }
    case IS_STRING:
        if (state->cur_idx > 0) {
            return 0;
        }
        id_ptr->str = Z_STRVAL_P(PCBC_P(state->zids));
        id_ptr->len = Z_STRLEN_P(PCBC_P(state->zids));
        state->cur_idx++;
        return 1;
    default:
        // Invalid type for state->zids
        return 0;
    }
}
