#ifndef PARAMPARSER_H_
#define PARAMPARSER_H_

#define PCBC_PP_MAX_ARGS 10

typedef struct {
    char name[16];
    zval **ptr;
    zval val;
} pcbc_pp_state_arg;

typedef struct {
    pcbc_pp_state_arg args[PCBC_PP_MAX_ARGS];
    int arg_req;
    int arg_opt;
    int arg_named;
    int cur_idx;
    zval zids;
    zval tmpzid;
    HashPosition hash_pos;
} pcbc_pp_state;

// assumes first parameter in the spec is the ids (`id|`).
int pcbc_pp_begin(int param_count TSRMLS_DC, pcbc_pp_state *state, const char *spec, ...) {
    zval args[PCBC_PP_MAX_ARGS];
    char arg_name[16];
    const char *spec_iter = spec;
    char *arg_iter = arg_name;
    int arg_type = 0;
    int arg_num = 0;
    zval *znamed;
    int arg_unnamed;
    int ii;
    va_list vl;
    va_start(vl,spec);

    if (_zend_get_parameters_array_ex(param_count, args TSRMLS_CC) != SUCCESS) {
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
                
                memcpy(arg->name, arg_name, 16);
                arg->ptr = va_arg(vl, zval**);

                if (arg_num > 0 && arg_num < param_count) {
                    arg->val = args[arg_num];
                } else {
                    ZVAL_UNDEF(&arg->val);
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
    } while(1);

    if (param_count < state->arg_req) {
        php_printf("Less than required number of args.\n");
        return FAILURE;
    }

    arg_unnamed = state->arg_req + state->arg_opt;
    if (param_count > arg_unnamed) {
        znamed = &args[arg_unnamed];

        // Ensure that it is an options array!
        if (Z_TYPE_P(znamed) != IS_ARRAY) {
            php_printf("Options argument must be an associative array.\n");
            return FAILURE;
        }
    } else {
        znamed = NULL;
    }

    for (ii = 0; ii < state->arg_named; ++ii) {
        int aii = arg_unnamed + ii;
        pcbc_pp_state_arg *arg = &state->args[aii];

        if (znamed) {
            HashTable *htoptions = Z_ARRVAL_P(znamed);
            zval *zvalue = zend_hash_str_find(
                    htoptions, arg->name, strlen(arg->name)+1);

            if (zvalue) {
                arg->val = *zvalue;
            } else {
                ZVAL_UNDEF(&arg->val);
            }
        } else {
            ZVAL_UNDEF(&arg->val);
        }
    }

    if (Z_TYPE(state->zids) == IS_STRING) {
        // Good to Go
    } else if (Z_TYPE(state->zids) == IS_ARRAY) {
        HashTable *hash = Z_ARRVAL(state->zids);
        zend_hash_internal_pointer_reset_ex(hash, &state->hash_pos);
    } else {
        // Error probably
    }

    return SUCCESS;
}

int pcbc_pp_ismapped(pcbc_pp_state *state) {
    return Z_TYPE(state->zids) != IS_STRING;
}

int pcbc_pp_keycount(pcbc_pp_state *state) {
    if (Z_TYPE(state->zids) == IS_STRING) {
        return 1;
    } else if (Z_TYPE(state->zids) == IS_ARRAY) {
        return zend_hash_num_elements(Z_ARRVAL(state->zids));
    } else {
        return 0;
    }
}

int pcbc_pp_next(pcbc_pp_state *state) {
    int ii;
    int arg_total = state->arg_req + state->arg_opt + state->arg_named;

    // Set everything to 'base' values
    for (ii = 1; ii < arg_total; ++ii) {
        if (Z_TYPE(state->args[ii].val) == IS_UNDEF) {
            *(state->args[ii].ptr) = NULL;
        } else {
            *(state->args[ii].ptr) = &state->args[ii].val;
        }
    }

    if (Z_TYPE(state->zids) == IS_STRING) {
        if (state->cur_idx > 0) {
            return 0;
        }
        *(state->args[0].ptr) = &state->zids;
        state->cur_idx++;
        return 1;
    } else if (Z_TYPE(state->zids) == IS_ARRAY) {
        HashTable *hash = Z_ARRVAL(state->zids);
        zval *data;
        zend_string *keystr;
        int key_type;
        zend_ulong keyidx;

        data = zend_hash_get_current_data_ex(hash, &state->hash_pos);
        if (data == 0) {
            return 0;
        }

        key_type = zend_hash_get_current_key_ex(hash, &keystr, &keyidx, &state->hash_pos);

        if (key_type == HASH_KEY_IS_STRING) {
            ZVAL_STR(&state->tmpzid, keystr);
            *(state->args[0].ptr) = &state->tmpzid;

            if (Z_TYPE_P(data) == IS_ARRAY) {
                HashTable *htdata = Z_ARRVAL_P(data);
                zval *zvalue;

                for (ii = 1; ii < arg_total; ++ii) {
                    pcbc_pp_state_arg * arg = &state->args[ii];

                    zvalue = zend_hash_str_find(
                            htdata, arg->name, strlen(arg->name));
                    if (zvalue) {
                        *(arg->ptr) = zvalue;
                    }
                }
            }
        } else if (key_type == HASH_KEY_IS_LONG) {
            *(state->args[0].ptr) = data;
        }

        zend_hash_move_forward_ex(hash, &state->hash_pos);
        return 1;
    }

    return 0;
}

#endif /* PARAMPARSER_H_ */
