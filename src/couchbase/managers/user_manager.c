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
#include <ext/standard/php_http.h>
#include <ext/standard/url.h>

#define LOGARGS(instance, lvl) LCB_LOG_##lvl, instance, "pcbc/user_manager", __FILE__, __LINE__

zend_class_entry *pcbc_user_manager_ce;
zend_class_entry *pcbc_role_ce;
zend_class_entry *pcbc_role_and_description_ce;
zend_class_entry *pcbc_origin_ce;
zend_class_entry *pcbc_role_and_origins_ce;
zend_class_entry *pcbc_user_ce;
zend_class_entry *pcbc_user_and_metadata_ce;
zend_class_entry *pcbc_group_ce;
zend_class_entry *pcbc_get_all_users_options_ce;
zend_class_entry *pcbc_get_user_options_ce;
zend_class_entry *pcbc_drop_user_options_ce;
zend_class_entry *pcbc_upsert_user_options_ce;

static void httpcb_getUser(void *ctx, zval *return_value, zval *response)
{
    zval *val;
    object_init_ex(return_value, pcbc_user_and_metadata_ce);
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("domain"));
    if (val && Z_TYPE_P(val) == IS_STRING) {
        zend_update_property(pcbc_user_and_metadata_ce, return_value, ZEND_STRL("domain"), val TSRMLS_CC);
    }
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("password_change_date"));
    if (val && Z_TYPE_P(val) == IS_STRING) {
        zend_update_property(pcbc_user_and_metadata_ce, return_value, ZEND_STRL("password_changed"), val TSRMLS_CC);
    }
    zval external_groups;
    array_init(&external_groups);
    zend_update_property(pcbc_user_and_metadata_ce, return_value, ZEND_STRL("external_groups"),
                         &external_groups TSRMLS_CC);
    zval_ptr_dtor(&external_groups);
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("external_groups"));
    if (val && Z_TYPE_P(val) == IS_ARRAY) {
        zval *ent;
        ZEND_HASH_FOREACH_VAL(HASH_OF(val), ent)
        {
            add_next_index_zval(&external_groups, ent);
        }
        ZEND_HASH_FOREACH_END();
    }

    zval user;
    object_init_ex(&user, pcbc_user_ce);
    zend_update_property(pcbc_user_and_metadata_ce, return_value, ZEND_STRL("user"), &user TSRMLS_CC);
    zval_ptr_dtor(&user);
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("id"));
    if (val && Z_TYPE_P(val) == IS_STRING) {
        zend_update_property(pcbc_user_ce, &user, ZEND_STRL("username"), val TSRMLS_CC);
    }
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("name"));
    if (val && Z_TYPE_P(val) == IS_STRING) {
        zend_update_property(pcbc_user_ce, &user, ZEND_STRL("display_name"), val TSRMLS_CC);
    }
    zval groups;
    array_init(&groups);
    zend_update_property(pcbc_user_ce, &user, ZEND_STRL("groups"), &groups TSRMLS_CC);
    zval_ptr_dtor(&groups);
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("groups"));
    if (val && Z_TYPE_P(val) == IS_ARRAY) {
        zval *ent;
        ZEND_HASH_FOREACH_VAL(HASH_OF(val), ent)
        {
            add_next_index_zval(&groups, ent);
        }
        ZEND_HASH_FOREACH_END();
    }
    zval user_roles;
    array_init(&user_roles);
    zend_update_property(pcbc_user_ce, &user, ZEND_STRL("roles"), &user_roles TSRMLS_CC);
    zval_ptr_dtor(&user_roles);

    zval roles;
    array_init(&roles);
    zend_update_property(pcbc_user_and_metadata_ce, return_value, ZEND_STRL("effective_roles"), &roles TSRMLS_CC);
    zval_ptr_dtor(&roles);
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("roles"));
    if (val && Z_TYPE_P(val) == IS_ARRAY) {
        zval *ent;
        ZEND_HASH_FOREACH_VAL(HASH_OF(val), ent)
        {
            zval role;
            object_init_ex(&role, pcbc_role_ce);
            val = zend_symtable_str_find(Z_ARRVAL_P(ent), ZEND_STRL("role"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                zend_update_property(pcbc_role_ce, &role, ZEND_STRL("name"), val TSRMLS_CC);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(ent), ZEND_STRL("bucket_name"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                zend_update_property(pcbc_role_ce, &role, ZEND_STRL("bucket"), val TSRMLS_CC);
            }
            int is_user_role = 0;
            zval origins;
            array_init(&origins);
            val = zend_symtable_str_find(Z_ARRVAL_P(ent), ZEND_STRL("origins"));
            if (val && Z_TYPE_P(val) == IS_ARRAY) {
                zval *e;
                ZEND_HASH_FOREACH_VAL(HASH_OF(val), e)
                {
                    zval origin;
                    object_init_ex(&origin, pcbc_origin_ce);
                    val = zend_symtable_str_find(Z_ARRVAL_P(e), ZEND_STRL("name"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        zend_update_property(pcbc_origin_ce, &origin, ZEND_STRL("name"), val TSRMLS_CC);
                    }
                    val = zend_symtable_str_find(Z_ARRVAL_P(e), ZEND_STRL("type"));
                    if (val && Z_TYPE_P(val) == IS_STRING) {
                        zend_update_property(pcbc_origin_ce, &origin, ZEND_STRL("type"), val TSRMLS_CC);
                        if (zend_binary_strcmp("user", 4, Z_STRVAL_P(val), Z_STRLEN_P(val)) == 0) {
                            is_user_role = 1;
                        }
                    }
                    add_next_index_zval(&origins, &origin);
                }
                ZEND_HASH_FOREACH_END();
            } else {
                is_user_role = 1; // backward compatibility. old server does not send origins => user role
            }
            if (is_user_role) {
                add_next_index_zval(&user_roles, &role);
            }
            zval role_and_origins;
            object_init_ex(&role_and_origins, pcbc_role_and_origins_ce);
            zend_update_property(pcbc_role_and_origins_ce, &role_and_origins, ZEND_STRL("role"), &role TSRMLS_CC);
            zval_ptr_dtor(&role);
            zend_update_property(pcbc_role_and_origins_ce, &role_and_origins, ZEND_STRL("origins"), &origins TSRMLS_CC);
            zval_ptr_dtor(&origins);
            add_next_index_zval(&roles, &role_and_origins);
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_METHOD(UserManager, getUser)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    zval *options = NULL;
    zend_string *username;

    int rv =
        zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S|O!", &username, &options, pcbc_get_user_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_user_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    smart_str path = {0};
    if (options) {
        zval dval, *domain;
        domain = zend_read_property(pcbc_get_user_options_ce, options, ZEND_STRL("domain_name"), 0, &dval);
        if (domain && Z_TYPE_P(domain) == IS_STRING) {
            smart_str_append_printf(&path, "/settings/rbac/users/%.*s", (int)Z_STRLEN_P(domain), Z_STRVAL_P(domain));
        }
    }
    if (smart_str_get_len(&path) == 0) {
        smart_str_appends(&path, "/settings/rbac/users/local");
    }
    smart_str_append_printf(&path, "/%.*s", (int)ZSTR_LEN(username), ZSTR_VAL(username));
    smart_str_0(&path);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    lcb_cmdhttp_path(cmd, ZSTR_VAL(path.s), ZSTR_LEN(path.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getUser, NULL TSRMLS_CC);
    smart_str_free(&path);
}

static void httpcb_getAllUsers(void *ctx, zval *return_value, zval *response)
{
    array_init(return_value);

    if (!response || Z_TYPE_P(response) != IS_ARRAY) {
        return;
    }
    zval *entry;
    ZEND_HASH_FOREACH_VAL(HASH_OF(response), entry)
    {
        zval user_and_meta;
        httpcb_getUser(ctx, &user_and_meta, entry);
        add_next_index_zval(return_value, &user_and_meta);
    }
    ZEND_HASH_FOREACH_END();
}

PHP_METHOD(UserManager, getAllUsers)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    zval *options = NULL;
    char *path = "/settings/rbac/users/local";
    size_t path_len = strlen(path);
    int need_to_free_path = 0;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "|O!", &options, pcbc_get_all_users_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_user_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);
    if (options) {
        zval dval, *domain;
        domain = zend_read_property(pcbc_get_all_users_options_ce, options, ZEND_STRL("domain_name"), 0, &dval);
        if (domain && Z_TYPE_P(domain) == IS_STRING) {
            path_len = spprintf(&path, 0, "/settings/rbac/users/%.*s", (int)Z_STRLEN_P(domain), Z_STRVAL_P(domain));
            need_to_free_path = 1;
        }
    }

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    lcb_cmdhttp_path(cmd, path, path_len);
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getAllUsers, NULL TSRMLS_CC);
    if (need_to_free_path) {
        efree(path);
    }
}

PHP_METHOD(UserManager, upsertUser)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val, *username;
    zval *options = NULL;
    zval *user;

    int rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "O|O!", &user, pcbc_user_ce, &options,
                                         pcbc_upsert_user_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_user_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);
    username = zend_read_property(pcbc_user_ce, user, ZEND_STRL("username"), 0, &val);
    if (!username || Z_TYPE_P(username) != IS_STRING) {
        RETURN_NULL();
    }

    smart_str path = {0};
    if (options) {
        zval dval, *domain;
        domain = zend_read_property(pcbc_upsert_user_options_ce, options, ZEND_STRL("domain_name"), 0, &dval);
        if (domain && Z_TYPE_P(domain) == IS_STRING) {
            smart_str_append_printf(&path, "/settings/rbac/users/%.*s", (int)Z_STRLEN_P(domain), Z_STRVAL_P(domain));
        }
    }
    if (smart_str_get_len(&path) == 0) {
        smart_str_appends(&path, "/settings/rbac/users/local");
    }
    smart_str_append_printf(&path, "/%.*s", (int)Z_STRLEN_P(username), Z_STRVAL_P(username));
    smart_str_0(&path);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_PUT);
    lcb_cmdhttp_path(cmd, ZSTR_VAL(path.s), ZSTR_LEN(path.s));
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));

    zval payload;
    array_init(&payload);
    prop = zend_read_property(pcbc_user_ce, user, ZEND_STRL("display_name"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "name", prop);
    }
    prop = zend_read_property(pcbc_user_ce, user, ZEND_STRL("password"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        add_assoc_zval(&payload, "password", prop);
    }
    smart_str buf = {0};
    prop = zend_read_property(pcbc_user_ce, user, ZEND_STRL("groups"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_ARRAY && zend_array_count(Z_ARRVAL_P(prop)) > 0) {
        add_assoc_zval(&payload, "groups", prop);
        zval *entry;
        ZEND_HASH_FOREACH_VAL(HASH_OF(prop), entry)
        {
            if (Z_TYPE_P(entry) == IS_STRING) {
                smart_str_append_printf(&buf, "%.*s", (int)Z_STRLEN_P(entry), Z_STRVAL_P(entry));
            }
            smart_str_appendc(&buf, ',');
        }
        ZEND_HASH_FOREACH_END();
        smart_str_0(&buf);
        add_assoc_stringl(&payload, "groups", ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
        smart_str_free(&buf);
    }
    prop = zend_read_property(pcbc_user_ce, user, ZEND_STRL("roles"), 0, &val);
    if (prop && Z_TYPE_P(prop) == IS_ARRAY && zend_array_count(Z_ARRVAL_P(prop)) > 0) {
        zval *entry;
        ZEND_HASH_FOREACH_VAL(HASH_OF(prop), entry)
        {
            zval zv;
            prop = zend_read_property(pcbc_role_ce, entry, ZEND_STRL("name"), 0, &zv);
            if (!prop || Z_TYPE_P(prop) != IS_STRING) {
                continue;
            }
            smart_str_append_printf(&buf, "%.*s", (int)Z_STRLEN_P(prop), Z_STRVAL_P(prop));
            prop = zend_read_property(pcbc_role_ce, entry, ZEND_STRL("bucket"), 0, &zv);
            if (prop && Z_TYPE_P(prop) == IS_STRING) {
                smart_str_append_printf(&buf, "[%.*s]", (int)Z_STRLEN_P(prop), Z_STRVAL_P(prop));
            }
            smart_str_appendc(&buf, ',');
        }
        ZEND_HASH_FOREACH_END();
        smart_str_0(&buf);
        add_assoc_stringl(&payload, "roles", ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
        smart_str_free(&buf);
    }
    rv = php_url_encode_hash_ex(HASH_OF(&payload), &buf, NULL, 0, NULL, 0, NULL, 0, NULL, NULL,
                                PHP_QUERY_RFC1738 TSRMLS_CC);
    zval_dtor(&payload);
    if (rv == FAILURE) {
        smart_str_free(&buf);
        smart_str_free(&path);
        RETURN_NULL();
    }
    smart_str_0(&buf);
    lcb_cmdhttp_body(cmd, ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    smart_str_free(&path);
    smart_str_free(&buf);
}

PHP_METHOD(UserManager, dropUser)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    zval *options = NULL;
    zend_string *username;

    int rv =
        zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S|O!", &username, &options, pcbc_drop_user_options_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_user_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    smart_str path = {0};
    if (options) {
        zval dval, *domain;
        domain = zend_read_property(pcbc_drop_user_options_ce, options, ZEND_STRL("domain_name"), 0, &dval);
        if (domain && Z_TYPE_P(domain) == IS_STRING) {
            smart_str_append_printf(&path, "/settings/rbac/users/%.*s", (int)Z_STRLEN_P(domain), Z_STRVAL_P(domain));
        }
    }
    if (smart_str_get_len(&path) == 0) {
        smart_str_appends(&path, "/settings/rbac/users/local");
    }
    smart_str_append_printf(&path, "/%.*s", (int)ZSTR_LEN(username), ZSTR_VAL(username));
    smart_str_0(&path);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_DELETE);
    lcb_cmdhttp_path(cmd, ZSTR_VAL(path.s), ZSTR_LEN(path.s));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    smart_str_free(&path);
}

static void httpcb_getRoles(void *ctx, zval *return_value, zval *response)
{
    array_init(return_value);

    if (!response || Z_TYPE_P(response) != IS_ARRAY) {
        return;
    }
    zval *entry;
    ZEND_HASH_FOREACH_VAL(HASH_OF(response), entry)
    {
        zval role;
        object_init_ex(&role, pcbc_role_ce);
        zval *val;
        val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("role"));
        if (val && Z_TYPE_P(val) == IS_STRING) {
            zend_update_property(pcbc_role_ce, &role, ZEND_STRL("name"), val TSRMLS_CC);
        }
        val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("bucket_name"));
        if (val && Z_TYPE_P(val) == IS_STRING) {
            zend_update_property(pcbc_role_ce, &role, ZEND_STRL("bucket"), val TSRMLS_CC);
        }

        zval role_and_desc;
        object_init_ex(&role_and_desc, pcbc_role_and_description_ce);
        zend_update_property(pcbc_role_and_description_ce, &role_and_desc, ZEND_STRL("role"), &role TSRMLS_CC);
        zval_ptr_dtor(&role);
        val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("name"));
        if (val && Z_TYPE_P(val) == IS_STRING) {
            zend_update_property(pcbc_role_and_description_ce, &role_and_desc, ZEND_STRL("display_name"),
                                 val TSRMLS_CC);
        }
        val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("desc"));
        if (val && Z_TYPE_P(val) == IS_STRING) {
            zend_update_property(pcbc_role_and_description_ce, &role_and_desc, ZEND_STRL("description"), val TSRMLS_CC);
        }

        add_next_index_zval(return_value, &role_and_desc);
    }
    ZEND_HASH_FOREACH_END();
}

PHP_METHOD(UserManager, getRoles)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    char *path = "/settings/rbac/roles";

    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_user_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    lcb_cmdhttp_path(cmd, path, strlen(path));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getRoles, NULL TSRMLS_CC);
}

static void httpcb_getGroup(void *ctx, zval *return_value, zval *response)
{
    if (!response || Z_TYPE_P(response) != IS_ARRAY) {
        return;
    }
    object_init_ex(return_value, pcbc_group_ce);

    zval *val;
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("id"));
    if (val && Z_TYPE_P(val) == IS_STRING) {
        zend_update_property(pcbc_group_ce, return_value, ZEND_STRL("name"), val TSRMLS_CC);
    }
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("ldap_group_ref"));
    if (val && Z_TYPE_P(val) == IS_STRING) {
        zend_update_property(pcbc_group_ce, return_value, ZEND_STRL("ldap_group_reference"), val TSRMLS_CC);
    }
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("description"));
    if (val && Z_TYPE_P(val) == IS_STRING) {
        zend_update_property(pcbc_group_ce, return_value, ZEND_STRL("description"), val TSRMLS_CC);
    }

    zval roles;
    array_init(&roles);
    zend_update_property(pcbc_group_ce, return_value, ZEND_STRL("roles"), &roles TSRMLS_CC);
    zval_ptr_dtor(&roles);
    val = zend_symtable_str_find(Z_ARRVAL_P(response), ZEND_STRL("roles"));
    if (val && Z_TYPE_P(val) == IS_ARRAY) {
        zval *entry;
        ZEND_HASH_FOREACH_VAL(HASH_OF(val), entry)
        {
            zval role;
            object_init_ex(&role, pcbc_role_ce);
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("role"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                zend_update_property(pcbc_role_ce, &role, ZEND_STRL("name"), val TSRMLS_CC);
            }
            val = zend_symtable_str_find(Z_ARRVAL_P(entry), ZEND_STRL("bucket_name"));
            if (val && Z_TYPE_P(val) == IS_STRING) {
                zend_update_property(pcbc_role_ce, &role, ZEND_STRL("bucket"), val TSRMLS_CC);
            }

            add_next_index_zval(&roles, &role);
        }
        ZEND_HASH_FOREACH_END();
    }
}

PHP_METHOD(UserManager, getGroup)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    char *path;
    int rv, path_len;
    zend_string *name;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_user_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    path_len = spprintf(&path, 0, "/settings/rbac/groups/%.*s", (int)ZSTR_LEN(name), ZSTR_VAL(name));
    lcb_cmdhttp_path(cmd, path, path_len);
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getGroup, NULL TSRMLS_CC);
    efree(path);
}

static void httpcb_getAllGroups(void *ctx, zval *return_value, zval *response)
{
    array_init(return_value);

    if (!response || Z_TYPE_P(response) != IS_ARRAY) {
        return;
    }
    zval *entry;
    ZEND_HASH_FOREACH_VAL(HASH_OF(response), entry)
    {
        zval group;
        httpcb_getGroup(ctx, &group, entry);
        add_next_index_zval(return_value, &group);
    }
    ZEND_HASH_FOREACH_END();
}

PHP_METHOD(UserManager, getAllGroups)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    char *path = "/settings/rbac/groups";

    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_user_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_GET);
    lcb_cmdhttp_path(cmd, path, strlen(path));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, httpcb_getAllGroups, NULL TSRMLS_CC);
}

PHP_METHOD(UserManager, upsertGroup)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val, *group, *roles, *name, val1, val2;
    int rv, path_len;
    char *path = NULL;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "O", &group, pcbc_group_ce);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_user_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    roles = zend_read_property(pcbc_group_ce, group, ZEND_STRL("roles"), 0, &val1);
    if (!roles || Z_TYPE_P(roles) != IS_ARRAY) {
        RETURN_NULL();
    }
    name = zend_read_property(pcbc_group_ce, group, ZEND_STRL("name"), 0, &val2);
    if (!name || Z_TYPE_P(name) != IS_STRING) {
        RETURN_NULL();
    }
    path_len = spprintf(&path, 0, "/settings/rbac/groups/%.*s", (int)Z_STRLEN_P(name), Z_STRVAL_P(name));

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_PUT);
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));

    zval *entry;
    smart_str buf = {0};
    prop = zend_read_property(pcbc_group_ce, group, ZEND_STRL("description"), 0, &val2);
    if (prop && Z_TYPE_P(prop) == IS_STRING) {
        smart_str_appends(&buf, "description=");
        zend_string *str = php_url_encode(Z_STRVAL_P(prop), Z_STRLEN_P(prop));
        smart_str_append(&buf, str);
        zend_string_free(str);
        smart_str_appendc(&buf, '&');
    }
    smart_str_appends(&buf, "roles=");
    ZEND_HASH_FOREACH_VAL(HASH_OF(roles), entry)
    {
        zval zv;
        prop = zend_read_property(pcbc_role_ce, entry, ZEND_STRL("name"), 0, &zv);
        if (!prop || Z_TYPE_P(prop) != IS_STRING) {
            continue;
        }
        smart_str_append_printf(&buf, "%.*s", (int)Z_STRLEN_P(prop), Z_STRVAL_P(prop));
        prop = zend_read_property(pcbc_role_ce, entry, ZEND_STRL("bucket"), 0, &zv);
        if (prop && Z_TYPE_P(prop) == IS_STRING) {
            smart_str_append_printf(&buf, "[%.*s]", (int)Z_STRLEN_P(prop), Z_STRVAL_P(prop));
        }
        smart_str_appendc(&buf, ',');
    }
    ZEND_HASH_FOREACH_END();
    smart_str_0(&buf);
    lcb_cmdhttp_body(cmd, ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));

    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(path);
    smart_str_free(&buf);
}

PHP_METHOD(UserManager, dropGroup)
{
    pcbc_cluster_t *cluster = NULL;
    zval *prop, val;
    int rv, path_len;
    char *path;
    zend_string *name;

    rv = zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &name);
    if (rv == FAILURE) {
        RETURN_NULL();
    }
    prop = zend_read_property(pcbc_user_manager_ce, getThis(), ZEND_STRL("cluster"), 0, &val);
    cluster = Z_CLUSTER_OBJ_P(prop);

    path_len = spprintf(&path, 0, "/settings/rbac/groups/%.*s", (int)ZSTR_LEN(name), ZSTR_VAL(name));

    lcb_CMDHTTP *cmd;
    lcb_cmdhttp_create(&cmd, LCB_HTTP_TYPE_MANAGEMENT);
    lcb_cmdhttp_method(cmd, LCB_HTTP_METHOD_DELETE);
    lcb_cmdhttp_path(cmd, path, path_len);
    lcb_cmdhttp_content_type(cmd, PCBC_CONTENT_TYPE_FORM, strlen(PCBC_CONTENT_TYPE_FORM));
    pcbc_http_request(return_value, cluster->conn->lcb, cmd, 1, NULL, NULL, NULL TSRMLS_CC);
    efree(path);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_UserManager_getUser, 0, 1, Couchbase\\UserAndMetadata, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\GetUserOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_UserManager_getAllUsers, 0, 0, IS_ARRAY, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\GetAllUsersOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_UserManager_upsertUser, 0, 0, 1)
ZEND_ARG_OBJ_INFO(0, user, Couchbase\\User, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\UpsertUserOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_UserManager_dropUser, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_ARG_OBJ_INFO(0, options, Couchbase\\DropUserOptions, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_UserManager_getRoles, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_UserManager_getGroup, 0, 0, Couchbase\\Group, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(ai_UserManager_getAllGroups, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_UserManager_upsertGroup, 0, 0, 1)
ZEND_ARG_OBJ_INFO(0, group, Couchbase\\Group, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_UserManager_dropGroup, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry user_manager_methods[] = {
    PHP_ME(UserManager, getUser, ai_UserManager_getUser, ZEND_ACC_PUBLIC)
    PHP_ME(UserManager, getAllUsers, ai_UserManager_getAllUsers, ZEND_ACC_PUBLIC)
    PHP_ME(UserManager, upsertUser, ai_UserManager_upsertUser, ZEND_ACC_PUBLIC)
    PHP_ME(UserManager, dropUser, ai_UserManager_dropUser, ZEND_ACC_PUBLIC)
    PHP_ME(UserManager, getRoles, ai_UserManager_getRoles, ZEND_ACC_PUBLIC)
    PHP_ME(UserManager, getGroup, ai_UserManager_getGroup, ZEND_ACC_PUBLIC)
    PHP_ME(UserManager, getAllGroups, ai_UserManager_getAllGroups, ZEND_ACC_PUBLIC)
    PHP_ME(UserManager, upsertGroup, ai_UserManager_upsertGroup, ZEND_ACC_PUBLIC)
    PHP_ME(UserManager, dropGroup, ai_UserManager_dropGroup, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Role, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_role_ce, getThis(), ZEND_STRL("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(Role, bucket)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_role_ce, getThis(), ZEND_STRL("bucket"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(Role, setName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_role_ce, getThis(), ZEND_STRL("name"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(Role, setBucket)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_role_ce, getThis(), ZEND_STRL("bucket"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_Role_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_Role_bucket, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Role_setName, 0, 1, Couchbase\\Role, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Role_setBucket, 0, 1, Couchbase\\Role, 0)
ZEND_ARG_TYPE_INFO(0, bucket, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry role_methods[] = {
    PHP_ME(Role, name, ai_Role_name, ZEND_ACC_PUBLIC)
    PHP_ME(Role, bucket, ai_Role_bucket, ZEND_ACC_PUBLIC)
    PHP_ME(Role, setName, ai_Role_setName, ZEND_ACC_PUBLIC)
    PHP_ME(Role, setBucket, ai_Role_setBucket, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(RoleAndDescription, role)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_role_and_description_ce, getThis(), ZEND_STRL("role"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(RoleAndDescription, displayName)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_role_and_description_ce, getThis(), ZEND_STRL("display_name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(RoleAndDescription, description)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_role_and_description_ce, getThis(), ZEND_STRL("description"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_RoleAndDescription_role, Couchbase\\Role, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_RoleAndDescription_displayName, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_RoleAndDescription_description, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry role_and_description_methods[] = {
    PHP_ME(RoleAndDescription, role, ai_RoleAndDescription_role, ZEND_ACC_PUBLIC)
    PHP_ME(RoleAndDescription, displayName, ai_RoleAndDescription_displayName, ZEND_ACC_PUBLIC)
    PHP_ME(RoleAndDescription, description, ai_RoleAndDescription_description, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Origin, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_origin_ce, getThis(), ZEND_STRL("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(Origin, type)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_origin_ce, getThis(), ZEND_STRL("type"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_Origin_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_Origin_type, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry origin_methods[] = {
    PHP_ME(Origin, type, ai_Origin_type, ZEND_ACC_PUBLIC)
    PHP_ME(Origin, name, ai_Origin_name, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(RoleAndOrigins, role)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_role_and_origins_ce, getThis(), ZEND_STRL("role"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(RoleAndOrigins, origins)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_role_and_origins_ce, getThis(), ZEND_STRL("origins"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_RoleAndOrigins_role, Couchbase\\Role, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_RoleAndOrigins_origins, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry role_and_origins_methods[] = {
    PHP_ME(RoleAndOrigins, role, ai_RoleAndOrigins_role, ZEND_ACC_PUBLIC)
    PHP_ME(RoleAndOrigins, origins, ai_RoleAndOrigins_origins, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(User, username)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_user_ce, getThis(), ZEND_STRL("username"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(User, displayName)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_user_ce, getThis(), ZEND_STRL("display_name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(User, groups)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_user_ce, getThis(), ZEND_STRL("groups"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(User, roles)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_user_ce, getThis(), ZEND_STRL("roles"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(User, setUsername)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_user_ce, getThis(), ZEND_STRL("username"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(User, setPassword)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_user_ce, getThis(), ZEND_STRL("password"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(User, setDisplayName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_user_ce, getThis(), ZEND_STRL("display_name"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(User, setGroups)
{
    zval *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "a", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property(pcbc_user_ce, getThis(), ZEND_STRL("groups"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(User, setRoles)
{
    zval *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "a", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property(pcbc_user_ce, getThis(), ZEND_STRL("roles"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_User_username, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_User_displayName, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_User_groups, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_User_roles, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_User_setUsername, 0, 1, Couchbase\\User, 0)
ZEND_ARG_TYPE_INFO(0, username, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_User_setPassword, 0, 1, Couchbase\\User, 0)
ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_User_setDisplayName, 0, 1, Couchbase\\User, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_User_setGroups, 0, 1, Couchbase\\User, 0)
ZEND_ARG_TYPE_INFO(0, groups, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_User_setRoles, 0, 1, Couchbase\\User, 0)
ZEND_ARG_TYPE_INFO(0, roles, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry user_methods[] = {
    PHP_ME(User, username, ai_User_username, ZEND_ACC_PUBLIC)
    PHP_ME(User, displayName, ai_User_displayName, ZEND_ACC_PUBLIC)
    PHP_ME(User, groups, ai_User_groups, ZEND_ACC_PUBLIC)
    PHP_ME(User, roles, ai_User_roles, ZEND_ACC_PUBLIC)
    PHP_ME(User, setUsername, ai_User_setUsername, ZEND_ACC_PUBLIC)
    PHP_ME(User, setPassword, ai_User_setPassword, ZEND_ACC_PUBLIC)
    PHP_ME(User, setDisplayName, ai_User_setDisplayName, ZEND_ACC_PUBLIC)
    PHP_ME(User, setGroups, ai_User_setGroups, ZEND_ACC_PUBLIC)
    PHP_ME(User, setRoles, ai_User_setRoles, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(UserAndMetadata, domain)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_user_and_metadata_ce, getThis(), ZEND_STRL("domain"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(UserAndMetadata, passwordChanged)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_user_and_metadata_ce, getThis(), ZEND_STRL("password_changed"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(UserAndMetadata, externalGroups)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_user_and_metadata_ce, getThis(), ZEND_STRL("external_groups"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(UserAndMetadata, effectiveRoles)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_user_and_metadata_ce, getThis(), ZEND_STRL("effective_roles"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(UserAndMetadata, user)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_user_and_metadata_ce, getThis(), ZEND_STRL("user"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_UserAndMetadata_domain, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_UserAndMetadata_passwordChanged, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_UserAndMetadata_externalGroups, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_UserAndMetadata_effectiveRoles, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_UserAndMetadata_user, Couchbase\\User, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry user_and_metadata_methods[] = {
    PHP_ME(UserAndMetadata, domain, ai_UserAndMetadata_domain, ZEND_ACC_PUBLIC)
    PHP_ME(UserAndMetadata, user, ai_UserAndMetadata_user, ZEND_ACC_PUBLIC)
    PHP_ME(UserAndMetadata, effectiveRoles, ai_UserAndMetadata_effectiveRoles, ZEND_ACC_PUBLIC)
    PHP_ME(UserAndMetadata, passwordChanged, ai_UserAndMetadata_passwordChanged, ZEND_ACC_PUBLIC)
    PHP_ME(UserAndMetadata, externalGroups, ai_UserAndMetadata_externalGroups, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(Group, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_group_ce, getThis(), ZEND_STRL("name"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(Group, description)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_group_ce, getThis(), ZEND_STRL("description"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(Group, ldapGroupReference)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_group_ce, getThis(), ZEND_STRL("ldap_group_reference"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(Group, roles)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        RETURN_NULL();
    }

    zval *prop, rv;
    prop = zend_read_property(pcbc_group_ce, getThis(), ZEND_STRL("roles"), 0, &rv);
    ZVAL_COPY(return_value, prop);
}

PHP_METHOD(Group, setName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_group_ce, getThis(), ZEND_STRL("name"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(Group, setDescription)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_group_ce, getThis(), ZEND_STRL("description"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

PHP_METHOD(Group, setRoles)
{
    zval *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "a", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property(pcbc_group_ce, getThis(), ZEND_STRL("roles"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_Group_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_Group_description, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_Group_roles, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_Group_ldapGroupReference, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Group_setName, 0, 1, Couchbase\\Group, 0)
ZEND_ARG_TYPE_INFO(0, name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Group_setDescription, 0, 1, Couchbase\\Group, 0)
ZEND_ARG_TYPE_INFO(0, description, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_Group_setRoles, 0, 1, Couchbase\\Group, 0)
ZEND_ARG_TYPE_INFO(0, roles, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry group_methods[] = {
    PHP_ME(Group, name, ai_Group_name, ZEND_ACC_PUBLIC)
    PHP_ME(Group, description, ai_Group_description, ZEND_ACC_PUBLIC)
    PHP_ME(Group, roles, ai_Group_roles, ZEND_ACC_PUBLIC)
    PHP_ME(Group, ldapGroupReference, ai_Group_ldapGroupReference, ZEND_ACC_PUBLIC)
    PHP_ME(Group, setName, ai_Group_setName, ZEND_ACC_PUBLIC)
    PHP_ME(Group, setDescription, ai_Group_setDescription, ZEND_ACC_PUBLIC)
    PHP_ME(Group, setRoles, ai_Group_setRoles, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(GetUserOptions, domainName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_get_user_options_ce, getThis(), ZEND_STRL("domain_name"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetUserOptions_domainName, 0, 1, Couchbase\\GetUserOptions, 0)
ZEND_ARG_TYPE_INFO(0, domainName, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry get_user_options_methods[] = {
    PHP_ME(GetUserOptions, domainName, ai_GetUserOptions_domainName, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(UpsertUserOptions, domainName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_upsert_user_options_ce, getThis(), ZEND_STRL("domain_name"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_UpsertUserOptions_domainName, 0, 1, Couchbase\\UpsertUserOptions, 0)
ZEND_ARG_TYPE_INFO(0, domainName, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry upsert_user_options_methods[] = {
    PHP_ME(UpsertUserOptions, domainName, ai_UpsertUserOptions_domainName, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(DropUserOptions, domainName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_drop_user_options_ce, getThis(), ZEND_STRL("domain_name"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_DropUserOptions_domainName, 0, 1, Couchbase\\DropUserOptions, 0)
ZEND_ARG_TYPE_INFO(0, domainName, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry drop_user_options_methods[] = {
    PHP_ME(DropUserOptions, domainName, ai_DropUserOptions_domainName, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_METHOD(GetAllUsersOptions, domainName)
{
    zend_string *val;
    if (zend_parse_parameters_throw(ZEND_NUM_ARGS() TSRMLS_CC, "S", &val) == FAILURE) {
        RETURN_NULL();
    }

    zend_update_property_str(pcbc_get_all_users_options_ce, getThis(), ZEND_STRL("domain_name"), val TSRMLS_CC);
    RETURN_ZVAL(getThis(), 1, 0);
}

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetAllUsersOptions_domainName, 0, 1, Couchbase\\GetAllUsersOptions, 0)
ZEND_ARG_TYPE_INFO(0, domainName, IS_STRING, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry get_all_users_options_methods[] = {
    PHP_ME(GetAllUsersOptions, domainName, ai_GetAllUsersOptions_domainName, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
// clang-format on

PHP_MINIT_FUNCTION(UserManager)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "UserManager", user_manager_methods);
    pcbc_user_manager_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_user_manager_ce, ZEND_STRL("cluster"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "Role", role_methods);
    pcbc_role_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_role_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_role_ce, ZEND_STRL("bucket"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "RoleAndDescription", role_and_description_methods);
    pcbc_role_and_description_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_role_and_description_ce, ZEND_STRL("role"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_role_and_description_ce, ZEND_STRL("display_name"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_role_and_description_ce, ZEND_STRL("description"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "Origin", origin_methods);
    pcbc_origin_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_origin_ce, ZEND_STRL("type"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_origin_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "RoleAndOrigins", role_and_origins_methods);
    pcbc_role_and_origins_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_role_and_origins_ce, ZEND_STRL("role"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_role_and_origins_ce, ZEND_STRL("origins"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "User", user_methods);
    pcbc_user_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_user_ce, ZEND_STRL("username"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_user_ce, ZEND_STRL("password"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_user_ce, ZEND_STRL("display_name"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_user_ce, ZEND_STRL("groups"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_user_ce, ZEND_STRL("roles"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "UserAndMetadata", user_and_metadata_methods);
    pcbc_user_and_metadata_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_user_and_metadata_ce, ZEND_STRL("domain"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_user_and_metadata_ce, ZEND_STRL("user"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_user_and_metadata_ce, ZEND_STRL("effective_roles"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_user_and_metadata_ce, ZEND_STRL("password_changed"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_user_and_metadata_ce, ZEND_STRL("external_groups"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "Group", group_methods);
    pcbc_group_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_group_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_group_ce, ZEND_STRL("description"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_group_ce, ZEND_STRL("roles"), ZEND_ACC_PRIVATE TSRMLS_CC);
    zend_declare_property_null(pcbc_group_ce, ZEND_STRL("ldap_group_reference"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GetAllUsersOptions", get_all_users_options_methods);
    pcbc_get_all_users_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_get_all_users_options_ce, ZEND_STRL("domain_name"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GetUserOptions", get_user_options_methods);
    pcbc_get_user_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_get_user_options_ce, ZEND_STRL("domain_name"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DropUserOptions", drop_user_options_methods);
    pcbc_drop_user_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_drop_user_options_ce, ZEND_STRL("domain_name"), ZEND_ACC_PRIVATE TSRMLS_CC);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "UpsertUserOptions", upsert_user_options_methods);
    pcbc_upsert_user_options_ce = zend_register_internal_class(&ce TSRMLS_CC);
    zend_declare_property_null(pcbc_upsert_user_options_ce, ZEND_STRL("domain_name"), ZEND_ACC_PRIVATE TSRMLS_CC);

    return SUCCESS;
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
