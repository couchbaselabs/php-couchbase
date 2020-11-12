/**
 *     Copyright 2018-2019 Couchbase, Inc.
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

#define LOGARGS(lvl) LCB_LOG_##lvl, NULL, "pcbc/cert_authenticator", __FILE__, __LINE__

static inline pcbc_cert_authenticator_t *pcbc_cert_authenticator_fetch_object(zend_object *obj)
{
    return (pcbc_cert_authenticator_t *)((char *)obj - XtOffsetOf(pcbc_cert_authenticator_t, std));
}
#define Z_CERT_AUTHENTICATOR_OBJ(zo) (pcbc_cert_authenticator_fetch_object(zo))

zend_class_entry *pcbc_cert_authenticator_ce;
extern zend_class_entry *pcbc_authenticator_ce;

PHP_METHOD(CertAuthenticator, __construct)
{
    zend_parse_parameters_none_throw();
}

ZEND_BEGIN_ARG_INFO_EX(ai_CertAuthenticator_none, 0, 0, 0)
ZEND_END_ARG_INFO()

// clang-format off
zend_function_entry cert_authenticator_methods[] = {
    PHP_ME(CertAuthenticator, __construct, ai_CertAuthenticator_none, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_FE_END
};
// clang-format on

zend_object_handlers cert_authenticator_handlers;

static void cert_authenticator_free_object(zend_object *object)
{
    pcbc_cert_authenticator_t *obj = Z_CERT_AUTHENTICATOR_OBJ(object);

    zend_object_std_dtor(&obj->std);
}

static zend_object *authenticator_create_object(zend_class_entry *class_type)
{
    pcbc_cert_authenticator_t *obj = NULL;

    obj = PCBC_ALLOC_OBJECT_T(pcbc_cert_authenticator_t, class_type);

    zend_object_std_init(&obj->std, class_type);
    object_properties_init(&obj->std, class_type);

    obj->std.handlers = &cert_authenticator_handlers;
    return &obj->std;
}

PHP_MINIT_FUNCTION(CertAuthenticator)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "CertAuthenticator", cert_authenticator_methods);
    pcbc_cert_authenticator_ce = zend_register_internal_class(&ce);
    pcbc_cert_authenticator_ce->create_object = authenticator_create_object;
    PCBC_CE_DISABLE_SERIALIZATION(pcbc_cert_authenticator_ce);

    zend_class_implements(pcbc_cert_authenticator_ce, 1, pcbc_authenticator_ce);

    memcpy(&cert_authenticator_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    cert_authenticator_handlers.free_obj = cert_authenticator_free_object;
    cert_authenticator_handlers.offset = XtOffsetOf(pcbc_cert_authenticator_t, std);
    return SUCCESS;
}
