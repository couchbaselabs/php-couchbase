#ifndef PHPHELPERS_H_
#define PHPHELPERS_H_

#include <php.h>

#if PHP_VERSION_ID >= 50400
#define phlp_object_properties_init object_properties_init
#else
static void phlp_object_properties_init(zend_object *obj, zend_class_entry* type) {
	zval *tmp;
    ALLOC_HASHTABLE(obj->properties);
    zend_hash_init(obj->properties, 0, NULL, ZVAL_PTR_DTOR, 0);
	zend_hash_copy(obj->properties, &type->default_properties,
		(copy_ctor_func_t)zval_add_ref, (void *)&tmp, sizeof(zval *));
}
#endif

#if ZEND_MODULE_API_NO >= 20151012
#define phlp_zend_register_internal_class_ex(ce, parent_ce) zend_register_internal_class_ex(ce, parent_ce TSRMLS_CC)
#else
#define phlp_zend_register_internal_class_ex(ce, parent_ce) zend_register_internal_class_ex(ce, parent_ce, NULL TSRMLS_CC)
#endif

#if ZEND_MODULE_API_NO >= 20060613
#define phlp_zend_exception_get_default() zend_exception_get_default(TSRMLS_C)
#else
#define phlp_zend_exception_get_default() zend_exception_get_default()
#endif

#endif // PHPHELPERS_H_
