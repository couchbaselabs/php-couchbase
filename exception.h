#ifndef EXCEPTION_H_
#define EXCEPTION_H_

void make_exception(zval *ex, zend_class_entry *exception_ce, const char *message, long code TSRMLS_DC);
void make_pcbc_exception(zval *ex, const char *message, long code TSRMLS_DC);
void make_lcb_exception(zval *ex, long code, const char *msg TSRMLS_DC);

#define throw_pcbc_exception(message, code) { \
    zval zerror; \
    make_pcbc_exception(&zerror, message, code TSRMLS_CC); \
    zend_throw_exception_object(&zerror TSRMLS_CC); }
#define throw_lcb_exception(code) { \
    zval zerror; \
    make_lcb_exception(&zerror, code, NULL TSRMLS_CC); \
	zend_throw_exception_object(&zerror TSRMLS_CC); }

extern zend_class_entry *default_exception_ce;
extern zend_class_entry *cb_exception_ce;

#endif
