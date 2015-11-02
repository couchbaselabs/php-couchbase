#ifndef CLUSTER_H_
#define CLUSTER_H_

#include <libcouchbase/couchbase.h>
#include <php.h>

typedef struct cluster_object {
	lcb_t lcb;
	zval error;

	zend_object std;
} cluster_object;

#endif // CLUSTER_H_
