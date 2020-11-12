/**
 *     Copyright 2019 Couchbase, Inc.
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

/**
 * Interface for all FTS sort options in querying.
 */

#include "couchbase.h"

zend_class_entry *pcbc_search_sort_ce;

static const zend_function_entry search_sort_interface[] = {PHP_FE_END};

PHP_MINIT_FUNCTION(SearchSort)
{
    zend_class_entry ce;
    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchSort", search_sort_interface);
    pcbc_search_sort_ce = zend_register_internal_interface(&ce);

    return SUCCESS;
}
