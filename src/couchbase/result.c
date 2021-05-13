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

#include <ext/date/php_date.h>

// clang-format off
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_MutationToken_partitionId, IS_LONG, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_MutationToken_partitionUuid, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_MutationToken_sequenceNumber, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_MutationToken_bucketName, IS_STRING, 1)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_mutation_token_ce;
static const zend_function_entry pcbc_mutation_token_methods[] = {
    PHP_ABSTRACT_ME(MutationToken, partitionId, ai_MutationToken_partitionId)
    PHP_ABSTRACT_ME(MutationToken, partitionUuid, ai_MutationToken_partitionUuid)
    PHP_ABSTRACT_ME(MutationToken, sequenceNumber, ai_MutationToken_sequenceNumber)
    PHP_ABSTRACT_ME(MutationToken, bucketName, ai_MutationToken_bucketName)
    PHP_FE_END
};

PHP_METHOD(MutationTokenImpl, partitionId);
PHP_METHOD(MutationTokenImpl, partitionUuid);
PHP_METHOD(MutationTokenImpl, sequenceNumber);
PHP_METHOD(MutationTokenImpl, bucketName);

zend_class_entry *pcbc_mutation_token_impl_ce;
static const zend_function_entry pcbc_mutation_token_impl_methods[] = {
    PHP_ME(MutationTokenImpl, partitionId, ai_MutationToken_partitionId, ZEND_ACC_PUBLIC)
    PHP_ME(MutationTokenImpl, partitionUuid, ai_MutationToken_partitionUuid, ZEND_ACC_PUBLIC)
    PHP_ME(MutationTokenImpl, sequenceNumber, ai_MutationToken_sequenceNumber, ZEND_ACC_PUBLIC)
    PHP_ME(MutationTokenImpl, bucketName, ai_MutationToken_bucketName, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_QueryMetaData_status, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_QueryMetaData_requestId, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_QueryMetaData_clientContextId, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_QueryMetaData_signature, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_QueryMetaData_errors, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_QueryMetaData_warnings, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_QueryMetaData_metrics, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_QueryMetaData_profile, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_query_meta_data_ce;
static const zend_function_entry pcbc_query_meta_data_methods[] = {
    PHP_ABSTRACT_ME(QueryMetaData, status, ai_QueryMetaData_status)
    PHP_ABSTRACT_ME(QueryMetaData, requestId, ai_QueryMetaData_requestId)
    PHP_ABSTRACT_ME(QueryMetaData, clientContextId, ai_QueryMetaData_clientContextId)
    PHP_ABSTRACT_ME(QueryMetaData, signature, ai_QueryMetaData_signature)
    PHP_ABSTRACT_ME(QueryMetaData, warnings, ai_QueryMetaData_warnings)
    PHP_ABSTRACT_ME(QueryMetaData, errors, ai_QueryMetaData_errors)
    PHP_ABSTRACT_ME(QueryMetaData, metrics, ai_QueryMetaData_metrics)
    PHP_ABSTRACT_ME(QueryMetaData, profile, ai_QueryMetaData_profile)
    PHP_FE_END
};

PHP_METHOD(QueryMetaDataImpl, status);
PHP_METHOD(QueryMetaDataImpl, requestId);
PHP_METHOD(QueryMetaDataImpl, clientContextId);
PHP_METHOD(QueryMetaDataImpl, signature);
PHP_METHOD(QueryMetaDataImpl, errors);
PHP_METHOD(QueryMetaDataImpl, warnings);
PHP_METHOD(QueryMetaDataImpl, metrics);
PHP_METHOD(QueryMetaDataImpl, profile);

zend_class_entry *pcbc_query_meta_data_impl_ce;
static const zend_function_entry pcbc_query_meta_data_impl_methods[] = {
    PHP_ME(QueryMetaDataImpl, status, ai_QueryMetaData_status, ZEND_ACC_PUBLIC)
    PHP_ME(QueryMetaDataImpl, requestId, ai_QueryMetaData_requestId, ZEND_ACC_PUBLIC)
    PHP_ME(QueryMetaDataImpl, clientContextId, ai_QueryMetaData_clientContextId, ZEND_ACC_PUBLIC)
    PHP_ME(QueryMetaDataImpl, signature, ai_QueryMetaData_signature, ZEND_ACC_PUBLIC)
    PHP_ME(QueryMetaDataImpl, errors, ai_QueryMetaData_errors, ZEND_ACC_PUBLIC)
    PHP_ME(QueryMetaDataImpl, warnings, ai_QueryMetaData_warnings, ZEND_ACC_PUBLIC)
    PHP_ME(QueryMetaDataImpl, metrics, ai_QueryMetaData_metrics, ZEND_ACC_PUBLIC)
    PHP_ME(QueryMetaDataImpl, profile, ai_QueryMetaData_profile, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchMetaData_successCount, IS_LONG, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchMetaData_errorCount, IS_LONG, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchMetaData_took, IS_LONG, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchMetaData_totalHits, IS_LONG, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchMetaData_maxScore, IS_DOUBLE, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchMetaData_metrics, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_search_meta_data_ce;
static const zend_function_entry pcbc_search_meta_data_methods[] = {
    PHP_ABSTRACT_ME(SearchMetaData, successCount, ai_SearchMetaData_successCount)
    PHP_ABSTRACT_ME(SearchMetaData, errorCount, ai_SearchMetaData_errorCount)
    PHP_ABSTRACT_ME(SearchMetaData, took, ai_SearchMetaData_took)
    PHP_ABSTRACT_ME(SearchMetaData, totalHits, ai_SearchMetaData_totalHits)
    PHP_ABSTRACT_ME(SearchMetaData, maxScore, ai_SearchMetaData_maxScore)
    PHP_ABSTRACT_ME(SearchMetaData, metrics, ai_SearchMetaData_metrics)
    PHP_FE_END
};

PHP_METHOD(SearchMetaDataImpl, successCount);
PHP_METHOD(SearchMetaDataImpl, errorCount);
PHP_METHOD(SearchMetaDataImpl, took);
PHP_METHOD(SearchMetaDataImpl, totalHits);
PHP_METHOD(SearchMetaDataImpl, maxScore);
PHP_METHOD(SearchMetaDataImpl, metrics);

zend_class_entry *pcbc_search_meta_data_impl_ce;
static const zend_function_entry pcbc_search_meta_data_impl_methods[] = {
    PHP_ME(SearchMetaDataImpl, successCount, ai_SearchMetaData_successCount, ZEND_ACC_PUBLIC)
    PHP_ME(SearchMetaDataImpl, errorCount, ai_SearchMetaData_errorCount, ZEND_ACC_PUBLIC)
    PHP_ME(SearchMetaDataImpl, took, ai_SearchMetaData_took, ZEND_ACC_PUBLIC)
    PHP_ME(SearchMetaDataImpl, totalHits, ai_SearchMetaData_totalHits, ZEND_ACC_PUBLIC)
    PHP_ME(SearchMetaDataImpl, maxScore, ai_SearchMetaData_maxScore, ZEND_ACC_PUBLIC)
    PHP_ME(SearchMetaDataImpl, metrics, ai_SearchMetaData_metrics, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_ViewMetaData_totalRows, IS_LONG, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_ViewMetaData_debug, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_view_meta_data_ce;
static const zend_function_entry pcbc_view_meta_data_methods[] = {
    PHP_ABSTRACT_ME(ViewMetaData, totalRows, ai_ViewMetaData_totalRows)
    PHP_ABSTRACT_ME(ViewMetaData, debug, ai_ViewMetaData_debug)
    PHP_FE_END
};

PHP_METHOD(ViewMetaDataImpl, totalRows);
PHP_METHOD(ViewMetaDataImpl, debug);

zend_class_entry *pcbc_view_meta_data_impl_ce;
static const zend_function_entry pcbc_view_meta_data_impl_methods[] = {
    PHP_ME(ViewMetaDataImpl, totalRows, ai_ViewMetaData_totalRows, ZEND_ACC_PUBLIC)
    PHP_ME(ViewMetaDataImpl, debug, ai_ViewMetaData_debug, ZEND_ACC_PUBLIC)
    PHP_FE_END
};


ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_Result_cas, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_Result_expiry, IS_LONG, 1)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_result_ce;
static const zend_function_entry pcbc_result_methods[] = {
    PHP_ABSTRACT_ME(Result, cas, ai_Result_cas)
    PHP_FE_END
};

PHP_METHOD(ResultImpl, cas);

zend_class_entry *pcbc_result_impl_ce;
static const zend_function_entry pcbc_result_impl_methods[] = {
    PHP_ME(ResultImpl, cas, ai_Result_cas, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_INFO(ai_GetResult_content, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_GetResult_expiryTime, 0, 0, DateTimeInterface, 1)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_get_result_ce;
static const zend_function_entry pcbc_get_result_methods[] = {
    PHP_ABSTRACT_ME(GetResult, content, ai_GetResult_content)
    PHP_ABSTRACT_ME(GetResult, expiryTime, ai_GetResult_expiryTime)
    PHP_FE_END
};

PHP_METHOD(GetResultImpl, cas);
PHP_METHOD(GetResultImpl, expiry);
PHP_METHOD(GetResultImpl, expiryTime);
PHP_METHOD(GetResultImpl, content);

zend_class_entry *pcbc_get_result_impl_ce;
static const zend_function_entry pcbc_get_result_impl_methods[] = {
    PHP_ME(GetResultImpl, cas, ai_Result_cas, ZEND_ACC_PUBLIC)
    PHP_ME(GetResultImpl, expiry, ai_Result_expiry, ZEND_ACC_PUBLIC|ZEND_ACC_DEPRECATED)
    PHP_ME(GetResultImpl, expiryTime, ai_GetResult_expiryTime, ZEND_ACC_PUBLIC)
    PHP_ME(GetResultImpl, content, ai_GetResult_content, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_INFO(ai_GetReplicaResult_content, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_GetReplicaResult_isReplica, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_get_replica_result_ce;
static const zend_function_entry pcbc_get_replica_result_methods[] = {
    PHP_ABSTRACT_ME(GetReplicaResult, content, ai_GetReplicaResult_content)
    PHP_ABSTRACT_ME(GetReplicaResult, isReplica, ai_GetReplicaResult_isReplica)
    PHP_FE_END
};

PHP_METHOD(GetReplicaResultImpl, cas);
PHP_METHOD(GetReplicaResultImpl, expiry);
PHP_METHOD(GetReplicaResultImpl, content);
PHP_METHOD(GetReplicaResultImpl, isReplica);

zend_class_entry *pcbc_get_replica_result_impl_ce;
static const zend_function_entry pcbc_get_replica_result_impl_methods[] = {
    PHP_ME(GetReplicaResultImpl, cas, ai_Result_cas, ZEND_ACC_PUBLIC)
    PHP_ME(GetReplicaResultImpl, expiry, ai_Result_expiry, ZEND_ACC_PUBLIC|ZEND_ACC_DEPRECATED)
    PHP_ME(GetReplicaResultImpl, content, ai_GetReplicaResult_content, ZEND_ACC_PUBLIC)
    PHP_ME(GetReplicaResultImpl, isReplica, ai_GetReplicaResult_isReplica, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_ExistsResult_exists, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_exists_result_ce;
static const zend_function_entry pcbc_exists_result_methods[] = {
    PHP_ABSTRACT_ME(ExistsResult, exists, ai_ExistsResult_exists)
    PHP_FE_END
};

PHP_METHOD(ExistsResultImpl, cas);
PHP_METHOD(ExistsResultImpl, expiry);
PHP_METHOD(ExistsResultImpl, exists);

zend_class_entry *pcbc_exists_result_impl_ce;
static const zend_function_entry pcbc_exists_result_impl_methods[] = {
    PHP_ME(ExistsResultImpl, cas, ai_Result_cas, ZEND_ACC_PUBLIC)
    PHP_ME(ExistsResultImpl, expiry, ai_Result_expiry, ZEND_ACC_PUBLIC)
    PHP_ME(ExistsResultImpl, exists, ai_ExistsResult_exists, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_MutationResult_mutationToken, Couchbase\\MutationToken, 1)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_mutation_result_ce;
static const zend_function_entry pcbc_mutation_result_methods[] = {
    PHP_ABSTRACT_ME(MutationResult, mutationToken, ai_MutationResult_mutationToken)
    PHP_FE_END
};

PHP_METHOD(MutationResultImpl, cas);
PHP_METHOD(MutationResultImpl, expiry);
PHP_METHOD(MutationResultImpl, mutationToken);

zend_class_entry *pcbc_mutation_result_impl_ce;
static const zend_function_entry pcbc_mutation_result_impl_methods[] = {
    PHP_ME(MutationResultImpl, cas, ai_Result_cas, ZEND_ACC_PUBLIC)
    PHP_ME(MutationResultImpl, expiry, ai_Result_expiry, ZEND_ACC_PUBLIC)
    PHP_ME(MutationResultImpl, mutationToken, ai_MutationResult_mutationToken, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

PHP_METHOD(StoreResultImpl, cas);
PHP_METHOD(StoreResultImpl, expiry);
PHP_METHOD(StoreResultImpl, mutationToken);

zend_class_entry *pcbc_store_result_impl_ce;
static const zend_function_entry pcbc_store_result_impl_methods[] = {
    PHP_ME(StoreResultImpl, cas, ai_Result_cas, ZEND_ACC_PUBLIC)
    PHP_ME(StoreResultImpl, expiry, ai_Result_expiry, ZEND_ACC_PUBLIC)
    PHP_ME(StoreResultImpl, mutationToken, ai_MutationResult_mutationToken, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_CounterResult_content, IS_LONG, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_counter_result_ce;
static const zend_function_entry pcbc_counter_result_methods[] = {
    PHP_ABSTRACT_ME(CounterResult, content, ai_CounterResult_content)
    PHP_FE_END
};

PHP_METHOD(CounterResultImpl, cas);
PHP_METHOD(CounterResultImpl, expiry);
PHP_METHOD(CounterResultImpl, mutationToken);
PHP_METHOD(CounterResultImpl, content);

zend_class_entry *pcbc_counter_result_impl_ce;
static const zend_function_entry pcbc_counter_result_impl_methods[] = {
    PHP_ME(CounterResultImpl, cas, ai_Result_cas, ZEND_ACC_PUBLIC)
    PHP_ME(CounterResultImpl, expiry, ai_Result_expiry, ZEND_ACC_PUBLIC)
    PHP_ME(CounterResultImpl, mutationToken, ai_MutationResult_mutationToken, ZEND_ACC_PUBLIC)
    PHP_ME(CounterResultImpl, content, ai_CounterResult_content, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(ai_LookupInResult_expiryTime, 0, 0, DateTimeInterface, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_LookupInResult_content, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, index, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_LookupInResult_exists, _IS_BOOL, 0)
ZEND_ARG_TYPE_INFO(0, index, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_LookupInResult_status, IS_LONG, 0)
ZEND_ARG_TYPE_INFO(0, index, IS_LONG, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_lookup_in_result_ce;
static const zend_function_entry pcbc_lookup_in_result_methods[] = {
    PHP_ABSTRACT_ME(LookupInResult, expiryTime, ai_LookupInResult_expiryTime)
    PHP_ABSTRACT_ME(LookupInResult, content, ai_LookupInResult_content)
    PHP_ABSTRACT_ME(LookupInResult, exists, ai_LookupInResult_exists)
    PHP_ABSTRACT_ME(LookupInResult, status, ai_LookupInResult_status)
    PHP_FE_END
};

PHP_METHOD(LookupInResultImpl, cas);
PHP_METHOD(LookupInResultImpl, expiry);
PHP_METHOD(LookupInResultImpl, expiryTime);
PHP_METHOD(LookupInResultImpl, content);
PHP_METHOD(LookupInResultImpl, exists);
PHP_METHOD(LookupInResultImpl, status);

zend_class_entry *pcbc_lookup_in_result_impl_ce;
static const zend_function_entry pcbc_lookup_in_result_impl_methods[] = {
    PHP_ME(LookupInResultImpl, cas, ai_Result_cas, ZEND_ACC_PUBLIC)
    PHP_ME(LookupInResultImpl, expiry, ai_Result_expiry, ZEND_ACC_PUBLIC|ZEND_ACC_DEPRECATED)
    PHP_ME(LookupInResultImpl, expiryTime, ai_LookupInResult_expiryTime, ZEND_ACC_PUBLIC)
    PHP_ME(LookupInResultImpl, content, ai_LookupInResult_content, ZEND_ACC_PUBLIC)
    PHP_ME(LookupInResultImpl, exists, ai_LookupInResult_exists, ZEND_ACC_PUBLIC)
    PHP_ME(LookupInResultImpl, status, ai_LookupInResult_status, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

zend_class_entry *pcbc_lookup_in_result_entry_ce;
static const zend_function_entry pcbc_lookup_in_result_entry_methods[] = {
    PHP_FE_END
};

ZEND_BEGIN_ARG_INFO_EX(ai_MutateInResult_content, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, index, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_MutateInResult_status, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, index, IS_LONG, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_mutate_in_result_ce;
static const zend_function_entry pcbc_mutate_in_result_methods[] = {
    PHP_ABSTRACT_ME(MutateInResult, content, ai_MutateInResult_content)
    PHP_FE_END
};

PHP_METHOD(MutateInResultImpl, cas);
PHP_METHOD(MutateInResultImpl, expiry);
PHP_METHOD(MutateInResultImpl, mutationToken);
PHP_METHOD(MutateInResultImpl, content);
PHP_METHOD(MutateInResultImpl, status);

zend_class_entry *pcbc_mutate_in_result_impl_ce;
static const zend_function_entry pcbc_mutate_in_result_impl_methods[] = {
    PHP_ME(MutateInResultImpl, cas, ai_Result_cas, ZEND_ACC_PUBLIC)
    PHP_ME(MutateInResultImpl, expiry, ai_Result_expiry, ZEND_ACC_PUBLIC)
    PHP_ME(MutateInResultImpl, mutationToken, ai_MutationResult_mutationToken, ZEND_ACC_PUBLIC)
    PHP_ME(MutateInResultImpl, content, ai_MutateInResult_content, ZEND_ACC_PUBLIC)
    PHP_ME(MutateInResultImpl, status, ai_MutateInResult_status, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

zend_class_entry *pcbc_mutate_in_result_entry_ce;
static const zend_function_entry pcbc_mutate_in_result_entry_methods[] = {
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_QueryResult_metaData, Couchbase\\QueryMetaData, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_QueryResult_rows, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_query_result_ce;
static const zend_function_entry pcbc_query_result_methods[] = {
    PHP_ABSTRACT_ME(QueryResult, metaData, ai_QueryResult_metaData)
    PHP_ABSTRACT_ME(QueryResult, rows, ai_QueryResult_rows)
    PHP_FE_END
};

PHP_METHOD(QueryResultImpl, metaData);
PHP_METHOD(QueryResultImpl, rows);

zend_class_entry *pcbc_query_result_impl_ce;
static const zend_function_entry pcbc_query_result_impl_methods[] = {
    PHP_ME(QueryResultImpl, metaData, ai_QueryResult_metaData, ZEND_ACC_PUBLIC)
    PHP_ME(QueryResultImpl, rows, ai_QueryResult_rows, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_AnalyticsResult_metaData, Couchbase\\QueryMetaData, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_AnalyticsResult_rows, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_analytics_result_ce;
static const zend_function_entry pcbc_analytics_result_methods[] = {
    PHP_ABSTRACT_ME(AnalyticsResult, metaData, ai_AnalyticsResult_metaData)
    PHP_ABSTRACT_ME(AnalyticsResult, rows, ai_AnalyticsResult_rows)
    PHP_FE_END
};

PHP_METHOD(AnalyticsResultImpl, metaData);
PHP_METHOD(AnalyticsResultImpl, rows);

zend_class_entry *pcbc_analytics_result_impl_ce;
static const zend_function_entry pcbc_analytics_result_impl_methods[] = {
    PHP_ME(AnalyticsResultImpl, metaData, ai_AnalyticsResult_metaData, ZEND_ACC_PUBLIC)
    PHP_ME(AnalyticsResultImpl, rows, ai_AnalyticsResult_rows, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchFacetResult_field, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchFacetResult_total, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchFacetResult_missing, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchFacetResult_other, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchFacetResult_terms, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchFacetResult_numericRanges, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchFacetResult_dateRanges, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_search_facet_result_ce;
static const zend_function_entry pcbc_search_facet_result_methods[] = {
    PHP_ABSTRACT_ME(SearchFacetResult, field, ai_SearchFacetResult_field)
    PHP_ABSTRACT_ME(SearchFacetResult, total, ai_SearchFacetResult_total)
    PHP_ABSTRACT_ME(SearchFacetResult, missing, ai_SearchFacetResult_missing)
    PHP_ABSTRACT_ME(SearchFacetResult, other, ai_SearchFacetResult_other)
    PHP_ABSTRACT_ME(SearchFacetResult, terms, ai_SearchFacetResult_terms)
    PHP_ABSTRACT_ME(SearchFacetResult, numericRanges, ai_SearchFacetResult_numericRanges)
    PHP_ABSTRACT_ME(SearchFacetResult, dateRanges, ai_SearchFacetResult_dateRanges)
    PHP_FE_END
};

PHP_METHOD(SearchFacetImplResult, field);
PHP_METHOD(SearchFacetImplResult, total);
PHP_METHOD(SearchFacetImplResult, missing);
PHP_METHOD(SearchFacetImplResult, other);
PHP_METHOD(SearchFacetImplResult, terms);
PHP_METHOD(SearchFacetImplResult, numericRanges);
PHP_METHOD(SearchFacetImplResult, dateRanges);

zend_class_entry *pcbc_search_facet_result_impl_ce;
static const zend_function_entry pcbc_search_facet_result_impl_methods[] = {
    PHP_ME(SearchFacetImplResult, field, ai_SearchFacetResult_field, ZEND_ACC_PUBLIC)
    PHP_ME(SearchFacetImplResult, total, ai_SearchFacetResult_total, ZEND_ACC_PUBLIC)
    PHP_ME(SearchFacetImplResult, missing, ai_SearchFacetResult_missing, ZEND_ACC_PUBLIC)
    PHP_ME(SearchFacetImplResult, other, ai_SearchFacetResult_other, ZEND_ACC_PUBLIC)
    PHP_ME(SearchFacetImplResult, terms, ai_SearchFacetResult_terms, ZEND_ACC_PUBLIC)
    PHP_ME(SearchFacetImplResult, numericRanges, ai_SearchFacetResult_numericRanges, ZEND_ACC_PUBLIC)
    PHP_ME(SearchFacetImplResult, dateRanges, ai_SearchFacetResult_dateRanges, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_TermFacetResult_term, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_TermFacetResult_count, IS_LONG, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_term_facet_result_ce;
static const zend_function_entry pcbc_term_facet_result_methods[] = {
    PHP_ABSTRACT_ME(TermFacetResult, term, ai_TermFacetResult_term)
    PHP_ABSTRACT_ME(TermFacetResult, count, ai_TermFacetResult_count)
    PHP_FE_END
};

PHP_METHOD(TermFacetImplResult, term);
PHP_METHOD(TermFacetImplResult, count);

zend_class_entry *pcbc_term_facet_result_impl_ce;
static const zend_function_entry pcbc_term_facet_result_impl_methods[] = {
    PHP_ME(TermFacetImplResult, term, ai_TermFacetResult_term, ZEND_ACC_PUBLIC)
    PHP_ME(TermFacetImplResult, count, ai_TermFacetResult_count, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_NumericRangeFacetResult_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_NumericRangeFacetResult_min, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(ai_NumericRangeFacetResult_max, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_NumericRangeFacetResult_count, IS_LONG, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_numeric_range_facet_result_ce;
static const zend_function_entry pcbc_numeric_range_facet_result_methods[] = {
    PHP_ABSTRACT_ME(NumericRangeFacetResult, name, ai_NumericRangeFacetResult_name)
    PHP_ABSTRACT_ME(NumericRangeFacetResult, min, ai_NumericRangeFacetResult_min)
    PHP_ABSTRACT_ME(NumericRangeFacetResult, max, ai_NumericRangeFacetResult_max)
    PHP_ABSTRACT_ME(NumericRangeFacetResult, count, ai_NumericRangeFacetResult_count)
    PHP_FE_END
};

PHP_METHOD(NumericRangeFacetImplResult, name);
PHP_METHOD(NumericRangeFacetImplResult, min);
PHP_METHOD(NumericRangeFacetImplResult, max);
PHP_METHOD(NumericRangeFacetImplResult, count);

zend_class_entry *pcbc_numeric_range_facet_result_impl_ce;
static const zend_function_entry pcbc_numeric_range_facet_result_impl_methods[] = {
    PHP_ME(NumericRangeFacetImplResult, name, ai_NumericRangeFacetResult_name, ZEND_ACC_PUBLIC)
    PHP_ME(NumericRangeFacetImplResult, min, ai_NumericRangeFacetResult_min, ZEND_ACC_PUBLIC)
    PHP_ME(NumericRangeFacetImplResult, max, ai_NumericRangeFacetResult_max, ZEND_ACC_PUBLIC)
    PHP_ME(NumericRangeFacetImplResult, count, ai_NumericRangeFacetResult_count, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_DateRangeFacetResult_name, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_DateRangeFacetResult_start, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_DateRangeFacetResult_end, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_DateRangeFacetResult_count, IS_LONG, 0)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_date_range_facet_result_ce;
static const zend_function_entry pcbc_date_range_facet_result_methods[] = {
    PHP_ABSTRACT_ME(DateRangeFacetResult, name, ai_DateRangeFacetResult_name)
    PHP_ABSTRACT_ME(DateRangeFacetResult, start, ai_DateRangeFacetResult_start)
    PHP_ABSTRACT_ME(DateRangeFacetResult, end, ai_DateRangeFacetResult_end)
    PHP_ABSTRACT_ME(DateRangeFacetResult, count, ai_DateRangeFacetResult_count)
    PHP_FE_END
};

PHP_METHOD(DateRangeFacetImplResult, name);
PHP_METHOD(DateRangeFacetImplResult, start);
PHP_METHOD(DateRangeFacetImplResult, end);
PHP_METHOD(DateRangeFacetImplResult, count);

zend_class_entry *pcbc_date_range_facet_result_impl_ce;
static const zend_function_entry pcbc_date_range_facet_result_impl_methods[] = {
    PHP_ME(DateRangeFacetImplResult, name, ai_DateRangeFacetResult_name, ZEND_ACC_PUBLIC)
    PHP_ME(DateRangeFacetImplResult, start, ai_DateRangeFacetResult_start, ZEND_ACC_PUBLIC)
    PHP_ME(DateRangeFacetImplResult, end, ai_DateRangeFacetResult_end, ZEND_ACC_PUBLIC)
    PHP_ME(DateRangeFacetImplResult, count, ai_DateRangeFacetResult_count, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_SearchResult_metaData, Couchbase\\SearchMetaData, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchResult_facets, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_SearchResult_rows, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_search_result_ce;
static const zend_function_entry pcbc_search_result_methods[] = {
    PHP_ABSTRACT_ME(SearchResult, facets, ai_SearchResult_facets)
    PHP_ABSTRACT_ME(SearchResult, metaData, ai_SearchResult_metaData)
    PHP_ABSTRACT_ME(SearchResult, rows, ai_SearchResult_rows)
    PHP_FE_END
};

PHP_METHOD(SearchResultImpl, metaData);
PHP_METHOD(SearchResultImpl, facets);
PHP_METHOD(SearchResultImpl, rows);

zend_class_entry *pcbc_search_result_impl_ce;
static const zend_function_entry pcbc_search_result_impl_methods[] = {
    PHP_ME(SearchResultImpl, metaData, ai_SearchResult_metaData, ZEND_ACC_PUBLIC)
    PHP_ME(SearchResultImpl, facets, ai_SearchResult_facets, ZEND_ACC_PUBLIC)
    PHP_ME(SearchResultImpl, rows, ai_SearchResult_rows, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO(ai_ViewResult_metaData, Couchbase\\ViewMetaData, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_ViewResult_rows, IS_ARRAY, 1)
ZEND_END_ARG_INFO()

zend_class_entry *pcbc_view_result_ce;
static const zend_function_entry pcbc_view_result_methods[] = {
    PHP_ABSTRACT_ME(ViewResult, metaData, ai_ViewResult_metaData)
    PHP_ABSTRACT_ME(ViewResult, rows, ai_ViewResult_rows)
    PHP_FE_END
};

PHP_METHOD(ViewResultImpl, metaData);
PHP_METHOD(ViewResultImpl, rows);

zend_class_entry *pcbc_view_result_impl_ce;
static const zend_function_entry pcbc_view_result_impl_methods[] = {
    PHP_ME(ViewResultImpl, metaData, ai_ViewResult_metaData, ZEND_ACC_PUBLIC)
    PHP_ME(ViewResultImpl, rows, ai_ViewResult_rows, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(ai_ViewRow_id, IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(ai_ViewRow_key, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(ai_ViewRow_value, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(ai_ViewRow_document, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(ViewRow, id);
PHP_METHOD(ViewRow, key);
PHP_METHOD(ViewRow, value);
PHP_METHOD(ViewRow, document);

zend_class_entry *pcbc_view_result_entry_ce;
static const zend_function_entry pcbc_view_result_entry_methods[] = {
    PHP_ME(ViewRow, id, ai_ViewRow_id, ZEND_ACC_PUBLIC)
    PHP_ME(ViewRow, key, ai_ViewRow_key, ZEND_ACC_PUBLIC)
    PHP_ME(ViewRow, value, ai_ViewRow_value, ZEND_ACC_PUBLIC)
    PHP_ME(ViewRow, document, ai_ViewRow_document, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

// clang-format on

PHP_MINIT_FUNCTION(Result)
{
    zend_class_entry ce;

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutationToken", pcbc_mutation_token_methods);
    pcbc_mutation_token_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutationTokenImpl", pcbc_mutation_token_impl_methods);
    pcbc_mutation_token_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_mutation_token_impl_ce, 1, pcbc_mutation_token_ce);
    zend_declare_property_null(pcbc_mutation_token_impl_ce, ZEND_STRL("partition_id"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutation_token_impl_ce, ZEND_STRL("partition_uuid"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutation_token_impl_ce, ZEND_STRL("sequence_number"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutation_token_impl_ce, ZEND_STRL("bucket_name"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "QueryMetaData", pcbc_query_meta_data_methods);
    pcbc_query_meta_data_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "QueryMetaDataImpl", pcbc_query_meta_data_impl_methods);
    pcbc_query_meta_data_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_query_meta_data_impl_ce, 1, pcbc_query_meta_data_ce);
    zend_declare_property_null(pcbc_query_meta_data_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_query_meta_data_impl_ce, ZEND_STRL("request_id"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_query_meta_data_impl_ce, ZEND_STRL("client_context_id"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_query_meta_data_impl_ce, ZEND_STRL("signature"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_query_meta_data_impl_ce, ZEND_STRL("errors"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_query_meta_data_impl_ce, ZEND_STRL("warnings"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_query_meta_data_impl_ce, ZEND_STRL("metrics"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchMetaData", pcbc_search_meta_data_methods);
    pcbc_search_meta_data_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchMetaDataImpl", pcbc_search_meta_data_impl_methods);
    pcbc_search_meta_data_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_search_meta_data_impl_ce, 1, pcbc_search_meta_data_ce);
    zend_declare_property_null(pcbc_search_meta_data_impl_ce, ZEND_STRL("success_count"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_meta_data_impl_ce, ZEND_STRL("error_count"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_meta_data_impl_ce, ZEND_STRL("took"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_meta_data_impl_ce, ZEND_STRL("total_hits"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_meta_data_impl_ce, ZEND_STRL("max_score"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_meta_data_impl_ce, ZEND_STRL("metrics"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_meta_data_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ViewMetaData", pcbc_view_meta_data_methods);
    pcbc_view_meta_data_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ViewMetaDataImpl", pcbc_view_meta_data_impl_methods);
    pcbc_view_meta_data_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_view_meta_data_impl_ce, 1, pcbc_view_meta_data_ce);
    zend_declare_property_null(pcbc_view_meta_data_impl_ce, ZEND_STRL("total_rows"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_view_meta_data_impl_ce, ZEND_STRL("debug"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "Result", pcbc_result_methods);
    pcbc_result_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ResultImpl", pcbc_result_impl_methods);
    pcbc_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_result_impl_ce, 1, pcbc_result_ce);
    zend_declare_property_null(pcbc_result_impl_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_result_impl_ce, ZEND_STRL("expiry"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_result_impl_ce, ZEND_STRL("key"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_result_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_result_impl_ce, ZEND_STRL("err_ctx"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_result_impl_ce, ZEND_STRL("err_ref"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GetResult", pcbc_get_result_methods);
    pcbc_get_result_ce = zend_register_internal_interface(&ce);
    zend_class_implements(pcbc_get_result_ce, 1, pcbc_result_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GetResultImpl", pcbc_get_result_impl_methods);
    pcbc_get_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_get_result_impl_ce, 1, pcbc_get_result_ce);
    zend_declare_property_null(pcbc_get_result_impl_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_result_impl_ce, ZEND_STRL("data"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_result_impl_ce, ZEND_STRL("expiry"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_result_impl_ce, ZEND_STRL("key"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_result_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_result_impl_ce, ZEND_STRL("err_ctx"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_result_impl_ce, ZEND_STRL("err_ref"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_result_impl_ce, ZEND_STRL("decoder"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GetReplicaResult", pcbc_get_replica_result_methods);
    pcbc_get_replica_result_ce = zend_register_internal_interface(&ce);
    zend_class_implements(pcbc_get_replica_result_ce, 1, pcbc_result_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "GetReplicaResultImpl", pcbc_get_replica_result_impl_methods);
    pcbc_get_replica_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_get_replica_result_impl_ce, 1, pcbc_get_replica_result_ce);
    zend_declare_property_null(pcbc_get_replica_result_impl_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_replica_result_impl_ce, ZEND_STRL("data"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_replica_result_impl_ce, ZEND_STRL("expiry"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_replica_result_impl_ce, ZEND_STRL("key"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_replica_result_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_replica_result_impl_ce, ZEND_STRL("err_ctx"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_replica_result_impl_ce, ZEND_STRL("err_ref"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_replica_result_impl_ce, ZEND_STRL("is_replica"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_get_result_impl_ce, ZEND_STRL("decoder"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ExistsResult", pcbc_exists_result_methods);
    pcbc_exists_result_ce = zend_register_internal_interface(&ce);
    zend_class_implements(pcbc_exists_result_ce, 1, pcbc_result_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ExistsResultImpl", pcbc_exists_result_impl_methods);
    pcbc_exists_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_exists_result_impl_ce, 1, pcbc_exists_result_ce);
    zend_declare_property_null(pcbc_exists_result_impl_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_exists_result_impl_ce, ZEND_STRL("expiry"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_exists_result_impl_ce, ZEND_STRL("key"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_exists_result_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_exists_result_impl_ce, ZEND_STRL("err_ctx"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_exists_result_impl_ce, ZEND_STRL("err_ref"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_exists_result_impl_ce, ZEND_STRL("is_found"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutationResult", pcbc_mutation_result_methods);
    pcbc_mutation_result_ce = zend_register_internal_interface(&ce);
    zend_class_implements(pcbc_mutation_result_ce, 1, pcbc_result_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutationResultImpl", pcbc_mutation_result_impl_methods);
    pcbc_mutation_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_mutation_result_impl_ce, 1, pcbc_mutation_result_ce);
    zend_declare_property_null(pcbc_mutation_result_impl_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutation_result_impl_ce, ZEND_STRL("expiry"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutation_result_impl_ce, ZEND_STRL("key"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutation_result_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutation_result_impl_ce, ZEND_STRL("err_ctx"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutation_result_impl_ce, ZEND_STRL("err_ref"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutation_result_impl_ce, ZEND_STRL("mutation_token"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "StoreResultImpl", pcbc_store_result_impl_methods);
    pcbc_store_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_store_result_impl_ce, 1, pcbc_mutation_result_ce);
    zend_declare_property_null(pcbc_store_result_impl_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_store_result_impl_ce, ZEND_STRL("expiry"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_store_result_impl_ce, ZEND_STRL("key"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_store_result_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_store_result_impl_ce, ZEND_STRL("err_ctx"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_store_result_impl_ce, ZEND_STRL("err_ref"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_store_result_impl_ce, ZEND_STRL("mutation_token"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_store_result_impl_ce, ZEND_STRL("is_stored"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_store_result_impl_ce, ZEND_STRL("num_persisted"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_store_result_impl_ce, ZEND_STRL("num_replicated"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "CounterResult", pcbc_counter_result_methods);
    pcbc_counter_result_ce = zend_register_internal_interface(&ce);
    zend_class_implements(pcbc_counter_result_ce, 1, pcbc_mutation_result_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "CounterResultImpl", pcbc_counter_result_impl_methods);
    pcbc_counter_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_counter_result_impl_ce, 1, pcbc_counter_result_ce);
    zend_declare_property_null(pcbc_counter_result_impl_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_counter_result_impl_ce, ZEND_STRL("expiry"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_counter_result_impl_ce, ZEND_STRL("key"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_counter_result_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_counter_result_impl_ce, ZEND_STRL("err_ctx"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_counter_result_impl_ce, ZEND_STRL("err_ref"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_counter_result_impl_ce, ZEND_STRL("mutation_token"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_counter_result_impl_ce, ZEND_STRL("content"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "LookupInResult", pcbc_lookup_in_result_methods);
    pcbc_lookup_in_result_ce = zend_register_internal_interface(&ce);
    zend_class_implements(pcbc_lookup_in_result_ce, 1, pcbc_result_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "LookupInResultImpl", pcbc_lookup_in_result_impl_methods);
    pcbc_lookup_in_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_lookup_in_result_impl_ce, 1, pcbc_lookup_in_result_ce);
    zend_declare_property_null(pcbc_lookup_in_result_impl_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_lookup_in_result_impl_ce, ZEND_STRL("expiry"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_lookup_in_result_impl_ce, ZEND_STRL("key"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_lookup_in_result_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_lookup_in_result_impl_ce, ZEND_STRL("err_ctx"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_lookup_in_result_impl_ce, ZEND_STRL("err_ref"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_lookup_in_result_impl_ce, ZEND_STRL("data"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "LookupInResultEntry", pcbc_lookup_in_result_entry_methods);
    pcbc_lookup_in_result_entry_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_lookup_in_result_entry_ce, ZEND_STRL("code"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_lookup_in_result_entry_ce, ZEND_STRL("value"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutateInResult", pcbc_mutate_in_result_methods);
    pcbc_mutate_in_result_ce = zend_register_internal_interface(&ce);
    zend_class_implements(pcbc_mutate_in_result_ce, 1, pcbc_mutation_result_ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutateInResultImpl", pcbc_mutate_in_result_impl_methods);
    pcbc_mutate_in_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_mutate_in_result_impl_ce, 1, pcbc_mutate_in_result_ce);
    zend_declare_property_null(pcbc_mutate_in_result_impl_ce, ZEND_STRL("cas"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_in_result_impl_ce, ZEND_STRL("expiry"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_in_result_impl_ce, ZEND_STRL("key"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_in_result_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_in_result_impl_ce, ZEND_STRL("err_ctx"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_in_result_impl_ce, ZEND_STRL("err_ref"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_in_result_impl_ce, ZEND_STRL("mutation_token"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_in_result_impl_ce, ZEND_STRL("data"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "MutateInResultEntry", pcbc_mutate_in_result_entry_methods);
    pcbc_mutate_in_result_entry_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_mutate_in_result_entry_ce, ZEND_STRL("code"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_mutate_in_result_entry_ce, ZEND_STRL("value"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "QueryResult", pcbc_query_result_methods);
    pcbc_query_result_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "QueryResultImpl", pcbc_query_result_impl_methods);
    pcbc_query_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_query_result_impl_ce, 1, pcbc_query_result_ce);
    zend_declare_property_null(pcbc_query_result_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_query_result_impl_ce, ZEND_STRL("meta"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_query_result_impl_ce, ZEND_STRL("rows"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "AnalyticsResult", pcbc_analytics_result_methods);
    pcbc_analytics_result_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "AnalyticsResultImpl", pcbc_analytics_result_impl_methods);
    pcbc_analytics_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_analytics_result_impl_ce, 1, pcbc_analytics_result_ce);
    zend_declare_property_null(pcbc_analytics_result_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_analytics_result_impl_ce, ZEND_STRL("meta"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_analytics_result_impl_ce, ZEND_STRL("rows"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchFacetResult", pcbc_search_facet_result_methods);
    pcbc_search_facet_result_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchFacetResultImpl", pcbc_search_facet_result_impl_methods);
    pcbc_search_facet_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_search_facet_result_impl_ce, 1, pcbc_search_facet_result_ce);
    zend_declare_property_null(pcbc_search_facet_result_impl_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_facet_result_impl_ce, ZEND_STRL("field"), ZEND_ACC_PRIVATE);
    zend_declare_property_long(pcbc_search_facet_result_impl_ce, ZEND_STRL("total"), 0, ZEND_ACC_PRIVATE);
    zend_declare_property_long(pcbc_search_facet_result_impl_ce, ZEND_STRL("missing"), 0, ZEND_ACC_PRIVATE);
    zend_declare_property_long(pcbc_search_facet_result_impl_ce, ZEND_STRL("other"), 0, ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_facet_result_impl_ce, ZEND_STRL("terms"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_facet_result_impl_ce, ZEND_STRL("numeric_ranges"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_facet_result_impl_ce, ZEND_STRL("date_ranges"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "TermFacetResult", pcbc_term_facet_result_methods);
    pcbc_term_facet_result_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "TermFacetResultImpl", pcbc_term_facet_result_impl_methods);
    pcbc_term_facet_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_term_facet_result_impl_ce, 1, pcbc_term_facet_result_ce);
    zend_declare_property_null(pcbc_term_facet_result_impl_ce, ZEND_STRL("term"), ZEND_ACC_PRIVATE);
    zend_declare_property_long(pcbc_term_facet_result_impl_ce, ZEND_STRL("count"), 0, ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "NumericRangeFacetResult", pcbc_numeric_range_facet_result_methods);
    pcbc_numeric_range_facet_result_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "NumericRangeFacetResultImpl", pcbc_numeric_range_facet_result_impl_methods);
    pcbc_numeric_range_facet_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_numeric_range_facet_result_impl_ce, 1, pcbc_numeric_range_facet_result_ce);
    zend_declare_property_null(pcbc_numeric_range_facet_result_impl_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_numeric_range_facet_result_impl_ce, ZEND_STRL("min"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_numeric_range_facet_result_impl_ce, ZEND_STRL("max"), ZEND_ACC_PRIVATE);
    zend_declare_property_long(pcbc_numeric_range_facet_result_impl_ce, ZEND_STRL("count"), 0, ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DateRangeFacetResult", pcbc_date_range_facet_result_methods);
    pcbc_date_range_facet_result_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "DateRangeFacetResultImpl", pcbc_date_range_facet_result_impl_methods);
    pcbc_date_range_facet_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_date_range_facet_result_impl_ce, 1, pcbc_date_range_facet_result_ce);
    zend_declare_property_null(pcbc_date_range_facet_result_impl_ce, ZEND_STRL("name"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_date_range_facet_result_impl_ce, ZEND_STRL("start"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_date_range_facet_result_impl_ce, ZEND_STRL("end"), ZEND_ACC_PRIVATE);
    zend_declare_property_long(pcbc_date_range_facet_result_impl_ce, ZEND_STRL("count"), 0, ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchResult", pcbc_search_result_methods);
    pcbc_search_result_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "SearchResultImpl", pcbc_search_result_impl_methods);
    pcbc_search_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_search_result_impl_ce, 1, pcbc_search_result_ce);
    zend_declare_property_null(pcbc_search_result_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_result_impl_ce, ZEND_STRL("meta"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_result_impl_ce, ZEND_STRL("facets"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_search_result_impl_ce, ZEND_STRL("rows"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ViewResult", pcbc_view_result_methods);
    pcbc_view_result_ce = zend_register_internal_interface(&ce);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ViewResultImpl", pcbc_view_result_impl_methods);
    pcbc_view_result_impl_ce = zend_register_internal_class(&ce);
    zend_class_implements(pcbc_view_result_impl_ce, 1, pcbc_view_result_ce);
    zend_declare_property_null(pcbc_view_result_impl_ce, ZEND_STRL("status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_view_result_impl_ce, ZEND_STRL("http_status"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_view_result_impl_ce, ZEND_STRL("body"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_view_result_impl_ce, ZEND_STRL("body_str"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_view_result_impl_ce, ZEND_STRL("meta"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_view_result_impl_ce, ZEND_STRL("rows"), ZEND_ACC_PRIVATE);

    INIT_NS_CLASS_ENTRY(ce, "Couchbase", "ViewRow", pcbc_view_result_entry_methods);
    pcbc_view_result_entry_ce = zend_register_internal_class(&ce);
    zend_declare_property_null(pcbc_view_result_entry_ce, ZEND_STRL("id"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_view_result_entry_ce, ZEND_STRL("key"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_view_result_entry_ce, ZEND_STRL("value"), ZEND_ACC_PRIVATE);
    zend_declare_property_null(pcbc_view_result_entry_ce, ZEND_STRL("document"), ZEND_ACC_PRIVATE);

    return SUCCESS;
}

PHP_METHOD(MutationTokenImpl, partitionId)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_mutation_token_impl_ce, getThis(), ("partition_id"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(MutationTokenImpl, partitionUuid)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_mutation_token_impl_ce, getThis(), ("partition_uuid"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(MutationTokenImpl, sequenceNumber)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_mutation_token_impl_ce, getThis(), ("sequence_number"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(MutationTokenImpl, bucketName)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_mutation_token_impl_ce, getThis(), ("bucket_name"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(ResultImpl, cas)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_result_impl_ce, getThis(), ("cas"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(GetResultImpl, cas)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_get_result_impl_ce, getThis(), ("cas"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(GetResultImpl, expiry)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_get_result_impl_ce, getThis(), ("expiry"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(GetResultImpl, expiryTime)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_get_result_impl_ce, getThis(), ("expiry"), 0, &rv);

    if (prop && Z_TYPE_P(prop) == IS_LONG) {
        zend_long expiry = Z_LVAL_P(prop);
        if (expiry > 0) {
            smart_str buf = {0};
            smart_str_append_printf(&buf, "@%lu", expiry);
            php_date_instantiate(php_date_get_immutable_ce(), return_value);
            php_date_initialize(Z_PHPDATE_P(return_value), ZSTR_VAL(buf.s), ZSTR_LEN(buf.s), NULL, NULL, 0);
            smart_str_free(&buf);
            return;
        }
    }
    RETURN_NULL();
}

PHP_METHOD(GetResultImpl, content)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, *decoder, *flags, *datatype, rv1, rv2, rv3, rv4;
    prop = pcbc_read_property(pcbc_get_result_impl_ce, getThis(), ("data"), 0, &rv1);
    decoder = pcbc_read_property(pcbc_get_result_impl_ce, getThis(), ("decoder"), 0, &rv2);
    flags = pcbc_read_property(pcbc_get_result_impl_ce, getThis(), ("flags"), 0, &rv3);
    datatype = pcbc_read_property(pcbc_get_result_impl_ce, getThis(), ("datatype"), 0, &rv4);
    pcbc_decode_value(decoder, return_value, prop, Z_TYPE_P(flags) == IS_LONG ? Z_LVAL_P(flags) : 0,
                      Z_TYPE_P(datatype) == IS_LONG ? Z_LVAL_P(datatype) : 0);
}

PHP_METHOD(GetReplicaResultImpl, cas)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_get_replica_result_impl_ce, getThis(), ("cas"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(GetReplicaResultImpl, expiry)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_get_replica_result_impl_ce, getThis(), ("expiry"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(GetReplicaResultImpl, content)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, *decoder, *flags, *datatype, rv1, rv2, rv3, rv4;
    prop = pcbc_read_property(pcbc_get_result_impl_ce, getThis(), ("data"), 0, &rv1);
    decoder = pcbc_read_property(pcbc_get_result_impl_ce, getThis(), ("decoder"), 0, &rv2);
    flags = pcbc_read_property(pcbc_get_result_impl_ce, getThis(), ("flags"), 0, &rv3);
    datatype = pcbc_read_property(pcbc_get_result_impl_ce, getThis(), ("datatype"), 0, &rv4);
    pcbc_decode_value(decoder, return_value, prop, Z_TYPE_P(flags) == IS_LONG ? Z_LVAL_P(flags) : 0,
                      Z_TYPE_P(datatype) == IS_LONG ? Z_LVAL_P(datatype) : 0);
}

PHP_METHOD(GetReplicaResultImpl, isReplica)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_get_replica_result_impl_ce, getThis(), ("is_replica"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(ExistsResultImpl, cas)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_exists_result_impl_ce, getThis(), ("cas"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(ExistsResultImpl, expiry)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_exists_result_impl_ce, getThis(), ("expiry"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(ExistsResultImpl, exists)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_exists_result_impl_ce, getThis(), ("is_found"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(MutationResultImpl, cas)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_mutation_result_impl_ce, getThis(), ("cas"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(MutationResultImpl, expiry)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_mutation_result_impl_ce, getThis(), ("expiry"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(MutationResultImpl, mutationToken)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_mutation_result_impl_ce, getThis(), ("mutation_token"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(StoreResultImpl, cas)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_store_result_impl_ce, getThis(), ("cas"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(StoreResultImpl, expiry)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_store_result_impl_ce, getThis(), ("expiry"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(StoreResultImpl, mutationToken)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_store_result_impl_ce, getThis(), ("mutation_token"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(CounterResultImpl, cas)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_counter_result_impl_ce, getThis(), ("cas"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(CounterResultImpl, expiry)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_counter_result_impl_ce, getThis(), ("expiry"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(CounterResultImpl, mutationToken)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_counter_result_impl_ce, getThis(), ("mutation_token"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(CounterResultImpl, content)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_counter_result_impl_ce, getThis(), ("content"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(LookupInResultImpl, cas)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_lookup_in_result_impl_ce, getThis(), ("cas"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(LookupInResultImpl, expiry)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_lookup_in_result_impl_ce, getThis(), ("expiry"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(LookupInResultImpl, expiryTime)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_lookup_in_result_impl_ce, getThis(), ("expiry"), 0, &rv);

    if (prop && Z_TYPE_P(prop) == IS_LONG) {
        zend_long expiry = Z_LVAL_P(prop);
        if (expiry > 0) {
            smart_str buf = {0};
            smart_str_append_printf(&buf, "@%lu", expiry);
            php_date_instantiate(php_date_get_immutable_ce(), return_value);
            php_date_initialize(Z_PHPDATE_P(return_value), ZSTR_VAL(buf.s), ZSTR_LEN(buf.s), NULL, NULL, 0);
            smart_str_free(&buf);
            return;
        }
    }
    RETURN_NULL();
}

PHP_METHOD(LookupInResultImpl, content)
{
    zend_long idx;
    int rc = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &idx);
    if (rc == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1, rv2;
    data = pcbc_read_property(pcbc_lookup_in_result_impl_ce, getThis(), ("data"), 0, &rv1);
    if (idx < zend_hash_num_elements(Z_ARRVAL_P(data))) {
        zval *entry = zend_hash_index_find(Z_ARRVAL_P(data), idx);
        if (Z_OBJCE_P(entry) == pcbc_lookup_in_result_entry_ce) {
            zval *value = pcbc_read_property(pcbc_lookup_in_result_entry_ce, entry, ("value"), 0, &rv2);
            ZVAL_DEREF(value);
            ZVAL_COPY_DEREF(return_value, value);
            return;
        }
    }

    RETURN_NULL();
}

PHP_METHOD(LookupInResultImpl, exists)
{
    zend_long idx;
    int rc = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &idx);
    if (rc == FAILURE) {
        RETURN_NULL();
    }

    zval *data, rv1, rv2;
    data = pcbc_read_property(pcbc_lookup_in_result_impl_ce, getThis(), ("data"), 0, &rv1);
    if (idx < zend_hash_num_elements(Z_ARRVAL_P(data))) {
        zval *entry = zend_hash_index_find(Z_ARRVAL_P(data), idx);
        if (Z_OBJCE_P(entry) == pcbc_lookup_in_result_entry_ce) {
            zval *code = pcbc_read_property(pcbc_lookup_in_result_entry_ce, entry, ("code"), 0, &rv2);
            if (Z_LVAL_P(code) == 0) {
                RETURN_TRUE;
            }
        }
    }
    RETURN_FALSE;
}

PHP_METHOD(LookupInResultImpl, status)
{
    zend_long idx;
    int rc = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &idx);
    if (rc == FAILURE) {
        RETURN_NULL();
    }

    zval *data, rv1, rv2;
    data = pcbc_read_property(pcbc_lookup_in_result_impl_ce, getThis(), ("data"), 0, &rv1);
    if (idx < zend_hash_num_elements(Z_ARRVAL_P(data))) {
        zval *entry = zend_hash_index_find(Z_ARRVAL_P(data), idx);
        if (Z_OBJCE_P(entry) == pcbc_lookup_in_result_entry_ce) {
            zval *code = pcbc_read_property(pcbc_lookup_in_result_entry_ce, entry, ("code"), 0, &rv2);
            ZVAL_DEREF(code);
            ZVAL_COPY_DEREF(return_value, code);
            return;
        }
    }
    RETURN_NULL();
}

PHP_METHOD(MutateInResultImpl, mutationToken)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_mutate_in_result_impl_ce, getThis(), ("mutation_token"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(MutateInResultImpl, cas)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_mutate_in_result_impl_ce, getThis(), ("cas"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(MutateInResultImpl, expiry)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_mutate_in_result_impl_ce, getThis(), ("expiry"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(MutateInResultImpl, content)
{
    zend_long idx;
    int rc = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &idx);
    if (rc == FAILURE) {
        RETURN_NULL();
    }
    zval *data, rv1, rv2;
    data = pcbc_read_property(pcbc_mutate_in_result_impl_ce, getThis(), ("data"), 0, &rv1);
    if (idx < zend_hash_num_elements(Z_ARRVAL_P(data))) {
        zval *entry = zend_hash_index_find(Z_ARRVAL_P(data), idx);
        if (Z_OBJCE_P(entry) == pcbc_mutate_in_result_entry_ce) {
            zval *value = pcbc_read_property(pcbc_mutate_in_result_entry_ce, entry, ("value"), 0, &rv2);
            ZVAL_DEREF(value);
            ZVAL_COPY_DEREF(return_value, value);
            return;
        }
    }

    RETURN_NULL();
}

PHP_METHOD(MutateInResultImpl, status)
{
    zend_long idx;
    int rc = zend_parse_parameters_throw(ZEND_NUM_ARGS(), "l", &idx);
    if (rc == FAILURE) {
        RETURN_NULL();
    }

    zval *data, rv1, rv2;
    data = pcbc_read_property(pcbc_mutate_in_result_impl_ce, getThis(), ("data"), 0, &rv1);
    if (idx < zend_hash_num_elements(Z_ARRVAL_P(data))) {
        zval *entry = zend_hash_index_find(Z_ARRVAL_P(data), idx);
        if (Z_OBJCE_P(entry) == pcbc_mutate_in_result_entry_ce) {
            zval *code = pcbc_read_property(pcbc_mutate_in_result_entry_ce, entry, ("code"), 0, &rv2);
            ZVAL_DEREF(code);
            ZVAL_COPY_DEREF(return_value, code);
            return;
        }
    }
    RETURN_NULL();
}

PHP_METHOD(QueryResultImpl, metaData)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_query_result_impl_ce, getThis(), ("meta"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(QueryResultImpl, rows)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_query_result_impl_ce, getThis(), ("rows"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(QueryMetaDataImpl, status)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_query_meta_data_impl_ce, getThis(), ("status"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(QueryMetaDataImpl, requestId)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_query_meta_data_impl_ce, getThis(), ("request_id"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(QueryMetaDataImpl, clientContextId)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_query_meta_data_impl_ce, getThis(), ("client_context_id"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(QueryMetaDataImpl, signature)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_query_meta_data_impl_ce, getThis(), ("signature"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(QueryMetaDataImpl, errors)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_query_meta_data_impl_ce, getThis(), ("errors"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(QueryMetaDataImpl, warnings)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_query_meta_data_impl_ce, getThis(), ("warnings"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(QueryMetaDataImpl, metrics)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_query_meta_data_impl_ce, getThis(), ("metrics"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(QueryMetaDataImpl, profile)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_query_meta_data_impl_ce, getThis(), ("profile"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(AnalyticsResultImpl, metaData)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_analytics_result_impl_ce, getThis(), ("meta"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(AnalyticsResultImpl, rows)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_analytics_result_impl_ce, getThis(), ("rows"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchMetaDataImpl, successCount)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_meta_data_impl_ce, getThis(), ("success_count"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchMetaDataImpl, errorCount)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_meta_data_impl_ce, getThis(), ("error_count"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchMetaDataImpl, took)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_meta_data_impl_ce, getThis(), ("took"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchMetaDataImpl, totalHits)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_meta_data_impl_ce, getThis(), ("total_hits"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchMetaDataImpl, maxScore)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_meta_data_impl_ce, getThis(), ("max_score"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchMetaDataImpl, metrics)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_meta_data_impl_ce, getThis(), ("metrics"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchResultImpl, metaData)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_result_impl_ce, getThis(), ("meta"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchResultImpl, facets)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_result_impl_ce, getThis(), ("facets"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchResultImpl, rows)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_result_impl_ce, getThis(), ("rows"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(ViewMetaDataImpl, totalRows)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_view_meta_data_impl_ce, getThis(), ("total_rows"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(ViewMetaDataImpl, debug)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_view_meta_data_impl_ce, getThis(), ("debug"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(ViewResultImpl, rows)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_view_result_impl_ce, getThis(), ("rows"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(ViewResultImpl, metaData)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_view_result_impl_ce, getThis(), ("meta"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(ViewRow, id)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_view_result_entry_ce, getThis(), ("id"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(ViewRow, key)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_view_result_entry_ce, getThis(), ("key"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(ViewRow, value)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_view_result_entry_ce, getThis(), ("value"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(ViewRow, document)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_view_result_entry_ce, getThis(), ("document"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchFacetImplResult, field)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_facet_result_impl_ce, getThis(), ("field"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchFacetImplResult, total)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_facet_result_impl_ce, getThis(), ("total"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchFacetImplResult, missing)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_facet_result_impl_ce, getThis(), ("missing"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchFacetImplResult, other)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_facet_result_impl_ce, getThis(), ("other"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchFacetImplResult, terms)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_facet_result_impl_ce, getThis(), ("terms"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchFacetImplResult, numericRanges)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_facet_result_impl_ce, getThis(), ("numeric_ranges"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(SearchFacetImplResult, dateRanges)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_search_facet_result_impl_ce, getThis(), ("date_ranges"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(TermFacetImplResult, term)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_term_facet_result_impl_ce, getThis(), ("term"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(TermFacetImplResult, count)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_term_facet_result_impl_ce, getThis(), ("count"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(NumericRangeFacetImplResult, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_numeric_range_facet_result_impl_ce, getThis(), ("name"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(NumericRangeFacetImplResult, min)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_numeric_range_facet_result_impl_ce, getThis(), ("min"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(NumericRangeFacetImplResult, max)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_numeric_range_facet_result_impl_ce, getThis(), ("max"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(NumericRangeFacetImplResult, count)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_numeric_range_facet_result_impl_ce, getThis(), ("count"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(DateRangeFacetImplResult, name)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_date_range_facet_result_impl_ce, getThis(), ("name"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(DateRangeFacetImplResult, start)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_date_range_facet_result_impl_ce, getThis(), ("start"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(DateRangeFacetImplResult, end)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_date_range_facet_result_impl_ce, getThis(), ("end"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

PHP_METHOD(DateRangeFacetImplResult, count)
{
    if (zend_parse_parameters_none_throw() == FAILURE) {
        return;
    }

    zval *prop, rv;
    prop = pcbc_read_property(pcbc_date_range_facet_result_impl_ce, getThis(), ("count"), 0, &rv);
    ZVAL_COPY_DEREF(return_value, prop);
}

/*
 * vim: et ts=4 sw=4 sts=4
 */
