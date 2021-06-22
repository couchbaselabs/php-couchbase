<?php

$options = new \Couchbase\ClusterOptions();
$options->credentials('Administrator', 'password');
$cluster = new \Couchbase\Cluster('couchbase://localhost', $options);

$dataverse_name = 'testaverse/testascope';
$dataset_name = 'testaset';
$index_name = 'testadex';
$bucket_name = 'travel-sample';

function displayDatasets($datasets) {
    printf("There are %d analytics datasets:\n", count($datasets));
    foreach ($datasets as $dataset) {
        printf("`%s`.%s", $dataset->dataverseName(), $dataset->name());
        printf(" on [%s]", $dataset->bucketName());
        printf(" at [%s]", $dataset->linkName());
        printf("\n");
    }
}

function displayAnalyticsIndexes($indexes) {
    printf("There are %d analytics indexes:\n", count($indexes));
    foreach ($indexes as $index) {
        printf("%s.%s.%s", $index->dataverseName(), $index->datasetName(), $index->name());
        if ($index->isPrimary()) {
            printf(" (primary)");
        }
        printf("\n");
    }
}

function displayPendingMutations($mutations) {
    printf("There are %d dataverses pending mutations:\n", count($mutations));
    foreach ($mutations as $dataverse => $datasets) {
        foreach($datasets as $dataset => $num) {
            printf("%s.%s has %d mutations", $dataverse, $dataset, $num);
        }
    }
    printf("\n");
}


displayDatasets($cluster->analyticsIndexes()->getAllDatasets());

try {
    $options = new \Couchbase\DisconnectAnalyticsLinkOptions();
    $options->dataverseName($dataverse_name);
    $start = microtime(true);
    $cluster->analyticsIndexes()->disconnectLink($options);
    printf("Link has been disconnected in %f seconds\n", microtime(true) - $start);
} catch (Exception $e) {
}

$options = new \Couchbase\DropAnalyticsDataverseOptions();
$options->ignoreIfNotExists(true);
$start = microtime(true);
$cluster->analyticsIndexes()->dropDataverse($dataverse_name, $options);
printf("Dataverse \"%s\" has been dropped in %f seconds\n", $dataverse_name, microtime(true) - $start);

$options = new \Couchbase\CreateAnalyticsDataverseOptions();
$options->ignoreIfExists(true);
$start = microtime(true);
$cluster->analyticsIndexes()->createDataverse($dataverse_name, $options);
printf("Dataverse \"%s\" has been created in %f seconds\n", $dataverse_name, microtime(true) - $start);

$options = new \Couchbase\DropAnalyticsDatasetOptions();
$options->ignoreIfNotExists(true);
$options->dataverseName($dataverse_name);
$start = microtime(true);
$cluster->analyticsIndexes()->dropDataset($dataset_name, $options);
printf("Dataset \"%s\" has been dropped in %f seconds\n", $dataset_name, microtime(true) - $start);

$options = new \Couchbase\CreateAnalyticsDatasetOptions();
$options->ignoreIfExists(true);
$options->dataverseName($dataverse_name);
$start = microtime(true);
$cluster->analyticsIndexes()->createDataset($dataset_name, $bucket_name, $options);
printf("Dataset \"%s\" has been created in %f seconds\n", $dataset_name, microtime(true) - $start);

displayDatasets($cluster->analyticsIndexes()->getAllDatasets());
displayAnalyticsIndexes($cluster->analyticsIndexes()->getAllIndexes());

$options = new \Couchbase\DropAnalyticsIndexOptions();
$options->ignoreIfNotExists(true);
$options->dataverseName($dataverse_name);
$start = microtime(true);
$cluster->analyticsIndexes()->dropIndex($dataset_name, $index_name, $options);
printf("Index \"%s\" has been dropped in %f seconds\n", $index_name, microtime(true) - $start);

$options = new \Couchbase\CreateAnalyticsIndexOptions();
$options->ignoreIfExists(true);
$options->dataverseName($dataverse_name);
$start = microtime(true);
$cluster->analyticsIndexes()->createIndex($dataset_name, $index_name, ["name" => "string"], $options);
printf("Index \"%s\" has been created in %f seconds\n", $index_name, microtime(true) - $start);

displayAnalyticsIndexes($cluster->analyticsIndexes()->getAllIndexes());

$options = new \Couchbase\ConnectAnalyticsLinkOptions();
$options->dataverseName($dataverse_name);
$start = microtime(true);
$cluster->analyticsIndexes()->connectLink($options);
printf("Link has been connected in %f seconds\n", $index_name, microtime(true) - $start);

$options = new \Couchbase\DisconnectAnalyticsLinkOptions();
$options->dataverseName($dataverse_name);
$start = microtime(true);
$cluster->analyticsIndexes()->disconnectLink($options);
printf("Link has been disconnected in %f seconds\n", microtime(true) - $start);

$options = new \Couchbase\ConnectAnalyticsLinkOptions();
$options->dataverseName($dataverse_name);
$options->linkName("Local");
$start = microtime(true);
$cluster->analyticsIndexes()->connectLink($options);
printf("Link has been connected in %f seconds\n", $index_name, microtime(true) - $start);

displayPendingMutations($cluster->analyticsIndexes()->getPendingMutations());
