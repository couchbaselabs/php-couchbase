<?php declare(strict_types=1);

use \PHPUnit\Framework\TestCase;

use \Couchbase\ClusterOptions;
use \Couchbase\Cluster;
use \Couchbase\SearchOptions;
use \Couchbase\MatchSearchQuery;

/**
 * The tests are relying on FTS index for travel-sample bucket exists.
 * See JSON definition of this index in the end of this file.
 */
class SearchCollectionsTest extends TestCase {
    public function setUp(): void {
        $testDSN = getenv('CB_DSN');
        if ($testDSN === FALSE) {
            $testDSN = 'couchbase://localhost/';
        }
        $options = new ClusterOptions();
        $options->credentials(getenv('CB_USER'), getenv('CB_PASSWORD'));
        $this->cluster = new Cluster($testDSN, $options);
    }

    public function testSearchWithCollections() {
        $query = new MatchSearchQuery("air");
        $options = new SearchOptions();
        $options->limit(15);
        $options->collections(["landmark", "hotel"]);

        $result = $this->cluster->searchQuery("travel-search", $query, $options);

        $this->assertNotNull($result);
        $this->assertNotEmpty($result->rows());
        $this->assertCount(9, $result->rows());
        $this->assertEquals(9, $result->metaData()->totalHits());

        foreach ($result->rows() as $hit) {
            $this->assertNotNull($hit['id']);
            $this->assertStringStartsWith("travel-search", $hit['index']);
            $this->assertGreaterThan(0, $hit['score']);
        }
    }
}

/*
{
  "type": "fulltext-index",
  "name": "travel-search",
  "uuid": "5a33ffb4d2627bbe",
  "sourceType": "gocbcore",
  "sourceName": "travel-sample",
  "sourceUUID": "5b29254f448b2599a3ab6fafc4ca75d2",
  "planParams": {
    "maxPartitionsPerPIndex": 1024,
    "indexPartitions": 1
  },
  "params": {
    "doc_config": {
      "docid_prefix_delim": "",
      "docid_regexp": "",
      "mode": "scope.collection.type_field",
      "type_field": "type"
    },
    "mapping": {
      "analysis": {},
      "default_analyzer": "standard",
      "default_datetime_parser": "dateTimeOptional",
      "default_field": "_all",
      "default_mapping": {
        "dynamic": false,
        "enabled": false
      },
      "default_type": "_default",
      "docvalues_dynamic": false,
      "index_dynamic": false,
      "store_dynamic": false,
      "type_field": "_type",
      "types": {
        "inventory.airline": {
          "dynamic": false,
          "enabled": true,
          "properties": {
            "name": {
              "dynamic": false,
              "enabled": true,
              "fields": [
                {
                  "analyzer": "en",
                  "include_in_all": true,
                  "index": true,
                  "name": "name",
                  "type": "text"
                }
              ]
            }
          }
        },
        "inventory.airport": {
          "dynamic": false,
          "enabled": true,
          "properties": {
            "airportname": {
              "dynamic": false,
              "enabled": true,
              "fields": [
                {
                  "analyzer": "en",
                  "include_in_all": true,
                  "index": true,
                  "name": "airportname",
                  "type": "text"
                }
              ]
            }
          }
        },
        "inventory.hotel": {
          "dynamic": false,
          "enabled": true,
          "properties": {
            "name": {
              "dynamic": false,
              "enabled": true,
              "fields": [
                {
                  "analyzer": "en",
                  "include_in_all": true,
                  "index": true,
                  "name": "name",
                  "type": "text"
                }
              ]
            }
          }
        },
        "inventory.landmark": {
          "dynamic": false,
          "enabled": true,
          "properties": {
            "name": {
              "dynamic": false,
              "enabled": true,
              "fields": [
                {
                  "analyzer": "en",
                  "include_in_all": true,
                  "index": true,
                  "name": "name",
                  "type": "text"
                }
              ]
            }
          }
        }
      }
    },
    "store": {
      "indexType": "scorch",
      "segmentVersion": 15
    }
  },
  "sourceParams": {}
}
*/