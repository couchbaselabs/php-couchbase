<?php declare(strict_types=1);

use \PHPUnit\Framework\TestCase;

use \Couchbase\ClusterOptions;
use \Couchbase\Cluster;
use \Couchbase\MutationState;
use \Couchbase\SearchHighlightMode;
use \Couchbase\SearchOptions;
use \Couchbase\ConjunctionSearchQuery;
use \Couchbase\DateRangeSearchQuery;
use \Couchbase\DisjunctionSearchQuery;
use \Couchbase\MatchPhraseSearchQuery;
use \Couchbase\MatchSearchQuery;
use \Couchbase\NumericRangeSearchFacet;
use \Couchbase\NumericRangeSearchQuery;
use \Couchbase\TermSearchQuery;
use \Couchbase\TermSearchFacet;
use \Couchbase\DateRangeSearchFacet;

/**
 * The tests are relying on FTS index for beer-sample bucket exists with the following mapping for type 'beer':
 *
 *    name | text | index | store | include in _all field | include term vectors
 *    description | text | index | store | include in _all field | include term vectors
 *    updated | datetime | index | store | include in _all field
 *    abv | number | index | store | include in _all field
 *    style | text | index | store | include in _all field | include term vectors
 *    category | text | index | store | include in _all field | include term vectors
 *
 * See JSON definition of this index in the end of this file.
 */
class SearchTest extends TestCase {
    public function setUp(): void {
        $testDSN = getenv('CB_DSN');
        if ($testDSN === FALSE) {
            $testDSN = 'couchbase://localhost/';
        }
        $options = new ClusterOptions();
        $options->credentials(getenv('CB_USER'), getenv('CB_PASSWORD'));
        $this->cluster = new Cluster($testDSN, $options);
    }

    public function testSearchWithLimit() {
        $query = new MatchPhraseSearchQuery("hop beer");
        $options = new SearchOptions();
        $options->limit(3);

        $result = $this->cluster->searchQuery("beer-search", $query, $options);

        $this->assertNotNull($result);
        $this->assertNotEmpty($result->rows());
        $this->assertCount(2, $result->rows());
        $this->assertEquals(2, $result->metaData()->totalHits());

        foreach ($result->rows() as $hit) {
            $this->assertNotNull($hit['id']);
            $this->assertStringStartsWith("beer-search", $hit['index']);
            $this->assertGreaterThan(0, $hit['score']);
        }
    }

    function testSearchWithNoHits() {
        $query = new MatchPhraseSearchQuery("doesnotexistintheindex");
        $options = new SearchOptions();
        $options->limit(3);

        $result = $this->cluster->searchQuery("beer-search", $query, $options);

        $this->assertNotNull($result);
        $this->assertEmpty($result->rows());
        $this->assertEquals(0, $result->metaData()->totalHits());
    }

    function testSearchWithConsistency() {

        $id = uniqid('testSearchWithConsistency');
        $query = new MatchPhraseSearchQuery($id);
        $options = new SearchOptions();
        $options->limit(3);

        $result = $this->cluster->searchQuery("beer-search", $query, $options);

        $this->assertNotNull($result);
        $this->assertEmpty($result->rows());
        $this->assertEquals(0, $result->metaData()->totalHits());

        $collection = $this->cluster->bucket('beer-sample')->defaultCollection();
        $result = $collection->upsert($id, ["type" => "beer", "name" => $id]);
        $mutationState = new MutationState();
        $mutationState->add($result);

        $options->consistentWith("beer-search", $mutationState);
        $result = $this->cluster->searchQuery("beer-search", $query, $options);

        $this->assertNotNull($result);
        $this->assertNotEmpty($result->rows());
        $this->assertEquals(1, $result->metaData()->totalHits());
        $this->assertEquals($id, $result->rows()[0]['id']);
    }

    function testSearchWithFields() {
        $nameField = "name";
        $query = new MatchPhraseSearchQuery("hop beer");
        $options = new SearchOptions();
        $options->limit(3)->fields([$nameField]);

        $result = $this->cluster->searchQuery("beer-search", $query, $options);

        $this->assertNotNull($result);
        $this->assertNotEmpty($result->rows());
        $this->assertCount(2, $result->rows());
        $this->assertEquals(2, $result->metaData()->totalHits());

        foreach ($result->rows() as $hit) {
            $this->assertNotNull($hit['id']);
            $this->assertStringStartsWith("beer-search", $hit['index']);
            $this->assertGreaterThan(0, $hit['score']);
            $this->assertNotEmpty($hit['fields']);
            $this->assertNotNull($hit['fields']['name']);
        }
    }

    function testSearchWithRanges() {
        $query = (new NumericRangeSearchQuery())->field("abv")->min(2.0)->max(3.2);
        $options = new SearchOptions();
        $options->fields(["abv"]);
        $result = $this->cluster->searchQuery("beer-search", $query, $options);

        $this->assertNotNull($result);
        $this->assertNotEmpty($result->rows());
        $this->assertEquals(count($result->rows()), $result->metaData()->totalHits());

        foreach ($result->rows() as $hit) {
            $this->assertNotNull($hit['id']);
            $this->assertStringStartsWith("beer-search", $hit['index']);
            $this->assertGreaterThan(0, $hit['score']);
            $this->assertNotEmpty($hit['fields']);
            $this->assertNotNull($hit['fields']['abv']);
            $this->assertGreaterThanOrEqual(2.0, $hit['fields']['abv']);
            $this->assertLessThan(3.3, $hit['fields']['abv']);
        }

        $startDate = new DateTime('2010-11-01 10:00:00');
        $startStr = $startDate->format(DATE_RFC3339);
        $query = new ConjunctionSearchQuery([
            (new TermSearchQuery("beer"))->field("type"),
            (new DateRangeSearchQuery())->field("updated")->start($startStr)->end(mktime(20, 0, 0, 12, 1, 2010))
        ]);
        $options = new SearchOptions();
        $options->fields(["updated", "type"]);
        $result = $this->cluster->searchQuery("beer-search", $query, $options);

        $this->assertNotNull($result);
        $this->assertNotEmpty($result->rows());
        $this->assertEquals(count($result->rows()), $result->metaData()->totalHits());

        $endDate = new DateTime('2010-12-01 20:00:00');
        foreach ($result->rows() as $hit) {
            $this->assertNotNull($hit['id']);
            $this->assertStringStartsWith("beer-search", $hit['index']);
            $this->assertGreaterThan(0, $hit['score']);
            $this->assertNotEmpty($hit['fields']);
            $this->assertNotNull($hit['fields']['updated']);
            $hitDate = new DateTime($hit['fields']['updated']);
            $diff = $startDate->diff($hitDate);
            $this->assertEquals(0, $diff->invert, "The hit->update date ({$hitDate->format(DATE_RFC3339)}) should go after start date ({$startDate->format(DATE_RFC3339)})");
            $diff = $endDate->diff($hitDate);
            $this->assertEquals(1, $diff->invert, "The hit->update date ({$hitDate->format(DATE_RFC3339)}) should go before or equals to end date ({$startDate->format(DATE_RFC3339)})");
        }
    }

    function testCompoundSearchQueries() {
        $nameQuery = (new MatchSearchQuery("green"))->field("name")->boost(3.4);
        $descriptionQuery = (new MatchSearchQuery("hop"))->field("description")->fuzziness(1);

        $disjunctionQuery = new DisjunctionSearchQuery([$nameQuery, $descriptionQuery]);
        $options = new SearchOptions();
        $options->fields(["type", "name", "description"]);
        $result = $this->cluster->searchQuery("beer-search", $disjunctionQuery, $options);
        $this->assertGreaterThan(1000, $result->metaData()->totalHits());
        $this->assertNotEmpty($result->rows());
        $this->assertMatchesRegularExpression('/green/i', $result->rows()[0]['fields']['name']);
        $this->assertDoesNotMatchRegularExpression('/hop/i', $result->rows()[0]['fields']['name']);
        $this->assertMatchesRegularExpression('/hop/i', $result->rows()[0]['fields']['description']);
        $this->assertDoesNotMatchRegularExpression('/green/i', $result->rows()[0]['fields']['description']);

        $disjunctionQuery->min(2);
        $options = new SearchOptions();
        $options->fields(["type", "name", "description"]);
        $result = $this->cluster->searchQuery("beer-search", $disjunctionQuery, $options);
        $this->assertNotEmpty($result->rows());
        $this->assertLessThan(10, $result->metaData()->totalHits());
        $disjunction2Result = $result;

        $conjunctionQuery = new ConjunctionSearchQuery([$nameQuery, $descriptionQuery]);
        $options = new SearchOptions();
        $options->fields(["type", "name", "description"]);
        $result = $this->cluster->searchQuery("beer-search", $conjunctionQuery, $options);
        $this->assertNotEmpty($result->rows());
        $this->assertEquals(count($disjunction2Result->rows()), count($result->rows()));
        $this->assertEquals($disjunction2Result->rows()[0]['fields']['name'],
                            $result->rows()[0]['fields']['name']);
        $this->assertEquals($disjunction2Result->rows()[0]['fields']['description'],
                            $result->rows()[0]['fields']['description']);
    }

    function testSearchWithFragments() {
        $query = new MatchSearchQuery("hop beer");
        $options = new SearchOptions();
        $options->limit(3)->highlight(SearchHighlightMode::HTML, ["name"]);

        $result = $this->cluster->searchQuery("beer-search", $query, $options);
        $this->assertNotEmpty($result->rows());

        foreach ($result->rows() as $hit) {
            $this->assertNotNull($hit['id']);
            $this->assertNotEmpty($hit['fragments']);
            $this->assertNotNull($hit['fragments']['name']);
            foreach ($hit['fragments']['name'] as $fragment) {
                $this->assertMatchesRegularExpression('/<mark>/', $fragment);
            }
        }
    }

    function testSearchWithFacets() {
        $query = (new TermSearchQuery("beer"))->field("type");
        $options = new SearchOptions();
        $options->facets([
            "foo" => new TermSearchFacet("name", 3),
            "bar" => (new DateRangeSearchFacet("updated", 1))
                        ->addRange("old", NULL,  mktime(0, 0, 0, 1, 1, 2014)), // "2014-01-01T00:00:00" also acceptable
            "baz" => (new NumericRangeSearchFacet("abv", 2))
                        ->addRange("strong", 4.9, NULL)
                        ->addRange("light", NULL, 4.89)
        ]);

        $result = $this->cluster->searchQuery("beer-search", $query, $options);

        $this->assertNotEmpty($result->rows());
        $this->assertNotEmpty($result->facets());

        $this->assertNotNull($result->facets()['foo']);
        $this->assertEquals('name', $result->facets()['foo']->field());
        $this->assertEquals('ale', $result->facets()['foo']->terms()[0]->term());
        $this->assertGreaterThan(1000, $result->facets()['foo']->terms()[0]->count());

        $this->assertNotNull($result->facets()['bar']);
        $this->assertEquals('updated', $result->facets()['bar']->field());
        $this->assertEquals('old', $result->facets()['bar']->dateRanges()[0]->name());
        $this->assertGreaterThan(5000, $result->facets()['bar']->dateRanges()[0]->count());

        $this->assertNotNull($result->facets()['baz']);
        $this->assertEquals('abv', $result->facets()['baz']->field());
        $this->assertEquals('light', $result->facets()['baz']->numericRanges()[0]->name());
        $this->assertGreaterThan(0, $result->facets()['baz']->numericRanges()[0]->max());
        $this->assertGreaterThan(100, $result->facets()['baz']->numericRanges()[0]->count());
    }
}

/*

curl -XPUT -H "Content-Type: application/json" \
-u Administrator:password http://localhost:8094/api/index/beer-search -d \
'{
  "type": "fulltext-index",
  "name": "beer-search",
  "sourceType": "couchbase",
  "sourceName": "beer-sample",
  "planParams": {
    "maxPartitionsPerPIndex": 171,
    "indexPartitions": 6
  },
  "params": {
    "doc_config": {
      "docid_prefix_delim": "",
      "docid_regexp": "",
      "mode": "type_field",
      "type_field": "type"
    },
    "mapping": {
      "analysis": {},
      "default_analyzer": "standard",
      "default_datetime_parser": "dateTimeOptional",
      "default_field": "_all",
      "default_mapping": {
        "dynamic": true,
        "enabled": true
      },
      "default_type": "_default",
      "docvalues_dynamic": true,
      "index_dynamic": true,
      "store_dynamic": false,
      "type_field": "_type",
      "types": {
        "beer": {
          "dynamic": true,
          "enabled": true,
          "properties": {
            "abv": {
              "dynamic": false,
              "enabled": true,
              "fields": [
                {
                  "docvalues": true,
                  "include_in_all": true,
                  "include_term_vectors": true,
                  "index": true,
                  "name": "abv",
                  "store": true,
                  "type": "number"
                }
              ]
            },
            "category": {
              "dynamic": false,
              "enabled": true,
              "fields": [
                {
                  "docvalues": true,
                  "include_in_all": true,
                  "include_term_vectors": true,
                  "index": true,
                  "name": "category",
                  "store": true,
                  "type": "text"
                }
              ]
            },
            "description": {
              "dynamic": false,
              "enabled": true,
              "fields": [
                {
                  "docvalues": true,
                  "include_in_all": true,
                  "include_term_vectors": true,
                  "index": true,
                  "name": "description",
                  "store": true,
                  "type": "text"
                }
              ]
            },
            "name": {
              "dynamic": false,
              "enabled": true,
              "fields": [
                {
                  "docvalues": true,
                  "include_in_all": true,
                  "include_term_vectors": true,
                  "index": true,
                  "name": "name",
                  "store": true,
                  "type": "text"
                }
              ]
            },
            "style": {
              "dynamic": false,
              "enabled": true,
              "fields": [
                {
                  "docvalues": true,
                  "include_in_all": true,
                  "include_term_vectors": true,
                  "index": true,
                  "name": "style",
                  "store": true,
                  "type": "text"
                }
              ]
            },
            "updated": {
              "dynamic": false,
              "enabled": true,
              "fields": [
                {
                  "docvalues": true,
                  "include_in_all": true,
                  "include_term_vectors": true,
                  "index": true,
                  "name": "updated",
                  "store": true,
                  "type": "datetime"
                }
              ]
            }
          }
        }
      }
    },
    "store": {
      "indexType": "scorch"
    }
  },
  "sourceParams": {}
}'

*/
