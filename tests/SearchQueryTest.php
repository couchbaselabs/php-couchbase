<?php
require_once('CouchbaseTestCase.php');

class SearchQueryTest extends CouchbaseTestCase {
    function testNullInNumericRangeFacet() {
        $facet = \Couchbase\SearchQuery::numericRangeFacet("abv", 2)->addRange("light", NULL, 4.89);
        $this->assertNotNull(json_encode($facet));
    }

    function testInlineSearchQuery() {
        $query = new \Couchbase\SearchQuery(
            'fooBarIndex',
            \Couchbase\SearchQuery::boolean()
                ->must(\Couchbase\SearchQuery::conjuncts(
                    \Couchbase\SearchQuery::docId('foo')->docIds('bar', 'baz'),
                    \Couchbase\SearchQuery::match('hello world'))->every(
                        \Couchbase\SearchQuery::matchAll()))
                ->should(\Couchbase\SearchQuery::disjuncts(
                    \Couchbase\SearchQuery::matchNone(),
                    \Couchbase\SearchQuery::dateRange()
                        ->start('2010-11-01T10:00:00+00:00')
                        ->end('2010-12-01T10:00:00+00:00'),
                    \Couchbase\SearchQuery::termRange()->min('hello')->max('world'),
                    \Couchbase\SearchQuery::geoDistance(1.0, 3.0, "10mi"),
                    \Couchbase\SearchQuery::geoBoundingBox(1.0, 3.0, 4.0, 5.0),
                    \Couchbase\SearchQuery::numericRange()->min(3)->max(42.5))->either(
                        \Couchbase\SearchQuery::wildcard('user*')->field('type')))
                ->mustNot(\Couchbase\SearchQuery::disjuncts(
                        \Couchbase\SearchQuery::phrase('foo', 'bar', 'baz')->field('description'),
                        \Couchbase\SearchQuery::regexp('user.*')->field('_class_name')))
        );
        $query
            ->fields("foo", "bar", "baz")
            ->highlight(\Couchbase\SearchQuery::HIGHLIGHT_SIMPLE, "foo", "bar", "baz")
            ->addFacet("foo", \Couchbase\SearchQuery::termFacet("name", 3))
            ->addFacet("bar", \Couchbase\SearchQuery::dateRangeFacet("updated", 1)
                       ->addRange("old", NULL, "2014-01-01T00:00:00"))
            ->addFacet("baz", \Couchbase\SearchQuery::numericRangeFacet("abv", 2)
                       ->addRange("strong", 4.9, NULL)
                       ->addRange("light", NULL, 4.89));
        $result = json_encode($query);
        $this->assertNotNull($result);
        $this->assertEquals(JSON_ERROR_NONE, json_last_error());
    }

    function testInlineSearchQury() {
        $query = new \Couchbase\SearchQuery('search', \Couchbase\SearchQuery::match('foo'));
        $query->sort('hello', 'world', '-_score');
        $result = json_encode($query);
        $this->assertEquals(JSON_ERROR_NONE, json_last_error());
        $this->assertEquals('{"indexName":"search","sort":["hello","world","-_score"],"query":{"match":"foo"}}', $result);
    }

    function testAdvancedSort() {
        $query = new \Couchbase\SearchQuery('search', \Couchbase\SearchQuery::match('foo'));
        $query->sort(
            'hello',
            \Couchbase\SearchSort::id()->descending(true),
            \Couchbase\SearchSort::score(),
                \Couchbase\SearchSort::geoDistance("foo", 27.4395527, 53.8835622),
            \Couchbase\SearchSort::field("bar")
                ->type(\Couchbase\SearchSortField::TYPE_NUMBER)
                ->missing(\Couchbase\SearchSortField::MISSING_FIRST)
        );
        $result = json_encode($query);
        $this->assertEquals(JSON_ERROR_NONE, json_last_error());
        $this->assertEquals(
            '{"indexName":"search","sort":["hello",' .
                '{"by":"id","desc":true},' .
                '{"by":"score","desc":false},' .
                '{"by":"geo_distance","desc":false,"field":"foo","location":[27.4395527,53.8835622]},' .
                '{"by":"field","desc":false,"field":"bar","type":"number","missing":"first"}],"query":{"match":"foo"}}',
                                $result);

    }
}
