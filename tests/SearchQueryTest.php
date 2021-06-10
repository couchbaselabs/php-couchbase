<?php declare(strict_types=1);

require_once('CouchbaseTestCase.php');

class SearchQueryTest extends CouchbaseTestCase {
    function testNullInNumericRangeFacet() {
        $facet = (new \Couchbase\NumericRangeSearchFacet("abv", 2))->addRange("light", NULL, 4.89)->addRange("staut", NULL, 7.89);
        $this->assertNotNull(json_encode($facet));
    }

    function testSearchQuery() {
        $query = (new \Couchbase\BooleanSearchQuery())
                    ->must(
                        (new \Couchbase\ConjunctionSearchQuery([
                            (new \Couchbase\DocIdSearchQuery)->docIds('bar', 'baz'),
                            new \Couchbase\MatchSearchQuery('hello world')
                        ]))
                        ->every(new \Couchbase\MatchAllSearchQuery())
                    )
                    ->should(
                        (new \Couchbase\DisjunctionSearchQuery([
                            new \Couchbase\MatchNoneSearchQuery(),
                            (new \Couchbase\DateRangeSearchQuery())->start('2010-11-01T10:00:00+00:00')->end('2010-12-01T10:00:00+00:00'),
                            new \Couchbase\TermRangeSearchQuery('hello', 'world'),
                            new \Couchbase\GeoDistanceSearchQuery(1.0, 3.0, "10mi"),
                            new \Couchbase\GeoBoundingBoxSearchQuery(1.0, 3.0, 4.0, 5.0),
                        ]))
                        ->either(new \Couchbase\NumericRangeSearchQuery(3, 42.5))
                        ->either((new \Couchbase\WildcardSearchQuery('user*'))->field('type'))
                    )
                    ->mustNot(
                        new \Couchbase\DisjunctionSearchQuery([
                            (new \Couchbase\PhraseSearchQuery('foo', 'bar', 'baz'))->field('description'),
                            (new \Couchbase\RegexpSearchQuery('user.*'))->field('_class_name')
                        ])
                    );
        $result = json_encode($query);
        $this->assertNotNull($result);
        $this->assertEquals(JSON_ERROR_NONE, json_last_error());

        $options = new \Couchbase\SearchOptions();
        $options->fields(["foo", "bar", "baz"]);
        $options->highlight(\Couchbase\SearchHighlightMode::SIMPLE, ["foo", "bar", "baz"]);
        $options->facets([
            "foo" => new \Couchbase\TermSearchFacet("name", 3),
            "bar" => (new \Couchbase\DateRangeSearchFacet("updated", 2))->addRange("old", NULL, "2014-01-01T00:00:00"),
            "baz" => (new \Couchbase\NumericRangeSearchFacet("abv", 2))->addRange("string", 4.9, NULL)->addRange("light", NULL, 4.89)
        ]);
        $result = json_encode($options);
        $this->assertNotNull($result);
        $this->assertEquals(JSON_ERROR_NONE, json_last_error());
    }

    function testInlineSearchQuery() {
        $result = json_encode((new \Couchbase\SearchOptions())->sort(['hello', 'world', '-_score']));
        $this->assertEquals(JSON_ERROR_NONE, json_last_error());
        $this->assertEquals('{"sort":["hello","world","-_score"]}', $result);

        $result = json_encode(new \Couchbase\MatchSearchQuery('foo'));
        $this->assertEquals(JSON_ERROR_NONE, json_last_error());
        $this->assertEquals('{"match":"foo"}', $result);
    }

    function testAdvancedSort() {
        $options = new \Couchbase\SearchOptions();
        $options->sort([
            'hello',
            (new \Couchbase\SearchSortId())->descending(true),
            new \Couchbase\SearchSortScore(),
            new \Couchbase\SearchSortGeoDistance("foo", 27.4395527, 53.8835622),
            (new \Couchbase\SearchSortField("bar"))
                ->type(\Couchbase\SearchSortType::NUMBER)
                ->missing(\Couchbase\SearchSortMissing::FIRST)
        ]);

        $result = json_encode($options);
        $this->assertEquals(JSON_ERROR_NONE, json_last_error());
        $this->assertEquals(
            '{"sort":["hello",' .
                '{"by":"id","desc":true},' .
                '{"by":"score"},' .
                '{"by":"geo_distance","field":"foo","location":[27.4395527,53.8835622]},' .
                '{"by":"field","field":"bar","type":"number","missing":"first"}]}',
                                $result);

    }

    function testBooleanSearchQuery() {
        $match_query = new \Couchbase\MatchSearchQuery('hello world');

        $disjunction_query = new \Couchbase\DisjunctionSearchQuery([$match_query]);
        $bool_query = (new \Couchbase\BooleanSearchQuery())->mustNot($disjunction_query);

        $result = json_encode($bool_query);
        $this->assertEquals(JSON_ERROR_NONE, json_last_error());
        $this->assertEquals('{"must_not":{"disjuncts":[{"match":"hello world"}]}}', $result);
    }
}
