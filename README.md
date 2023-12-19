![Tests](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/actions/workflows/test.yml/badge.svg)
![Coverage
Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/3c445ef26310e9f2d2ca09c697db1c71/raw/SigmaHQ-pySigma-backend-elasticsearch.json)
![Status](https://img.shields.io/badge/Status-release-green)

# pySigma Elasticsearch Backend

This is the Elasticsearch backend for pySigma. It provides the package `sigma.backends.elasticsearch` with the `LuceneBackend` class.

It supports the following output formats:

* default: Lucene queries.
* dsl_lucene: DSL with embedded Lucene queries.
* eql: Elastic Event Query Language queries.
* kibana_ndjson: Kibana NDJSON with Lucene queries.

Further, it contains the following processing pipelines in `sigma.pipelines.elasticsearch`:

* ecs_windows in windows submodule: ECS mapping for Windows event logs ingested with Winlogbeat.
* ecs_windows_old in windows submodule: ECS mapping for Windows event logs ingested with Winlogbeat <= 6.x.
* ecs_zeek_beats in zeek submodule: Zeek ECS mapping from Elastic.
* ecs_zeek_corelight in zeek submodule: Zeek ECS mapping from Corelight.
* zeek_raw in zeek submodule: Zeek raw JSON log field naming.

This backend is currently maintained by:

* [Thomas Patzke](https://github.com/SigmaHQ/)
* [Hendrik Bäcker](https://github.com/andurin)

Further maintainers required! Send a message to [Thomas](mailto:thomas@patzke.org) if you want to co-maintain this
backend.
