![Tests](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/actions/workflows/test.yml/badge.svg)}
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/SigmaHQ/3c445ef26310e9f2d2ca09c697db1c71/raw/SigmaHQ-pySigma-backend-elasticsearch.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Elasticsearch Backend

This is the Elasticsearch backend for pySigma. It provides the package `sigma.backends.elasticsearch` with the `ElasticsearchBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.elasticsearch`:

* No pipelines yet defined.

It supports the following output formats:

* default: plain Elasticsearch query strings
* kibana: Kibana JSONL with Elasticsearch query strings (not yet implemented)

This backend is currently maintained by:

* [Thomas Patzke](https://github.com/SigmaHQ/)

Further maintainers required! Send a message to [Thomas](mailto:thomas@patzke.org) if you want to co-maintain this
backend.