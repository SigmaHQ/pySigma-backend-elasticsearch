# DevTools Readme

For now you can find a docker compose environment to start your own
local Elasticsearch Node which can be used by the backend pytests
to check the code against a real ES Instance.

## Foreword

1. Don't use this ES Node for production data!
   * It isn't very hardened, using simple passwords, etc.
2. It depends a installed docker and the docker compose plugin
   * I guess you'll make it!

## Startup

Just open a new terminal and run `docker compose up` or `docker compose up -d` (detached).

```bash
cd devtools
mv dot_env .env
docker compose up -d
cd ..
```

## Run tests against this node

```bash
$ pytest tests/test_backend_elasticsearch_*_connect.py

================================================ test session starts ================================================
platform linux -- Python 3.10.12, pytest-7.4.4, pluggy-1.5.0 -- /home/dev/.local/share/virtualenvs/pysigma-backend-elasticsearch-qlQ8rDO_-py3.10/bin/python
cachedir: .pytest_cache
rootdir: /home/dev/pySigma-backend-elasticsearch
configfile: pyproject.toml
plugins: cov-4.1.0
collected 35 items                                                                                                  

tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_and_expression PASSED [  2%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_and_expression_empty_string PASSED [  5%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_or_expression PASSED [  8%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_and_or_expression PASSED [ 11%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_or_and_expression PASSED [ 14%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_in_expression PASSED [ 17%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_in_expression_empty_string PASSED [ 20%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_regex_query PASSED [ 22%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_cidr_query PASSED [ 25%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_ip_query PASSED   [ 28%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_field_name_with_whitespace PASSED [ 31%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_dot_value PASSED  [ 34%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_space_value_text PASSED [ 37%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_space_value_keyword PASSED [ 40%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_angle_brackets PASSED [ 42%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_angle_brackets_single PASSED [ 45%]
tests/test_backend_elasticsearch_eql_connect.py::TestConnectElasticsearch::test_connect_eql_windash_double PASSED [ 48%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_and_expression PASSED [ 51%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_and_expression_empty_string PASSED [ 54%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_or_expression PASSED [ 57%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_and_or_expression PASSED [ 60%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_or_and_expression PASSED [ 62%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_in_expression PASSED [ 65%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_in_expression_empty_string PASSED [ 68%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_regex_query PASSED [ 71%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_cidr_v4_query PASSED [ 74%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_cidr_v6_query PASSED [ 77%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_ip_query PASSED [ 80%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_field_name_with_whitespace PASSED [ 82%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_dot_value PASSED [ 85%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_space_value_text PASSED [ 88%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_space_value_keyword PASSED [ 91%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_angle_brackets PASSED [ 94%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_angle_brackets_single PASSED [ 97%]
tests/test_backend_elasticsearch_lucene_connect.py::TestConnectElasticsearch::test_connect_lucene_windash_double PASSED [100%]
```
