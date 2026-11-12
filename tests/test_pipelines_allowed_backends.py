import pytest

from sigma.pipelines.elasticsearch import pipelines


@pytest.mark.parametrize("name", sorted(pipelines))
@pytest.mark.parametrize("backend", ["eql", "esql", "lucene"])
def test_pipeline_allows_backends_of_this_package(name, backend):
    """Every pipeline shipped here must be usable with every backend shipped here."""
    assert backend in pipelines[name]().allowed_backends
