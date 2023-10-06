from .elasticsearch_lucene import LuceneBackend
from .elasticsearch_eql import EqlBackend

backends = {
    "elasticsearch": LuceneBackend,
    "elasticsearch-eql": EqlBackend,
}
