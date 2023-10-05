from .elasticsearch_lucene import LuceneBackend

backends = {
    "elasticsearch": LuceneBackend,
}
