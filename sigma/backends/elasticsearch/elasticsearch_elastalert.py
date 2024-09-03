from typing import ClassVar, Dict, List, Optional

from sigma.rule import SigmaRule
from sigma.conversion.state import ConversionState
from sigma.processing.pipeline import ProcessingPipeline
from sigma.correlations import SigmaCorrelationConditionOperator
from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationTimespan
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError, SigmaTimespanError
from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend

class ElastalertBackend(LuceneBackend):
    """
    Elastalert backend for Sigma. Converts Sigma rule into Elastalert rule, including correlation rules.
    """

    # A descriptive name of the backend
    name: ClassVar[str] = "Elasticsearch Elastalert"
    # Output formats provided by the backend as name -> description mapping.
    # The name should match to finalize_output_<name>.
    formats: ClassVar[Dict[str, str]] = {
        "default": "Elastalert rule",
    }
    # Does the backend requires that a processing pipeline is provided?
    requires_pipeline: ClassVar[bool] = True

    timespan_mapping: ClassVar[Dict[str, str]] = {
        "s": "seconds",
        "m": "minutes",
        "h": "hours",
        "d": "days",
        "w": "weeks",
        "M": "months",
        "y": "years",
    }

    correlation_methods: ClassVar[Dict[str, str]] = {
        "default": "Elastalert correlation rule",
    }
    default_correlation_query: ClassVar[Dict[str, str]] = {
        "default": "{search}\n{aggregate}\n{condition}"
    }

    correlation_search_single_rule_expression: ClassVar[str] = "{query}"
    correlation_condition_mapping: ClassVar[Dict[str, str]] = {
        SigmaCorrelationConditionOperator.GT: "max_threshold",
        SigmaCorrelationConditionOperator.LT: "min_threshold",
    }

    event_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "timeframe:\n  {timespan}\n{groupby}"
    }
    value_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "buffer_time:\n  {timespan}\n{groupby}"
    }

    groupby_expression: ClassVar[Dict[str, str]] = {"default": "query_key:\n{fields}"}
    groupby_field_expression: ClassVar[Dict[str, str]] = {"default": "- {field}"}
    groupby_field_expression_joiner: ClassVar[Dict[str, str]] = {"default": "\n"}

    event_count_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "num_events: {count}\ntype: frequency"
    }
    value_count_condition_expression: ClassVar[Dict[str, str]] = {
        "default": (
            "metric_agg_type: cardinality\n"
            "metric_agg_key: {field}\n"
            "{op}: {count}\n"
            "type: metric_aggregation"
        )
    }

    def __init__(
        self,
        processing_pipeline: Optional["ProcessingPipeline"] = None,
        collect_errors: bool = False,
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.severity_risk_mapping = {
            "INFORMATIONAL": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

    def convert_correlation_search(
        self,
        rule: SigmaCorrelationRule,
        **kwargs,
    ) -> str:
        if len(rule.rules) == 1:
            return super().convert_correlation_search(rule, **kwargs,)
        else:
            raise SigmaFeatureNotSupportedByBackendError(
                "Multiple rule queries is not supported by backend."
            )

    def convert_timespan(
        self,
        timespan: SigmaCorrelationTimespan,
        output_format: str | None = None,
        method: str | None = None,
    ) -> str:
        if timespan.unit in self.timespan_mapping:
            return f"{self.timespan_mapping[timespan.unit]}: {timespan.count}"

        raise SigmaTimespanError(
            f"Invalid timespan unit '{timespan.unit}' for Elastalert backend"
        )

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Dict:
        index = state.processing_state.get("index", "*")
        return (
            f"description: {rule.description if rule.description else ''}\n"
            f"index: {index}\n"
            "filter:\n"
            "- query:\n"
            "    query_string:\n"
            f"      query: {query}\n"
            f"priority: {self.severity_risk_mapping[rule.level.name] if rule.level is not None else 1}"
        )

    def finalize_output_default(self, queries: List[str]) -> List[Dict]:
        return list(queries)
