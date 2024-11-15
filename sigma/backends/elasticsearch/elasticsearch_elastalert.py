from typing import ClassVar, Dict, List, Optional, Union

from sigma.rule import SigmaRule
from sigma.conversion.state import ConversionState
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.processing.pipeline import ProcessingPipeline
from sigma.correlations import SigmaCorrelationConditionOperator
from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationTimespan
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
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

    state_defaults: ClassVar[Dict[str, str]] = {
        "index": "*",
    }

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
        if len(rule.rules) != 1:
            raise SigmaFeatureNotSupportedByBackendError(
                "Multiple correlation rules are not supported by Elastalert backend"
            )

        return super().convert_correlation_search(rule, **kwargs)

    def convert_timespan(
        self,
        timespan: SigmaCorrelationTimespan,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
    ) -> str:
        return f"{self.timespan_mapping[timespan.unit]}: {timespan.count}"

    def preprocess_indices(self, indices: List[str]) -> str:
        if not indices:
            return self.state_defaults["index"]

        if self.wildcard_multi in indices:
            return self.wildcard_multi

        if len(indices) == 1:
            return indices[0]

        # Deduplicate sources using a set
        indices = list(set(indices))

        # Sort the indices to ensure a consistent order as sets are arbitrary ordered
        indices.sort()

        return ",".join(indices)

    def finalize_query(
        self,
        rule: SigmaRule,
        query: Union[str, DeferredQueryExpression],
        index: int,
        state: ConversionState,
        output_format: str,
    ) -> Union[str, DeferredQueryExpression]:
        # If set, load the index from the processing state
        index_state = (
            state.processing_state.get("index", self.state_defaults["index"])
            if isinstance(rule, SigmaRule)
            else [
                state.processing_state.get("index", self.state_defaults["index"])
                for rule_reference in rule.rules
                for state in rule_reference.rule.get_conversion_states()
            ]
        )
        # If the non-default index is not a string, preprocess it
        if not isinstance(index_state, str):
            index_state = self.preprocess_indices(index_state)

        # Save the processed index back to the processing state
        state.processing_state["index"] = index_state
        return super().finalize_query(rule, query, index, state, output_format)

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        alert_type = "type: any\n" if not isinstance(rule, SigmaCorrelationRule) else ""

        return (
            f"description: {rule.description if rule.description else ''}\n"
            f"name: {rule.title if rule.title else ''}\n"
            f"index: \"{state.processing_state['index']}\"\n"
            "filter:\n"
            "- query:\n"
            "    query_string:\n"
            f"      query: {query}\n"
            f"{alert_type}"
            f"priority: {self.severity_risk_mapping[rule.level.name] if rule.level is not None else 1}"
        )

    def finalize_output_default(self, queries: List[str]) -> List[str]:
        return list(queries)
