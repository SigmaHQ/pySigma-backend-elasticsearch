from typing import ClassVar, Dict, List, Optional, Union, Any

from sigma.rule import SigmaRule
from sigma.conversion.state import ConversionState
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.processing.pipeline import ProcessingPipeline
from sigma.correlations import SigmaCorrelationConditionOperator
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend

import yaml

try:
    from yaml import CSafeDumper as Dumper
except ImportError:
    from yaml import SafeDumper as Dumper


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

    correlation_search_single_rule_expression: ClassVar[str] = "{query}"
    correlation_condition_mapping: ClassVar[Dict[str, str]] = {
        SigmaCorrelationConditionOperator.GTE: "max_threshold",
        SigmaCorrelationConditionOperator.GT: "max_threshold",
        SigmaCorrelationConditionOperator.LTE: "min_threshold",
        SigmaCorrelationConditionOperator.LT: "min_threshold",
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

    def convert_correlation_rule_from_template(
        self, rule: SigmaCorrelationRule, correlation_type: str, method: str
    ) -> List[Dict[str, Any]]:
        if f"convert_correlation_{correlation_type}_rule" not in type(self).__dict__:
            raise NotImplementedError(
                f"Correlation rule type '{correlation_type}' is not supported by backend."
            )

        elastalert_rule = {
            "filter": [
                {
                    "query": {
                        "query_string": {
                            "query": self.convert_correlation_search(rule),
                        }
                    }
                }
            ],
        }

        if rule.group_by:
            elastalert_rule["query_key"] = rule.group_by

        return [elastalert_rule]

    def convert_correlation_event_count_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if rule.condition.op in [
            SigmaCorrelationConditionOperator.LT,
            SigmaCorrelationConditionOperator.LTE,
        ]:
            raise SigmaFeatureNotSupportedByBackendError(
                f"Operator '{rule.condition.op}' is not supported by Elastalert backend for event count correlation rules."
            )

        elastalert_rule = super().convert_correlation_event_count_rule(
            rule, output_format, method
        )

        elastalert_rule[0].update(
            {
                "timeframe": {
                    self.timespan_mapping[rule.timespan.unit]: rule.timespan.count
                },
                "num_events": rule.condition.count,
                "type": "frequency",
            }
        )

        if rule.condition.op == SigmaCorrelationConditionOperator.GT:
            elastalert_rule[0]["num_events"] += 1

        return elastalert_rule

    def convert_correlation_value_count_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        elastalert_rule = super().convert_correlation_value_count_rule(
            rule, output_format, method
        )

        elastalert_rule[0].update(
            {
                "metric_agg_type": "cardinality",
                "metric_agg_key": rule.condition.fieldref,
                "buffer_time": {
                    self.timespan_mapping[rule.timespan.unit]: rule.timespan.count
                },
                self.correlation_condition_mapping[
                    rule.condition.op
                ]: rule.condition.count,
                "type": "metric_aggregation",
            }
        )

        if rule.condition.op in [
            SigmaCorrelationConditionOperator.GTE,
            SigmaCorrelationConditionOperator.LTE,
        ]:
            elastalert_rule[0][
                self.correlation_condition_mapping[rule.condition.op]
            ] -= 1

        return elastalert_rule

    def preprocess_indices(self, indices: List[str]) -> str:
        if not indices:
            return self.state_defaults["index"]

        if self.wildcard_multi in indices:
            return self.wildcard_multi

        if len(indices) == 1:
            return indices[0]

        indices = list(set(indices))  # Deduplicate

        # Sort the indices to ensure a consistent order as sets are arbitrary ordered
        indices.sort()

        return ",".join(indices)

    def finalize_query(
        self,
        rule: SigmaRule,
        query: Union[str, Dict[str, Any], DeferredQueryExpression],
        index: int,
        state: ConversionState,
        output_format: str,
    ) -> str:
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

        if not isinstance(rule, SigmaCorrelationRule):
            query = {
                "filter": [
                    {
                        "query": {
                            "query_string": {
                                "query": query,
                            }
                        }
                    }
                ],
                "type": "any",
            }

        query.update(
            {
                "description": rule.description if rule.description else "",
                "name": rule.title if rule.title else "",
                "index": index_state,
                "priority": (
                    self.severity_risk_mapping[rule.level.name]
                    if rule.level is not None
                    else 1
                ),
            }
        )

        return yaml.dump(query, Dumper=Dumper)

    def finalize_output_default(self, queries: List[str]) -> List[str]:
        return list(queries)
