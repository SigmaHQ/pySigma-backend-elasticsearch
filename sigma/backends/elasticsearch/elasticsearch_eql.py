import re
import json
from typing import ClassVar, Dict, List, Optional, Pattern, Tuple, Union, Any

from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conditions import (
    ConditionItem,
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
)
from sigma.types import SigmaCompareExpression, SigmaNull, SpecialChars, SigmaNumber
import ipaddress
import sigma


class EqlBackend(TextQueryBackend):
    """
    Elasticsearch event query language backend. Generates query strings described here in the
    Elasticsearch documentation:

    https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html
    """

    # A descriptive name of the backend
    name: ClassVar[str] = "Elasticsearch EQL"
    # Output formats provided by the backend as name -> description mapping.
    # The name should match to finalize_output_<name>.
    formats: ClassVar[Dict[str, str]] = {
        "default": "Plain Elasticsearch EQL queries.",
        "eqlapi": "Plain EQL queries ready for '/_eql/search' API endpoint.",
        "siem_rule": "Elasticsearch EQL queries as SIEM Rule.",
        "siem_rule_ndjson": "Elasticsearch EQL Query as SIEM Rules in NDJSON Format.",
    }
    # Does the backend requires that a processing pipeline is provided?
    requires_pipeline: ClassVar[bool] = True

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionOR,
        ConditionAND,
    )
    # Expression for precedence override grouping as format string with {expr} placeholder
    group_expression: ClassVar[str] = "({expr})"
    parenthesize: bool = True

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"
    # Token inserted between field and value (without separator)
    eq_token: ClassVar[str] = ":"

    field_quote: ClassVar[str] = "`"
    field_quote_pattern: ClassVar[Pattern] = re.compile(r"^\d.*|.*\s.*|-")
    field_quote_pattern_negation: ClassVar[bool] = False
    # String output
    # Fields
    # No quoting of field names
    # Escaping
    # Character to escape particular parts defined in field_escape_pattern.
    # field_escape: ClassVar[str] = ""
    # All matches of this pattern are prepended with the string contained in field_escape.
    # field_escape_pattern: ClassVar[Pattern] = re.compile("[\\s*]")

    # Values
    # string quoting character (added as escaping character)
    str_quote: ClassVar[str] = '"'
    str_quote_pattern: ClassVar[Pattern] = re.compile(r"^$|.*")
    str_quote_pattern_negation: ClassVar[bool] = False
    # Escaping character for special characrers inside string
    escape_char: ClassVar[str] = "\\"
    # Character used as multi-character wildcard
    wildcard_multi: ClassVar[str] = "*"
    # Character used as single-character wildcard
    wildcard_single: ClassVar[str] = "?"
    # Characters quoted in addition to wildcards and string quote
    # add_escaped: ClassVar[str] = '+-=&|!(){}[]<>^"~*?:\\/ '
    add_escaped: ClassVar[str] = '\n\r\t\\"'
    bool_values: ClassVar[
        Dict[bool, str]
    ] = {  # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # Regular expressions
    # Regular expression query as format string with placeholders {field} and {regex}
    re_expression: ClassVar[str] = '{field} regex~ "{regex}"'
    # Character used for escaping in regular expressions
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = ("/",)
    # Don't escape the escape char
    re_escape_escape_char: ClassVar[bool] = False

    # Case sensitive string matching expression. String is quoted/escaped like a normal string.
    # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.
    case_sensitive_match_expression: ClassVar[Optional[str]] = '{field} == {value}'

    # cidr expressions
    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_expression: ClassVar[str] = 'cidrMatch({field}, "{network}/{prefixlen}")'

    # Numeric comparison operators
    # Compare operation query as format string with placeholders {field}, {operator} and {value}
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    # Mapping between CompareOperators elements and strings used as replacement
    # for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Null/None expressions
    # Expression for field has null value as format string with {field} placeholder for field name
    field_null_expression: ClassVar[str] = "?{field} == null"

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    # Convert OR as in-expression
    convert_or_as_in: ClassVar[bool] = True
    # Convert AND as in-expression
    convert_and_as_in: ClassVar[bool] = False
    # Values in list can contain wildcards. If set to False (default)
    # only plain values are converted into in-expressions.
    in_expressions_allow_wildcards: ClassVar[bool] = True
    # Expression for field in list of values as format string with
    # placeholders {field}, {op} and {list}
    field_in_list_expression: ClassVar[str] = "{field}{op}({list})"
    # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    or_in_operator: ClassVar[str] = " like~ "
    # List element separator
    list_separator: ClassVar[str] = ", "

    # Value not bound to a field
    # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_str_expression: ClassVar[str] = '"{value}"'
    # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression: ClassVar[str] = "{value}"

    def __init__(
        self,
        processing_pipeline: Optional[
            "sigma.processing.pipeline.ProcessingPipeline"
        ] = None,
        collect_errors: bool = False,
        index_names: List = [
            "apm-*-transaction*",
            "auditbeat-*",
            "endgame-*",
            "filebeat-*",
            "logs-*",
            "packetbeat-*",
            "traces-apm*",
            "winlogbeat-*",
            "-*elastic-cloud-logs-*",
        ],
        schedule_interval: int = 5,
        schedule_interval_unit: str = "m",
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.index_names = index_names or [
            "apm-*-transaction*",
            "auditbeat-*",
            "endgame-*",
            "filebeat-*",
            "logs-*",
            "packetbeat-*",
            "traces-apm*",
            "winlogbeat-*",
            "-*elastic-cloud-logs-*",
        ]
        self.schedule_interval = schedule_interval or 5
        self.schedule_interval_unit = schedule_interval_unit or "m"
        self.severity_risk_mapping = {
            "INFORMATIONAL": 1,
            "LOW": 21,
            "MEDIUM": 47,
            "HIGH": 73,
            "CRITICAL": 99,
        }

    @staticmethod
    def _is_field_null_condition(cond: ConditionItem) -> bool:
        return isinstance(cond, ConditionFieldEqualsValueExpression) and isinstance(
            cond.value, SigmaNull
        )

    def is_ip(self, value: ConditionFieldEqualsValueExpression) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:  # pragma: no cover
        """Conversion of field = string value expressions"""
        if (  # Use '==' as operator for empty string or ip addresses
            cond.value.convert() == "" or self.is_ip(cond.value)
        ):
            expr = "{field}" + "==" + "{value}"
            value = cond.value
            return expr.format(
                field=self.escape_and_quote_field(cond.field),
                value=self.convert_value_str(value, state),
            )
        else:
            return super().convert_condition_field_eq_val_str(cond, state)

    def convert_condition_not(
        self, cond: ConditionNOT, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """When checking if a field is not null, convert "NOT NOT _exists_:field" to "_exists_:field"."""
        if EqlBackend._is_field_null_condition(cond.args[0]):
            # return f"_exists_:{cond.args[0].field}"
            return f"?{cond.args[0].field} != null"

        return super().convert_condition_not(cond, state)

    def compare_precedence(self, outer: ConditionItem, inner: ConditionItem) -> bool:
        """Override precedence check for null field conditions."""
        if isinstance(inner, ConditionNOT) and EqlBackend._is_field_null_condition(
            inner.args[0]
        ):
            # inner will turn into "_exists_:field", no parentheses needed
            return True

        if EqlBackend._is_field_null_condition(inner):
            # inner will turn into "NOT _exists_:field", force parentheses
            return False

        return super().compare_precedence(outer, inner)

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Any:
        # TODO: implement the per-query output for the output format {{ format }} here. Usually, the generated query is
        # embedded into a template, e.g. a JSON format with additional information from the Sigma rule.
        # TODO: proper type annotation.
        return f"any where {query}"

    def finalize_output_default(self, queries: List[str]) -> Any:
        # TODO: implement the output finalization for all generated queries for the format {{ format }} here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        # TODO: proper type annotation. Sigma CLI supports:
        # - str: output as is.
        # - bytes: output in file only (e.g. if a zip package is output).
        # - dict: output serialized as JSON.
        # - list of str: output each item as is separated by two newlines.
        # - list of dict: serialize each item as JSON and output all separated by newlines.
        return list(queries)

    def finalize_query_eqlapi(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Dict:
        """
        Create EQL Queries ready to be used against the '_eql/search' API Endpoint.
        """
        return {"query": f"any where {query}"}

    def finalize_output_eqlapi(self, queries: List[str]) -> Any:
        # TODO: implement the output finalization for all generated queries for the format {{ format }} here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        # TODO: proper type annotation. Sigma CLI supports:
        # - str: output as is.
        # - bytes: output in file only (e.g. if a zip package is output).
        # - dict: output serialized as JSON.
        # - list of str: output each item as is separated by two newlines.
        # - list of dict: serialize each item as JSON and output all separated by newlines.
        return list(queries)

    def finalize_query_siem_rule(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Dict:
        """
        Create SIEM Rules in JSON Format. These rules could be imported into Kibana using the
        Create Rule API https://www.elastic.co/guide/en/kibana/8.6/create-rule-api.html
        This API (and generated data) is NOT the same like importing Detection Rules via:
        Kibana -> Security -> Alerts -> Manage Rules -> Import
        If you want to have a nice importable NDJSON File for the Security Rule importer
        use pySigma Format 'siem_rule_ndjson' instead.
        """

        siem_rule = {
            "name": f"SIGMA - {rule.title}",
            "tags": [f"{n.namespace}-{n.name}" for n in rule.tags],
            "consumer": "siem",
            "enabled": True,
            "throttle": None,
            "schedule": {
                "interval": f"{self.schedule_interval}{self.schedule_interval_unit}"
            },
            "params": {
                "author": [rule.author] if rule.author is not None else [],
                "description": rule.description
                if rule.description is not None
                else "No description",
                "ruleId": str(rule.id),
                "falsePositives": rule.falsepositives,
                "from": f"now-{self.schedule_interval}{self.schedule_interval_unit}",
                "immutable": False,
                "license": "DRL",
                "outputIndex": "",
                "meta": {
                    "from": "1m",
                },
                "maxSignals": 100,
                "riskScore": self.severity_risk_mapping[rule.level.name]
                if rule.level is not None
                else 21,
                "riskScoreMapping": [],
                "severity": str(rule.level.name).lower()
                if rule.level is not None
                else "low",
                "severityMapping": [],
                "threat": [],
                "to": "now",
                "references": rule.references,
                "version": 1,
                "exceptionsList": [],
                "relatedIntegrations": [],
                "requiredFields": [],
                "setup": "",
                "type": "query",
                "language": "lucene",
                "index": self.index_names,
                "query": f"any where {query}",
                "filters": [],
            },
            "rule_type_id": "siem.queryRule",
            "notify_when": "onActiveAlert",
            "actions": [],
        }
        return siem_rule

    def finalize_output_siem_rule(self, queries: List[Dict]) -> Dict:
        return list(queries)

    def finalize_query_siem_rule_ndjson(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Dict:
        """
        Generating SIEM/Detection Rules in NDJSON Format. Compatible with

        https://www.elastic.co/guide/en/security/8.6/rules-ui-management.html#import-export-rules-ui
        """

        siem_rule = {
            "id": str(rule.id),
            "name": f"SIGMA - {rule.title}",
            "tags": [f"{n.namespace}-{n.name}" for n in rule.tags],
            "enabled": True,
            "throttle": "no_actions",
            "interval": f"{self.schedule_interval}{self.schedule_interval_unit}",
            "author": [rule.author] if rule.author is not None else [],
            "description": rule.description
            if rule.description is not None
            else "No description",
            "rule_id": str(rule.id),
            "false_positives": rule.falsepositives,
            "from": f"now-{self.schedule_interval}{self.schedule_interval_unit}",
            "immutable": False,
            "license": "DRL",
            "output_index": "",
            "meta": {
                "from": "1m",
            },
            "max_signals": 100,
            "risk_score": self.severity_risk_mapping[rule.level.name]
            if rule.level is not None
            else 21,
            "risk_score_mapping": [],
            "severity": str(rule.level.name).lower()
            if rule.level is not None
            else "low",
            "severity_mapping": [],
            "threat": [],
            "to": "now",
            "references": rule.references,
            "version": 1,
            "exceptions_list": [],
            "related_integrations": [],
            "required_fields": [],
            "setup": "",
            "type": "query",
            "language": "lucene",
            "index": self.index_names,
            "query": f"any where {query}",
            "filters": [],
            "actions": [],
        }
        return siem_rule

    def finalize_output_siem_rule_ndjson(self, queries: List[Dict]) -> Dict:
        return list(queries)
