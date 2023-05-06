import re
import json
from typing import ClassVar, Dict, List, Optional, Pattern, Tuple, Union, Any

from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression, ConditionType
from sigma.types import SigmaCompareExpression, SigmaString
import sigma


class LuceneBackend(TextQueryBackend):
    """
    Elasticsearch query string backend. Generates query strings described here in the 
    Elasticsearch documentation:

    https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html#query-string-syntax
    """
    # A descriptive name of the backend
    name: ClassVar[str] = "Elasticsearch Lucene"
    # Output formats provided by the backend as name -> description mapping.
    # The name should match to finalize_output_<name>.
    formats: ClassVar[Dict[str, str]] = {
        "default": "Plain Elasticsearch Lucene queries",
        "kibana_ndjson": "Kibana NDJSON import file with Lucene queries",
        "dsl_lucene": "Elasticsearch query DSL with embedded Lucene queries",
        "siem_rule": "Elasticsearch query DSL as SIEM Rules in JSON Format",
        "siem_rule_ndjson": "Elasticsearch query DSL as SIEM Rules in NDJSON Format",
    }
    # Does the backend requires that a processing pipeline is provided?
    requires_pipeline: ClassVar[bool] = True

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT, ConditionOR, ConditionAND)
    # Expression for precedence override grouping as format string with {expr} placeholder
    group_expression: ClassVar[str] = "({expr})"
    parenthesize: bool = True

    # Generated query tokens
    token_separator: str = " "     # separator inserted between all boolean operators
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    # Token inserted between field and value (without separator)
    eq_token: ClassVar[str] = ":"

    # String output
    # Fields
    # No quoting of field names
    # Escaping
    # Character to escape particular parts defined in field_escape_pattern.
    field_escape: ClassVar[str] = "\\"
    # All matches of this pattern are prepended with the string contained in field_escape.
    field_escape_pattern: ClassVar[Pattern] = re.compile("[\\s*]")

    # Values
    # string quoting character (added as escaping character)
    str_quote: ClassVar[str] = '"'
    str_quote_pattern: ClassVar[Pattern] = re.compile(".")
    str_quote_pattern_negation: ClassVar[bool] = True
    # Escaping character for special characrers inside string
    escape_char: ClassVar[str] = "\\"
    # Character used as multi-character wildcard
    wildcard_multi: ClassVar[str] = "*"
    # Character used as single-character wildcard
    wildcard_single: ClassVar[str] = "?"
    # Characters quoted in addition to wildcards and string quote
    add_escaped: ClassVar[str] = '+-=&|!(){}[]^"~*?:\\/ '
    filter_chars: ClassVar[str] = "<>"      # Characters filtered
    bool_values: ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # Regular expressions
    # Regular expression query as format string with placeholders {field} and {regex}
    re_expression: ClassVar[str] = "{field}:/{regex}/"
    # Character used for escaping in regular expressions
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = ("/",)
    # Don't escape the escape char
    re_escape_escape_char: ClassVar[bool] = False

    # cidr expressions
    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_expression: ClassVar[str] = "{field}:{network}\\/{prefixlen}"

    # Numeric comparison operators
    # Compare operation query as format string with placeholders {field}, {operator} and {value}
    compare_op_expression: ClassVar[str] = "{field}:{operator}{value}"
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
    field_null_expression: ClassVar[str] = "NOT _exists_:{field}"

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
    or_in_operator: ClassVar[str] = ":"
    # List element separator
    list_separator: ClassVar[str] = " OR "

    # Value not bound to a field
    # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_str_expression: ClassVar[str] = '"{value}"'
    # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression: ClassVar[str] = '{value}'

    def __init__(
        self,
        processing_pipeline: Optional["sigma.processing.pipeline.ProcessingPipeline"] = None,
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
            "-*elastic-cloud-logs-*"
        ],
        schedule_interval: int = 5,
        schedule_interval_unit: str = "m",
        case_insensitive_whitelist: Optional[str] = None,
        case_insensitive_blacklist: Optional[str] = None,
        field_extension: Optional[Union[List[str], str]] = None,
            **kwargs):

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
            "-*elastic-cloud-logs-*"
        ]
        self.schedule_interval = schedule_interval or 5
        self.schedule_interval_unit = schedule_interval_unit or "m"
        self.severity_risk_mapping = {
            "INFORMATIONAL": 1,
            "LOW": 21,
            "MEDIUM": 47,
            "HIGH": 73,
            "CRITICAL": 99
        }
        if case_insensitive_blacklist:
            self.case_insensitive_blacklist = set(
                item.strip() for item in case_insensitive_blacklist.split(','))
        else:
            self.case_insensitive_blacklist = set()

        if case_insensitive_whitelist:
            self.case_insensitive_whitelist = set(
                item.strip() for item in case_insensitive_whitelist.split(','))
        else:
            self.case_insensitive_whitelist = set()

        self.field_to_extension = {}

        if field_extension:
            if isinstance(field_extension, str):  # Only passed one field
                field_extension = [field_extension]

            for setting in field_extension:
                field_and_extensions = setting.split(',')
                field = field_and_extensions[0]
                extensions = field_and_extensions[1:]
                for extension in extensions:
                    self.field_to_extension[extension.strip()] = field.strip()

    def apply_backend_option_case_insensitive(self, cond: ConditionType) -> Tuple[ConditionType, bool]:
        if hasattr(cond, 'args'):
            conds = cond.args
        else:
            conds = [cond]

        was_changed = False
        for condition in conds:
            if type(condition.value) == SigmaString:
                if (
                    ('*' in self.case_insensitive_whitelist or
                     (condition.field in self.case_insensitive_whitelist))
                    and (condition.field not in self.case_insensitive_blacklist)
                ):
                    was_changed = True
                    converted = condition.value.convert(
                        escape_char=self.escape_char,
                        wildcard_multi='.*',
                        wildcard_single='.',
                        add_escaped='+-=&|!(){}"~?\\ <>#*./',
                        filter_chars=self.filter_chars,
                    )
                    condition.value = re.sub(
                        r"[A-Za-z]",
                        lambda x: ("[" + x.group(0).upper() +
                                   x.group(0).lower() + "]"
                                   ),
                        str(converted)
                    )
        return cond, was_changed

    def apply_backend_option_field_extension(self, cond: ConditionType) -> ConditionType:
        if hasattr(cond, 'args'):
            conds = cond.args
        else:
            conds = [cond]

        for condition in conds:
            if condition.field in self.field_to_extension:
                condition.field = f"{condition.field}.{self.field_to_extension[condition.field]}"

        return cond

    def convert_condition_as_in_expression(self, cond: Union[ConditionOR, ConditionAND], state: ConversionState) -> Union[str, DeferredQueryExpression]:
        if self.case_insensitive_whitelist:
            cond, was_changed = self.apply_backend_option_case_insensitive(
                cond
            )
            if was_changed:  # don't want to escape value twice
                return self.field_in_list_expression.format(
                    field=self.escape_and_quote_field(cond.args[0].field),
                    op=self.or_in_operator if isinstance(
                        cond, ConditionOR) else self.and_in_operator,
                    list=self.list_separator.join([
                        f"/{arg.value}/"
                        for arg in cond.args
                    ]),
                )
        if self.field_to_extension:
            cond = self.apply_backend_option_field_extension(cond)

        return super().convert_condition_as_in_expression(cond, state)

    def convert_condition_field_eq_val(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Any:
        if self.field_to_extension:
            cond = self.apply_backend_option_field_extension(cond)
        if self.case_insensitive_whitelist:
            cond, was_changed = self.apply_backend_option_case_insensitive(
                cond
            )
            if was_changed:
                return self.re_expression.format(field=cond.field, regex=cond.value)

        return super().convert_condition_field_eq_val(cond, state)

    def convert_condition_field_eq_val_null(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field is null expression value expressions"""
        if cond.parent_condition_chain_contains(ConditionNOT):
            return self.field_null_expression.format(field=self.escape_and_quote_field(cond.field)).replace(f"{self.not_token} ", "")
        else:
            return self.field_null_expression.format(field=self.escape_and_quote_field(cond.field))

    def finalize_query_dsl_lucene(
            self,
            rule: SigmaRule,
            query: str,
            index: int,
            state: ConversionState) -> Dict:

        return {
            "query": {
                "bool": {
                    "must": [
                        {
                            "query_string": {
                                "query": query,
                                "analyze_wildcard": True
                            }
                        }
                    ]
                }
            }
        }

    def finalize_output_dsl_lucene(self, queries: List[Dict]) -> Dict:
        return list(queries)

    def finalize_query_kibana_ndjson(
        self,
        rule: SigmaRule,
        query: str,
        index: int,
        state: ConversionState
    ) -> Dict:

        # TODO: implement the per-query output for the output format kibana here. Usually, the
        # generated query is embedded into a template, e.g. a JSON format with additional
        # information from the Sigma rule.
        columns = []
        index = "beats-*"
        ndjson = {
            "id": str(rule.id),
            "type": "search",
            "attributes": {
                "title": f"SIGMA - {rule.title}",
                "description": rule.description,
                "hits": 0,
                "columns": columns,
                "sort": ["@timestamp", "desc"],
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": str(json.dumps({
                        "index": index,
                        "filter":  [],
                        "highlight": {
                            "pre_tags": ["@kibana-highlighted-field@"],
                            "post_tags": ["@/kibana-highlighted-field@"],
                            "fields": {"*": {}},
                            "require_field_match": False,
                            "fragment_size": 2147483647
                        },
                        "query": {
                            "query_string": {
                                "query": query,
                                "analyze_wildcard": True
                            }
                        }
                    })
                    )
                }
            },
            "references": [
                {
                    "id": index,
                    "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "type": "index-pattern"
                }
            ]
        }
        return ndjson

    def finalize_output_kibana_ndjson(self, queries: List[str]) -> List[Dict]:
        # TODO: implement the output finalization for all generated queries for the format kibana
        # here. Usually, the single generated queries are embedded into a structure, e.g. some
        # JSON or XML that can be imported into the SIEM.
        return list(queries)

    def finalize_query_siem_rule(
        self,
        rule: SigmaRule,
        query: str,
        index: int,
        state: ConversionState
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
                "description": rule.description if rule.description is not None else "No description",
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
                "riskScore": self.severity_risk_mapping[rule.level.name] if rule.level is not None else 21,
                "riskScoreMapping": [],
                "severity": str(rule.level.name).lower() if rule.level is not None else "low",
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
                "query": query,
                "filters": []
            },
            "rule_type_id": "siem.queryRule",
            "notify_when": "onActiveAlert",
            "actions": []
        }
        return siem_rule

    def finalize_output_siem_rule(self, queries: List[Dict]) -> Dict:
        return list(queries)

    def finalize_query_siem_rule_ndjson(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> Dict:
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
            "description": rule.description if rule.description is not None else "No description",
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
            "risk_score": self.severity_risk_mapping[rule.level.name] if rule.level is not None else 21,
            "risk_score_mapping": [],
            "severity": str(rule.level.name).lower() if rule.level is not None else "low",
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
            "query": query,
            "filters": [],
            "actions": []
        }
        return siem_rule

    def finalize_output_siem_rule_ndjson(self, queries: List[Dict]) -> Dict:
        return list(queries)
