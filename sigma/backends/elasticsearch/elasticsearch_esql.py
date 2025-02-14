from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule, SigmaRuleTag
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import SigmaCompareExpression
from sigma.data.mitre_attack import mitre_attack_tactics, mitre_attack_techniques
import sigma
import re
import json
from typing import ClassVar, Dict, Tuple, Pattern, List, Iterable, Optional, Union


class ESQLBackend(TextQueryBackend):
    """ES|QL backend."""

    # TODO: change the token definitions according to the syntax. Delete these not supported by your backend.
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name: ClassVar[str] = "ES|QL backend"
    formats: Dict[str, str] = {
        "default": "Plain ES|QL queries",
        "kibana_ndjson": "Kibana ES|QL queries in NDJSON Format.",
        "siem_rule": "Elastic Security ES|QL queries as SIEM Rules in JSON Format.",
        "siem_rule_ndjson": "Elastic Security ES|QL queries as SIEM Rules in NDJSON Format.",
    }
    requires_pipeline: bool = True

    query_expression: ClassVar[str] = (
        "from {state[index]} metadata {state[metadata]} | where {query}"
    )
    state_defaults: ClassVar[Dict[str, str]] = {
        "index": "*",
        "metadata": "_id, _index, _version",
    }

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[str] = (
        "({expr})"  # Expression for precedence override grouping as format string with {expr} placeholder
    )

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"
    eq_token: ClassVar[str] = (
        "=="  # Token inserted between field and value (without separator)
    )

    # String output
    ## Fields
    ### Quoting
    field_quote: ClassVar[str] = (
        "`"  # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    )
    field_quote_pattern: ClassVar[Pattern] = re.compile(
        "^[\\w.]+$"
    )  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation: ClassVar[bool] = (
        True  # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).
    )

    ## Values
    str_quote: ClassVar[str] = (
        '"'  # string quoting character (added as escaping character)
    )
    escape_char: ClassVar[str] = (
        "\\"  # Escaping character for special characters inside string
    )
    wildcard_multi: ClassVar[str] = "*"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "?"  # Character used as single-character wildcard
    add_escaped: ClassVar[str] = (
        "\\"  # Characters quoted in addition to wildcards and string quote
    )
    filter_chars: ClassVar[str] = ""  # Characters filtered
    bool_values: ClassVar[Dict[bool, str]] = (
        {  # Values to which boolean values are mapped.
            True: "true",
            False: "false",
        }
    )

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[str] = "starts_with({field}, {value})"
    endswith_expression: ClassVar[str] = "ends_with({field}, {value})"
    wildcard_match_expression: ClassVar[str] = (
        "{field} like {value}"  # Special expression if wildcards can't be matched with the eq_token operator
    )

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression: ClassVar[str] = '{field} rlike "{regex}"'
    re_escape_char: ClassVar[str] = (
        "\\"  # Character used for escaping in regular expressions
    )
    re_escape: ClassVar[Tuple[str]] = ('"',)  # List of strings that are escaped
    re_escape_escape_char: bool = True  # If True, the escape character is also escaped
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.

    # CIDR expressions: define CIDR matching if backend has native support. Else pySigma expands
    # CIDR values into string wildcard matches.
    cidr_expression: ClassVar[str] = (
        'cidr_match({field}, "{value}")'  # CIDR expression query as format string with placeholders {field}, {value} (the whole CIDR value), {network} (network part only), {prefixlen} (length of network mask prefix) and {netmask} (CIDR network mask only).
    )

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = (
        "{field}{operator}{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    )
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Expression for comparing two event fields
    field_equals_field_expression: ClassVar[str] = (
        "{field1}=={field2}"  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    )
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (
        True,
        True,
    )  # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    field_null_expression: ClassVar[str] = (
        "{field} is null"  # Expression for field has null value as format string with {field} placeholder for field name
    )

    # Field existence condition expressions.
    field_exists_expression: ClassVar[str] = (
        "{field} is not null"  # Expression for field existence as format string with {field} placeholder for field name
    )
    field_not_exists_expression: ClassVar[str] = (
        "{field} is null"  # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.
    )

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = True  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = (
        False  # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    )
    field_in_list_expression: ClassVar[str] = (
        "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    )
    or_in_operator: ClassVar[str] = (
        "in"  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    )
    list_separator: ClassVar[str] = ", "  # List element separator

    # Correlations
    correlation_methods: ClassVar[Dict[str, str]] = {
        "stats": "Correlation with stats command",
    }
    default_correlation_method: ClassVar[str] = "stats"
    default_correlation_query: ClassVar[str] = {
        "stats": "{search}\n{aggregate}\n{condition}"
    }
    temporal_correlation_query: ClassVar[str] = {
        "stats": "{search}\n{typing}\n{aggregate}\n{condition}"
    }

    correlation_search_single_rule_expression: ClassVar[str] = "{query}"
    correlation_search_multi_rule_expression: ClassVar[str] = "{queries}"
    correlation_search_multi_rule_query_expression: ClassVar[str] = "({query})"
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = " or "

    typing_expression: ClassVar[str] = "| eval event_type=case({queries})"
    typing_rule_query_expression: ClassVar[str] = '{query}, "{ruleid}"'
    typing_rule_query_expression_joiner: ClassVar[str] = ", "

    # not yet supported for ES|QL because all queries from correlated rules are combined into one query.
    # correlation_search_field_normalization_expression: ClassVar[str] = " | rename {field} as {alias}"
    # correlation_search_field_normalization_expression_joiner: ClassVar[str] = ""

    event_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "stats": "| eval timebucket=date_trunc({timespan}, @timestamp) | stats event_count=count(){groupby}"
    }
    value_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "stats": "| eval timebucket=date_trunc({timespan}, @timestamp) | stats value_count=count_distinct({field}){groupby}"
    }
    temporal_aggregation_expression: ClassVar[Dict[str, str]] = {
        "stats": "| eval timebucket=date_trunc({timespan}, @timestamp) | stats event_type_count=count_distinct(event_type){groupby}"
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
    referenced_rules_expression: ClassVar[Dict[str, str]] = {"stats": "{ruleid}"}
    referenced_rules_expression_joiner: ClassVar[Dict[str, str]] = {"stats": ","}

    groupby_expression_nofield: ClassVar = {"stats": " by timebucket"}
    groupby_expression: ClassVar[Dict[str, str]] = {"stats": " by timebucket{fields}"}
    groupby_field_expression: ClassVar[Dict[str, str]] = {"stats": ", {field}"}
    groupby_field_expression_joiner: ClassVar[Dict[str, str]] = {"stats": ""}

    event_count_condition_expression: ClassVar[Dict[str, str]] = {
        "stats": "| where event_count {op} {count}"
    }
    value_count_condition_expression: ClassVar[Dict[str, str]] = {
        "stats": "| where value_count {op} {count}"
    }
    temporal_condition_expression: ClassVar[Dict[str, str]] = {
        "stats": "| where event_type_count {op} {count}"
    }

    def __init__(
        self,
        processing_pipeline: Optional[
            "sigma.processing.pipeline.ProcessingPipeline"
        ] = None,
        collect_errors: bool = False,
        schedule_interval: int = 5,
        schedule_interval_unit: str = "m",
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.schedule_interval = schedule_interval
        self.schedule_interval_unit = schedule_interval_unit
        self.severity_risk_mapping = {
            "INFORMATIONAL": 1,
            "LOW": 21,
            "MEDIUM": 47,
            "HIGH": 73,
            "CRITICAL": 99,
        }

    def flatten_list_of_indices(
        self, nested_list: List[Union[str, List[str]]]
    ) -> List[str]:
        flat_list = []
        for item in nested_list:
            if isinstance(item, list):
                flat_list.extend(
                    self.flatten_list_of_indices(item)
                )  # Recursively flatten the sublist
            else:
                flat_list.append(item)  # Append the string
        return flat_list

    def preprocess_indices(self, indices: List[str]) -> str:
        if not indices:
            return self.state_defaults["index"]

        if self.wildcard_multi in indices:
            return self.wildcard_multi

        indices = self.flatten_list_of_indices(nested_list=indices)
        if len(indices) == 1:
            return indices[0]

        indices = list(set(indices))  # Deduplicate

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

    def finalize_query_kibana_ndjson(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Dict:
        return {
            "attributes": {
                "columns": [],
                "description": (
                    rule.description
                    if rule.description is not None
                    else "No description"
                ),
                "grid": {},
                "hideChart": False,
                "isTextBasedQuery": True,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": str(
                        json.dumps(
                            {
                                "query": {"esql": query},
                                "index": {
                                    "title": state.processing_state["index"],
                                    "timeFieldName": "@timestamp",
                                    "sourceFilters": [],
                                    "type": "esql",
                                    "fieldFormats": {},
                                    "runtimeFieldMap": {},
                                    "allowNoIndex": False,
                                    "name": state.processing_state["index"],
                                    "allowHidden": False,
                                },
                                "filter": [],
                            }
                        )
                    ),
                },
                "sort": [["@timestamp", "desc"]],
                "timeRestore": False,
                "title": f"SIGMA - {rule.title}",
                "usesAdHocDataView": False,
            },
            "id": str(rule.id),
            "managed": False,
            "references": [],
            "type": "search",
            "typeMigrationVersion": "10.2.0",
        }

    def finalize_output_kibana_ndjson(self, queries: List[Dict]) -> List[List[Dict]]:
        return list(queries)

    def finalize_output_threat_model(self, tags: List[SigmaRuleTag]) -> Iterable[Dict]:
        attack_tags = [t for t in tags if t.namespace == "attack"]
        if not len(attack_tags) >= 2:
            return []

        techniques = [
            tag.name.upper() for tag in attack_tags if re.match(r"[tT]\d{4}", tag.name)
        ]
        tactics = [
            tag.name.lower()
            for tag in attack_tags
            if not re.match(r"[tT]\d{4}", tag.name)
        ]

        for tactic, technique in zip(tactics, techniques):
            if (
                not tactic or not technique
            ):  # Only add threat if tactic and technique is known
                continue

            try:
                if "." in technique:  # Contains reference to Mitre Att&ck subtechnique
                    sub_technique = technique
                    technique = technique[0:5]
                    sub_technique_name = mitre_attack_techniques[sub_technique]

                    sub_techniques = [
                        {
                            "id": sub_technique,
                            "reference": f"https://attack.mitre.org/techniques/{sub_technique.replace('.', '/')}",
                            "name": sub_technique_name,
                        }
                    ]
                else:
                    sub_techniques = []

                tactic_id = [
                    id
                    for (id, name) in mitre_attack_tactics.items()
                    if name == tactic.replace("_", "-")
                ][0]
                technique_name = mitre_attack_techniques[technique]
            except (IndexError, KeyError):
                # Occurs when Sigma Mitre Att&ck list is out of date
                continue

            yield {
                "tactic": {
                    "id": tactic_id,
                    "reference": f"https://attack.mitre.org/tactics/{tactic_id}",
                    "name": tactic.title().replace("_", " "),
                },
                "framework": "MITRE ATT&CK",
                "technique": [
                    {
                        "id": technique,
                        "reference": f"https://attack.mitre.org/techniques/{technique}",
                        "name": technique_name,
                        "subtechnique": sub_techniques,
                    }
                ],
            }

        for tag in attack_tags:
            tags.remove(tag)

    def finalize_query_siem_rule(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Dict:
        """
        Create SIEM Rules in JSON Format. These rules could be imported into Kibana using the
        Create Rule API https://www.elastic.co/guide/en/kibana/current/create-rule-api.html
        This API (and generated data) is NOT the same like importing Detection Rules via:
        Kibana -> Security -> Alerts -> Manage Rules -> Import
        If you want to have a nice importable NDJSON File for the Security Rule importer
        use pySigma Format 'siem_rule_ndjson' instead.
        """

        return {
            "name": f"SIGMA - {rule.title}",
            "tags": [f"{n.namespace}-{n.name}" for n in rule.tags],
            "enabled": True,
            "consumer": "siem",
            "throttle": None,
            "schedule": {
                "interval": f"{self.schedule_interval}{self.schedule_interval_unit}"
            },
            "params": {
                "author": [rule.author] if rule.author is not None else [],
                "description": (
                    rule.description
                    if rule.description is not None
                    else "No description"
                ),
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
                "relatedIntegrations": [],
                "requiredFields": [],
                "riskScore": (
                    self.severity_risk_mapping[rule.level.name]
                    if rule.level is not None
                    else 21
                ),
                "riskScoreMapping": [],
                "setup": "",
                "severity": (
                    str(rule.level.name).lower() if rule.level is not None else "low"
                ),
                "severityMapping": [],
                "threat": list(self.finalize_output_threat_model(rule.tags)),
                "to": "now",
                "references": rule.references,
                "version": 1,
                "exceptionsList": [],
                "type": "esql",
                "language": "esql",
                "query": query,
            },
            "rule_type_id": "siem.esqlRule",
            "notify_when": "onActiveAlert",
            "actions": [],
        }

    def finalize_output_siem_rule(self, queries: List[Dict]) -> List[List[Dict]]:
        return list(queries)

    def finalize_query_siem_rule_ndjson(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Dict:
        """
        Generating SIEM/Detection Rules in NDJSON Format. Compatible with

        https://www.elastic.co/guide/en/security/current/rules-ui-management.html#import-export-rules-ui
        """

        return {
            "id": str(rule.id),
            "name": f"SIGMA - {rule.title}",
            "tags": [f"{n.namespace}-{n.name}" for n in rule.tags],
            "interval": f"{self.schedule_interval}{self.schedule_interval_unit}",
            "enabled": True,
            "description": (
                rule.description if rule.description is not None else "No description"
            ),
            "risk_score": (
                0
                if rule.level is not None
                and str(rule.level.name).lower() == "informational"
                else (
                    self.severity_risk_mapping[rule.level.name]
                    if rule.level is not None
                    else 21
                )
            ),
            "severity": (
                "low"
                if rule.level is None or str(rule.level.name).lower() == "informational"
                else str(rule.level.name).lower()
            ),
            "note": "",
            "license": "DRL",
            "output_index": "",
            "meta": {
                "from": "1m",
            },
            "author": [rule.author] if rule.author is not None else [],
            "false_positives": rule.falsepositives,
            "from": f"now-{self.schedule_interval}{self.schedule_interval_unit}",
            "rule_id": str(rule.id),
            "max_signals": 100,
            "risk_score_mapping": [],
            "severity_mapping": [],
            "threat": list(self.finalize_output_threat_model(rule.tags)),
            "to": "now",
            "references": rule.references,
            "version": 1,
            "exceptions_list": [],
            "immutable": False,
            "related_integrations": [],
            "required_fields": [],
            "setup": "",
            "type": "esql",
            "language": "esql",
            "query": query,
            "actions": [],
        }

    def finalize_output_siem_rule_ndjson(self, queries: List[Dict]) -> List[List[Dict]]:
        return list(queries)
