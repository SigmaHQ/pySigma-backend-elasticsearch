from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import SigmaCompareExpression
import sigma
import re
import json
from typing import ClassVar, Dict, List, Optional, Pattern, Tuple

class LuceneBackend(TextQueryBackend):
    """
    Elasticsearch query string backend. Generates query strings described here in the Elasticsearch documentation:

    https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html#query-string-syntax
    """
    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionOR, ConditionAND)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder
    parenthesize: bool = True

    # Generated query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "OR"
    and_token : ClassVar[str] = "AND"
    not_token : ClassVar[str] = "NOT"
    eq_token : ClassVar[str] = ":"  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### No quoting of field names
    ### Escaping
    field_escape : ClassVar[str] = "\\"               # Character to escape particular parts defined in field_escape_pattern.
    field_escape_pattern : ClassVar[Pattern] = re.compile("[\\s*]")   # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote       : ClassVar[str] = '"'     # string quoting character (added as escaping character)
    str_quote_pattern: ClassVar[Pattern] = re.compile(".")
    str_quote_pattern_negation: ClassVar[bool] = True
    escape_char     : ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi  : ClassVar[str] = "*"     # Character used as multi-character wildcard
    wildcard_single : ClassVar[str] = "?"     # Character used as single-character wildcard
    add_escaped     : ClassVar[str] = '+-=&|!(){}[]^"~*?:\\/ '    # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = "<>"      # Characters filtered
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # Regular expressions
    re_expression : ClassVar[str] = "{field}:/{regex}/" # Regular expression query as format string with placeholders {field} and {regex}
    re_escape_char : ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ("/",)
    re_escape_escape_char : ClassVar[bool] = False      # Don't escape the escape char

    # cidr expressions
    cidr_expression : ClassVar[str] = "{field}:{network}\\/{prefixlen}"    # CIDR expression query as format string with placeholders {field} = {value}

    # Numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field}:{operator}{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    # Null/None expressions
    field_null_expression : ClassVar[str] = "NOT _exists_:{field}"          # Expression for field has null value as format string with {field} placeholder for field name

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in : ClassVar[bool] = True                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = False                   # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = True       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field}{op}({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = ":"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    list_separator : ClassVar[str] = " OR "               # List element separator

    # Value not bound to a field
    unbound_value_str_expression : ClassVar[str] = '"{value}"'   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[str] = '{value}'   # Expression for number value not bound to a field as format string with placeholder {value}

    def finalize_query_dsl_lucene(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> Dict:
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

    def finalize_query_kibana_ndjson(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> Dict:
        # TODO: implement the per-query output for the output format kibana here. Usually, the generated query is
        # embedded into a template, e.g. a JSON format with additional information from the Sigma rule.
        columns = list()
        index = "beats-*"
        ndjson = {
            "id": str(rule.id),
            "type": "search",
            "attributes": {
                "title": "SIGMA - {}".format(rule.title),
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
                            "fields": { "*":{} },
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
        # TODO: implement the output finalization for all generated queries for the format kibana here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        return list(queries)
