import pytest
from sigma.backends.elasticsearch.elasticsearch_eql import EqlBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError


@pytest.fixture(name="eql_backend")
def fixture_eql_backend():
    return EqlBackend()


def test_event_count_correlation_rule_stats_query(eql_backend: EqlBackend):
    correlation_rule = SigmaCollection.from_yaml(
        r"""
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
        - fieldD
    timespan: 15m
    condition:
        gte: 10
            """
    )
    assert eql_backend.convert(correlation_rule) == [
        'sequence by fieldC, fieldD with maxspan=15m \n [any where fieldA:"value1" and fieldB:"value2"]  with runs=10'
    ]

def test_value_count_correlation_rule_stats_query(eql_backend):
    correlation_rule = SigmaCollection.from_yaml(
            r"""
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        lt: 10
        field: fieldD
            """
        )
    assert eql_backend.convert(correlation_rule) == [
        """sequence by fieldC with maxspan=15m \n [any where fieldA:"value1" and fieldB:"value2"] by fieldD with runs=10"""
    ]

def test_temporal_correlation_rule_stats_query(eql_backend):
    # Rule differs from cookie cutter template, 'aliases' key removed as not supported by EQL.
    # EQL does not support timespans when events are un-ordered.
    # See: https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax#eql-samples
    correlation_rule = SigmaCollection.from_yaml(
        r"""
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value3
        fieldB: value4
    condition: selection
---
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldC
    timespan: 15m
""" 
        )
    assert(eql_backend.convert(correlation_rule) == [
        """sample by fieldC \n [any where fieldA:"value1" and fieldB:"value2"] \n [any where fieldA:"value3" and fieldB:"value4"] """
    ]
    )

def test_temporal_ordered_correlation_rule_stats_query(eql_backend):
    # Rule differs from cookie cutter template, 'aliases' key removed as not supported by EQL.
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value3
        fieldB: value4
    condition: selection
---
title: Ordered temporal correlation rule
status: test
correlation:
    type: temporal_ordered
    rules:
        - base_rule_1
        - base_rule_2
    group-by:
        - fieldC
    timespan: 15m
"""
    )
    assert eql_backend.convert(correlation_rule) == [
        """sequence by fieldC with maxspan=15m \n [any where fieldA:"value1" and fieldB:"value2"] \n [any where fieldA:"value3" and fieldB:"value4"] """
    ]
#   Full diff:
#     [
#         'sequence by fieldC with maxspan=15m \n'
#         ' [any where fieldA:"value1" and fieldB:"value2"] \n'
#   -     ' [any where fieldA:"value3" and fieldB:"value4"] ',
#   +     ' [any where fieldA:"value3" and fieldB:"value4"] by None with runs=2',
#   ?                                                       +++++++++++++++++++
#     ]
# More investigation is needed as to where this is coming from at the end of base_rule_2

def test_temporal_ordered_correlation_rule_stats_query_three_base_rules(eql_backend):
    correlation_rule = SigmaCollection.from_yaml(
        r"""
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value3
        fieldB: value4
    condition: selection
---
title: Base rule 3
name: base_rule_3
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value5
        fieldB: value6
    condition: selection
---
title: Ordered temporal correlation rule
status: test
correlation:
    type: temporal_ordered
    rules:
        - base_rule_1
        - base_rule_2
        - base_rule_3
    group-by:
        - fieldC
    timespan: 15m
"""
    )
    assert eql_backend.convert(correlation_rule) == [
        """sequence by fieldC with maxspan=15m \n [any where fieldA:"value1" and fieldB:"value2"] \n [any where fieldA:"value3" and fieldB:"value4"] \n [any where fieldA:"value5" and fieldB:"value6"]  """
    ]


def test_event_count_correlation_rule(eql_backend: EqlBackend):
    rule = SigmaCollection.from_yaml(
        r"""
title: Password Spraying via SChannelName
id: dcb9bf7c-216b-4a22-80a2-3232284cda18
name: password_spraying_schannel
status: experimental
description: Detecting Password Spraying via SChannelName
correlation:
    type: event_count
    rules:
        - ntlm_authentification
    group-by:
        - SChannelName
    timespan: 15m
    condition:
        gt: 35
---
title: NTLM Authentification
id: dcb9bf7c-216b-4a22-80a2-1232284cda18
name: ntlm_authentification
logsource:
    product: windows
    category: security
detection:
    selection:
        EventID: 8004
    condition: selection
        """
    )

    assert eql_backend.convert(rule) == [
        "sequence by SChannelName with maxspan=15m \n [any where EventID:8004]  with runs=35"
    ]


def test_value_count_correlation_rule(eql_backend: EqlBackend):
    rule = SigmaCollection.from_yaml(
        r"""
title: Password Spraying via SChannelName
id: dcb9bf7c-216b-4a22-80a2-3232284cda18
name: password_spraying_schannel
status: experimental
description: Detecting Password Spraying via SChannelName
correlation:
    type: value_count
    rules:
        - ntlm_authentification
    group-by:
        - SChannelName
    timespan: 15m
    condition:
        field: UserName
        gt: 35
---
title: NTLM Authentification
id: dcb9bf7c-216b-4a22-80a2-1232284cda18
name: ntlm_authentification
logsource:
    product: windows
    category: security
detection:
    selection:
        EventID: 8004
    condition: selection
        """
    )

    assert eql_backend.convert(rule) == [
        "sequence by SChannelName with maxspan=15m \n [any where EventID:8004] by UserName with runs=35"
    ]


def test_temporal_correlation_rule(eql_backend: EqlBackend):
    rule = SigmaCollection.from_yaml(
        r"""
title: Suspicious File Open Activity
status: experimental
description: Detects suspicious file open activity on Linux systems
correlation:
    type: temporal
    rules:
        - rule_one
        - rule_two
    group-by:
        - user.name
        - host.ip
    timespan: 15m
---
title: Linux Open File Activity
status: experimental
description: Detects open file activity on Linux systems
name: rule_one
logsource:
    category: audit
    product: linux
detection:
    selection:
        process.command_line|contains: git.exe
    condition: selection
---
title: Linux Open File Activity
name: rule_two
status: experimental
description: Detects open file activity on Linux systems
logsource:
    category: audit
    product: linux
detection:
    selection:
        process.command_line|contains: conhost.exe
    condition: selection

        """
    )

    assert eql_backend.convert(rule) == [
        'sample by user.name, host.ip \n [any where process.command_line:"*git.exe*"] \n [any where process.command_line:"*conhost.exe*"] '
    ]


def test_temporal_ordered_correlation_rule(eql_backend: EqlBackend):
    rule = SigmaCollection.from_yaml(
        r"""
title: Password Spraying via SChannelName
id: dcb9bf7c-216b-4a22-80a2-3232284cda18
name: password_spraying_schannel
status: experimental
description: Detecting Password Spraying via SChannelName
correlation:
    type: temporal_ordered
    rules:
        - ntlm_authentification
    group-by:
        - SChannelName
    timespan: 15m
    condition:
        field: UserName
        gt: 35
---
title: NTLM Authentification
id: dcb9bf7c-216b-4a22-80a2-1232284cda18
name: ntlm_authentification
logsource:
    product: windows
    category: security
detection:
    selection:
        EventID: 8004
    condition: selection
        """
    )

    assert eql_backend.convert(rule) == [
        "sequence by SChannelName with maxspan=15m \n [any where EventID:8004] by UserName with runs=35"
    ]