from sectestgen.adapters.cwe_map import sink_type_for_cwe_id, sink_type_for_cwe_strings


def test_sink_type_for_cwe_id_known():
    assert sink_type_for_cwe_id(78) == "command_execution"
    assert sink_type_for_cwe_id(89) == "sql_injection"


def test_sink_type_for_cwe_id_unknown_or_none():
    assert sink_type_for_cwe_id(9999) is None
    assert sink_type_for_cwe_id(None) is None


def test_sink_type_for_cwe_strings_extracts_number():
    strings = ["CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"]
    assert sink_type_for_cwe_strings(strings) == "dynamic_evaluation"


def test_sink_type_for_cwe_strings_empty():
    assert sink_type_for_cwe_strings(None) is None
    assert sink_type_for_cwe_strings([]) is None
