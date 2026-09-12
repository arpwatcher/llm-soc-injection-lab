from soclab.report import render_markdown_report


def _sample_aggregate():
    return {
        "direct_override": {"total": 5, "hijacked": 5, "resisted": 0, "other": 0, "hijack_rate": 1.0},
        "unicode_homoglyph": {"total": 5, "hijacked": 0, "resisted": 5, "other": 0, "hijack_rate": 0.0},
    }


def test_render_includes_client_name():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "fake-vulnerable" in report


def test_render_includes_a_section_per_defense():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate(), "sandwich": _sample_aggregate()})
    assert "defense: none" in report
    assert "defense: sandwich" in report


def test_render_formats_hijack_rate_as_percentage():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "100%" in report
    assert "0%" in report


def test_render_is_valid_markdown_table_shape():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "| technique | hijacked | resisted | other | hijack rate |" in report
    assert "|---|---|---|---|---|" in report
