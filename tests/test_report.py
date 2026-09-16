from soclab.report import render_combined_report, render_markdown_report


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


def test_render_includes_overall_hijack_rate():
    # 5 hijacked out of 10 total across both techniques in _sample_aggregate()
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "overall hijack rate: 50%" in report


def test_render_defaults_to_dismiss_direction():
    report = render_markdown_report("fake-vulnerable", {"none": _sample_aggregate()})
    assert "direction: dismiss" in report


def test_render_notes_escalate_direction_when_given():
    report = render_markdown_report("fake-escalation-vulnerable", {"none": _sample_aggregate()}, direction="escalate")
    assert "direction: escalate" in report


def test_combined_report_includes_both_directions():
    by_direction = {
        "dismiss": {"none": _sample_aggregate(), "sandwich": _sample_aggregate()},
        "escalate": {"none": _sample_aggregate(), "sandwich": _sample_aggregate()},
    }
    report = render_combined_report("fake-vulnerable", by_direction)
    assert "direction: dismiss" in report
    assert "direction: escalate" in report
    assert "defense: none" in report
    assert "defense: sandwich" in report


def test_combined_report_includes_client_name_and_tables():
    by_direction = {"dismiss": {"none": _sample_aggregate()}}
    report = render_combined_report("fake-stubborn", by_direction)
    assert "fake-stubborn" in report
    assert "| technique | hijacked | resisted | other | hijack rate |" in report
    assert "100%" in report
    assert "0%" in report
