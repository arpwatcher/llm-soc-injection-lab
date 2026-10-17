import pytest

from soclab import llm_client


@pytest.fixture(autouse=True)
def retry_waits(monkeypatch):
    """OllamaClient waits between retries of a failed request - every test
    that simulates a timeout or a 503 would otherwise really sleep through
    them. Records the waits instead, for the tests that check them."""
    waits: list[float] = []
    monkeypatch.setattr(llm_client.time, "sleep", waits.append)
    return waits
