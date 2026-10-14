"""Client telemetry seam: injectable, no-op by default, never authoritative (O-U16, O-U17)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from client_helpers import (
    ACTION_ALLOW,
    USER_TOKEN,
    FakeServer,
    build_client,
    conforming_allow,
    json_response,
    make_context,
    make_request,
)

from mtmf_client.observability import (
    ClientStatusClass,
    NoopClientInstrumentation,
    OtelClientInstrumentation,
    SnapshotRejectionReason,
    TokenFailureCategory,
)


class _FakeInstrumentation:
    def __init__(self) -> None:
        self.spans: list[str] = []
        self.responses: list[ClientStatusClass] = []
        self.token_failures: list[TokenFailureCategory] = []
        self.snapshot_rejections: list[SnapshotRejectionReason] = []

    @contextmanager
    def _span(self, name: str) -> Iterator[None]:
        self.spans.append(name)
        yield

    def span_evaluate(self):  # type: ignore[no-untyped-def]
        return self._span("evaluate")

    def span_token_acquire(self):  # type: ignore[no-untyped-def]
        return self._span("token")

    def record_http_response(self, *, status_class: ClientStatusClass) -> None:
        self.responses.append(status_class)

    def record_token_failure(self, *, category: TokenFailureCategory) -> None:
        self.token_failures.append(category)

    def record_snapshot_rejection(self, *, reason: SnapshotRejectionReason) -> None:
        self.snapshot_rejections.append(reason)


def test_o_u16_noop_instrumentation_is_inert() -> None:
    instrumentation = NoopClientInstrumentation()
    with instrumentation.span_evaluate():
        pass
    with instrumentation.span_token_acquire():
        pass
    instrumentation.record_http_response(status_class=ClientStatusClass.SUCCESS)
    instrumentation.record_token_failure(category=TokenFailureCategory.TRANSPORT)
    instrumentation.record_snapshot_rejection(reason=SnapshotRejectionReason.DENIED)


def test_o_u16_evaluate_records_span_and_status_class() -> None:
    server = FakeServer(evaluate_response=conforming_allow)
    instrumentation = _FakeInstrumentation()
    client, _config, _clock = build_client(server, instrumentation=instrumentation)
    request = make_request()
    try:
        client.evaluate(request, user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    assert instrumentation.spans == ["evaluate", "token"]
    # Both the token acquisition and the evaluate call are successful 2xx.
    assert instrumentation.responses == [ClientStatusClass.SUCCESS, ClientStatusClass.SUCCESS]
    assert server.evaluate_calls == 1
    assert server.token_calls == 1


def test_o_u17_token_failure_category_is_recorded() -> None:
    server = FakeServer(
        token_response=lambda _request: json_response("{}", status_code=401),
        evaluate_response=conforming_allow,
    )
    instrumentation = _FakeInstrumentation()
    client, _config, _clock = build_client(server, instrumentation=instrumentation)
    try:
        client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    except Exception:
        pass
    finally:
        client.close()
    assert instrumentation.token_failures == [TokenFailureCategory.REJECTED]
    assert server.evaluate_calls == 0


def test_o_u17_snapshot_rejection_reason_is_recorded() -> None:
    instrumentation = _FakeInstrumentation()
    server = FakeServer(evaluate_response=conforming_allow)
    client, _config, _clock = build_client(server, instrumentation=instrumentation)
    try:
        assert (
            client.is_allowed(
                None,
                context=make_context(),
                action=ACTION_ALLOW,
                resource=make_request().actions[0].resource,
            )
            is False
        )
    finally:
        client.close()
    assert instrumentation.snapshot_rejections == [SnapshotRejectionReason.NOT_OWNED]


class _FakeSpan:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: object) -> None:
        return None


class _FakeTracer:
    def __init__(self) -> None:
        self.names: list[str] = []

    def start_as_current_span(self, name: str) -> _FakeSpan:
        self.names.append(name)
        return _FakeSpan()


class _FakeCounter:
    def __init__(self) -> None:
        self.records: list[tuple[int, dict[str, str]]] = []

    def add(self, amount: int, attributes: dict[str, str]) -> None:
        self.records.append((amount, attributes))


class _FakeMeter:
    def __init__(self) -> None:
        self.counters: dict[str, _FakeCounter] = {}

    def create_counter(self, name: str, unit: str = "", description: str = "") -> _FakeCounter:
        del unit, description
        counter = _FakeCounter()
        self.counters[name] = counter
        return counter


def test_otel_client_instrumentation_uses_bounded_labels() -> None:
    tracer = _FakeTracer()
    meter = _FakeMeter()
    instrumentation = OtelClientInstrumentation(tracer=tracer, meter=meter)
    with instrumentation.span_evaluate():
        pass
    with instrumentation.span_token_acquire():
        pass
    instrumentation.record_http_response(status_class=ClientStatusClass.CLIENT_ERROR)
    instrumentation.record_token_failure(category=TokenFailureCategory.PROTOCOL)
    instrumentation.record_snapshot_rejection(reason=SnapshotRejectionReason.EXPIRED)
    assert tracer.names == ["mtmf.client.evaluate", "mtmf.client.token_acquire"]
    assert meter.counters["mtmf.client.http.responses"].records == [(1, {"status_class": "4xx"})]
    assert meter.counters["mtmf.client.tokens"].records == [
        (1, {"outcome": "failure", "category": "protocol"})
    ]
    assert meter.counters["mtmf.client.snapshot.rejections"].records == [(1, {"reason": "expired"})]


def test_http_response_status_class_recording_on_error() -> None:
    instrumentation = _FakeInstrumentation()
    server = FakeServer(
        evaluate_response=lambda _request: json_response("{}", status_code=503),
    )
    client, _config, _clock = build_client(server, instrumentation=instrumentation)
    try:
        client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    except Exception:
        pass
    finally:
        client.close()
    assert instrumentation.responses[-1] is ClientStatusClass.SERVER_ERROR
