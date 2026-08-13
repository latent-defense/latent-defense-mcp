"""handle_response status-attachment (LD-2255, review: claude[bot]).

These pin the PRODUCER side of the 404-detection fix: handle_response must stamp
the originating HTTP status onto every McpApiError it raises, for BOTH raise
sites (the structured-error-envelope branch and the per-status branch), so a
caller can branch on ``e.status`` instead of matching message text. The
list_path_comments tests exercise the consumer branch with a pre-stamped error;
these prove handle_response actually populates ``.status`` from a real response.
"""

import httpx
import pytest

from latent_defense_mcp.errors import McpApiError, handle_response


def _resp(status, *, json=None, text=None):
    kwargs = {}
    if json is not None:
        kwargs["json"] = json
    if text is not None:
        kwargs["text"] = text
    return httpx.Response(status, **kwargs)


def test_success_does_not_raise():
    handle_response(_resp(200, json={"ok": True}))  # returns None, no raise


def test_404_envelope_shape_sets_status_404():
    # A 404 whose body is the structured error envelope goes through the
    # ENVELOPE raise (status not in {401,403}) — its message is NOT the
    # "Resource not found (404)" prefix, so message-matching would miss it.
    resp = _resp(404, json={"error": {"code": "not_found",
                                      "message": "Attack path p1 has no comments"}})
    with pytest.raises(McpApiError) as exc:
        handle_response(resp, tool_name="list_path_comments")
    assert exc.value.status == 404
    assert not str(exc.value).startswith("Resource not found (404)")


def test_404_detail_shape_sets_status_404():
    # A 404 with the plain {detail:...} body goes through the per-status 404
    # branch; it too must carry status=404.
    resp = _resp(404, json={"detail": "no such path"})
    with pytest.raises(McpApiError) as exc:
        handle_response(resp, tool_name="list_path_comments")
    assert exc.value.status == 404
    assert str(exc.value).startswith("Resource not found (404)")


def test_403_envelope_routed_to_status_branch_sets_403():
    # Envelope is deliberately ignored for 401/403 (dedicated auth messaging);
    # the raised error must still carry status=403, not the envelope's status.
    resp = _resp(403, json={"error": {"code": "forbidden", "message": "denied"}})
    with pytest.raises(McpApiError) as exc:
        handle_response(resp, tool_name="list_path_comments")
    assert exc.value.status == 403


def test_401_sets_status_401():
    with pytest.raises(McpApiError) as exc:
        handle_response(_resp(401, text="nope"))
    assert exc.value.status == 401


def test_500_sets_status_500():
    with pytest.raises(McpApiError) as exc:
        handle_response(_resp(500, text="boom"))
    assert exc.value.status == 500


def test_unmapped_status_sets_status():
    # The catch-all raise (e.g. 418) must still stamp the real status.
    with pytest.raises(McpApiError) as exc:
        handle_response(_resp(418, text="teapot"))
    assert exc.value.status == 418
