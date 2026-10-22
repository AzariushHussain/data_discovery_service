import json
from unittest.mock import Mock
from urllib.error import HTTPError
import warnings

import pytest

from scripts import setup_openbao as setup


@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.setattr(setup, "ROOT", tmp_path)
    monkeypatch.setattr(setup, "SECRETS", tmp_path / ".secrets")
    monkeypatch.setattr(setup, "TOKEN_FILE", setup.SECRETS / "openbao-token.txt")
    monkeypatch.setattr(setup, "INIT_FILE", setup.SECRETS / "openbao-init.json")
    (tmp_path / "openbao").mkdir()
    (tmp_path / "openbao" / "discovery-policy.hcl").write_text('path "discovery/data/sources/*" {}')
    compose = Mock(side_effect=lambda *args, **kwargs: "127.0.0.1:8200" if args[0] == "port" else None)
    monkeypatch.setattr(setup, "compose", compose)
    monkeypatch.setattr(setup.time, "sleep", lambda _: None)
    return compose


def responses(initialized=True, sealed=False, mount=None):
    return [
        {"initialized": initialized},
        *([] if initialized else [{"root_token": "PRIVATE_ROOT", "keys": ["PRIVATE_KEY"]}]),
        {"sealed": sealed},
        *([{"sealed": False}] if sealed else []),
        {},
        {"data": {"discovery/": mount or {"type": "kv", "options": {"version": "2"}}}},
        {},
        {"auth": {"policies": ["discovery-service"], "client_token": "PRIVATE_APP"}},
    ]


def test_fresh_setup_initializes_once_and_saves_private_files(environment, monkeypatch, capsys):
    request = Mock(side_effect=responses(initialized=False, sealed=True))
    monkeypatch.setattr(setup, "request", request)
    prompt = Mock(side_effect=AssertionError("Fresh setup already has generated credentials"))
    monkeypatch.setattr(setup, "prompt_secret", prompt)
    setup.setup()
    assert setup.TOKEN_FILE.read_text() == "PRIVATE_APP"
    assert json.loads(setup.INIT_FILE.read_text())["root_token"] == "PRIVATE_ROOT"
    assert setup.TOKEN_FILE.stat().st_mode & 0o777 == 0o600
    assert setup.INIT_FILE.stat().st_mode & 0o777 == 0o600
    assert [c.args[2] for c in request.call_args_list].count("sys/init") == 2
    assert "PRIVATE_" not in capsys.readouterr().out
    environment.assert_any_call("up", "-d", "--build", "--force-recreate", "app")


def test_existing_sealed_vault_prompts_without_reinitializing(environment, monkeypatch):
    request = Mock(side_effect=responses(sealed=True))
    monkeypatch.setattr(setup, "request", request)
    monkeypatch.setattr(setup, "prompt_secret", Mock(side_effect=["PRIVATE_KEY", "PRIVATE_ROOT"]))
    setup.setup()
    assert not setup.INIT_FILE.exists()
    assert not any(c.args[:3] == ("http://127.0.0.1:8200", "POST", "sys/init") for c in request.call_args_list)
    assert request.call_args_list[2].kwargs["payload"] == {"key": "PRIVATE_KEY"}
    assert "PRIVATE_" not in str(environment.call_args_list)


def test_wrong_mount_does_not_replace_old_token(environment, monkeypatch):
    setup.SECRETS.mkdir()
    setup.TOKEN_FILE.write_text("existing-token")
    request = Mock(side_effect=responses(mount={"type": "kv", "options": {"version": "1"}}))
    monkeypatch.setattr(setup, "request", request)
    monkeypatch.setattr(setup, "prompt_secret", lambda _: "PRIVATE_ROOT")
    with pytest.raises(setup.SetupError, match="not KV v2"):
        setup.setup()
    assert setup.TOKEN_FILE.read_text() == "existing-token"
    assert not any(c.args[2] == "auth/token/create" for c in request.call_args_list)


def test_uninitialized_vault_does_not_overwrite_existing_recovery_file(environment, monkeypatch):
    setup.SECRETS.mkdir()
    setup.INIT_FILE.write_text("original recovery data")
    request = Mock(return_value={"initialized": False})
    monkeypatch.setattr(setup, "request", request)
    with pytest.raises(setup.SetupError, match="Recovery file already exists"):
        setup.setup()
    assert setup.INIT_FILE.read_text() == "original recovery data"
    request.assert_called_once()


def test_http_errors_do_not_include_response_body_or_token(monkeypatch):
    opener = Mock()
    opener.open.side_effect = HTTPError("http://localhost", 403, "PRIVATE_RESPONSE", {}, None)
    monkeypatch.setattr(setup, "build_opener", lambda *args: opener)
    with pytest.raises(setup.SetupError) as error:
        setup.request("http://localhost", "GET", "sys/mounts", "PRIVATE_TOKEN")
    assert str(error.value) == "OpenBao sys/mounts returned HTTP 403."


def test_hidden_prompt_never_falls_back_to_echoed_input(monkeypatch):
    def unavailable(message):
        warnings.warn("No private terminal", setup.getpass.GetPassWarning)
    monkeypatch.setattr(setup.getpass, "getpass", unavailable)
    with pytest.raises(setup.SetupError, match="interactive terminal"):
        setup.prompt_secret("Administrator token: ")
