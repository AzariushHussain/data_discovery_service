from pathlib import Path

import httpx

from app.config import settings


class SecretStoreError(Exception):
    """OpenBao could not complete a secret operation."""


class SecretStore:
    def _request(
        self,
        method: str,
        secret_path: str,
        payload: dict | None = None,
    ) -> httpx.Response:
        try:
            token = Path(settings.OPENBAO_TOKEN_FILE).read_text().strip()
        except OSError:
            raise SecretStoreError(
                "OpenBao token file could not be read."
            ) from None

        if not token:
            raise SecretStoreError("OpenBao token file is empty.")

        url = (
            f"{settings.OPENBAO_ADDR.rstrip('/')}/v1/"
            f"{settings.OPENBAO_MOUNT}/data/{secret_path}"
        )

        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.request(
                    method,
                    url,
                    headers={"X-Vault-Token": token},
                    json=payload,
                )
                response.raise_for_status()
                return response
        except httpx.HTTPStatusError as exc:
            raise SecretStoreError(
                f"OpenBao rejected the request "
                f"(HTTP {exc.response.status_code})."
            ) from None
        except httpx.RequestError:
            raise SecretStoreError("OpenBao is unreachable.") from None

    def store_dsn(self, secret_path: str, dsn: str) -> None:
        self._request(
            "POST",
            secret_path,
            payload={"data": {"dsn": dsn}},
        )

    def get_dsn(self, secret_path: str) -> str:
        response = self._request("GET", secret_path)

        try:
            dsn = response.json()["data"]["data"]["dsn"]
        except (ValueError, KeyError, TypeError):
            raise SecretStoreError(
                "OpenBao returned an invalid DSN record."
            ) from None

        if not isinstance(dsn, str) or not dsn.strip():
            raise SecretStoreError("Stored DSN is empty or invalid.")

        return dsn