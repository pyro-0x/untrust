"""Read-only Azure REST access for the azure-cvm checks.

Tokens come from ``azure-identity`` (``pip install 'untrust[azure]'``: CLI login,
environment, managed identity or GitHub OIDC) or, without it, from the Azure CLI.
Every call is a GET to a fixed Microsoft host; nothing is written.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

ARM = "https://management.azure.com"
VAULT_SCOPE = "https://vault.azure.net"
ALLOWED_SUFFIXES = (".vault.azure.net", ".managedhsm.azure.net", ".attest.azure.net")
COMPUTE_API = "2024-07-01"
ATTESTATION_API = "2021-06-01"
KEYVAULT_API = "7.4"

_tokens: dict[str, str] = {}


def token(resource: str = ARM) -> str:
    if resource in _tokens:
        return _tokens[resource]
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore[import-not-found]

        value = str(DefaultAzureCredential().get_token(resource.rstrip("/") + "/.default").token)
    except ImportError:
        az = shutil.which("az")
        if az is None:
            raise RuntimeError("install 'untrust[azure]' or sign in with the Azure CLI") from None
        out = subprocess.run([az, "account", "get-access-token", "--resource", resource,
                              "--query", "accessToken", "-o", "tsv"],
                             capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            raise RuntimeError("Azure CLI could not issue a token; run `az login`") from None
        value = out.stdout.strip()
    _tokens[resource] = value
    return value


def get(url: str, resource: str = ARM) -> dict[str, Any]:
    host = urllib.parse.urlsplit(url).hostname or ""
    if not (url.startswith(ARM + "/") or host.endswith(ALLOWED_SUFFIXES)):
        raise ValueError(f"refusing to call {host}: not an Azure management endpoint")
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token(resource),
                                                   "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            value: dict[str, Any] = json.loads(response.read())
            return value
    except urllib.error.HTTPError as exc:
        reason = {401: "unauthorized", 403: "access denied", 404: "not found"}.get(
            exc.code, f"HTTP {exc.code}")
        raise RuntimeError(f"{reason} reading {urllib.parse.urlsplit(url).path}") from None


def resource_id(subscription: str, group: str, provider: str, name: str) -> str:
    return (f"/subscriptions/{subscription}/resourceGroups/{group}/providers/"
            f"{provider}/{name}")


def vm(subscription: str, group: str, name: str) -> dict[str, Any]:
    path = resource_id(subscription, group, "Microsoft.Compute/virtualMachines", name)
    return get(f"{ARM}{path}?api-version={COMPUTE_API}")


def os_disk(disk_id: str) -> dict[str, Any]:
    return get(f"{ARM}{disk_id}?api-version=2023-10-02")


def attestation_provider(subscription: str, group: str, name: str) -> dict[str, Any]:
    path = resource_id(subscription, group, "Microsoft.Attestation/attestationProviders", name)
    return get(f"{ARM}{path}?api-version={ATTESTATION_API}")


def key(vault: str, name: str) -> dict[str, Any]:
    host = vault if "." in vault else f"{vault}.vault.azure.net"
    return get(f"https://{host}/keys/{urllib.parse.quote(name)}?api-version={KEYVAULT_API}",
               resource=VAULT_SCOPE)
