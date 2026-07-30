"""Shared helpers for alternative state-backend checks.

A TEE's bootstrap state does not have to live in S3. Turnkey and
nitriding-style deployments keep encrypted key shares in DynamoDB;
others use Secrets Manager, SSM Parameter Store, a host-mounted EFS/EBS
filesystem, or an RDS/Aurora database. Attestation covers none of them —
the backend is just an implementation detail of the same trust boundary:
"untrusted external state the enclave loads at boot".

Every backend therefore needs the same class of controls the S3 checks
enforce:

* encryption at rest under a customer-managed KMS CMK, so the KMS key
  policy (see KMS-01) can gate decrypt on enclave attestation;
* least-privilege / non-public access and write scope;
* anti-rollback (versioning / point-in-time recovery / no silent
  overwrite);
* audit logging of data-plane operations via CloudTrail data events.

These helpers factor out the two pieces every backend check shares: CMK
identification and CloudTrail data-event coverage lookup.
"""
from __future__ import annotations

import boto3
from botocore.exceptions import ClientError


def classify_kms_key(key_ref: str | None, region: str | None = None) -> str:
    """Authoritatively classify the KMS key a backend encrypts with.

    Returns one of:

    * ``"none"``        — no key (AWS-owned default; e.g. a DynamoDB table
                          with no SSEDescription). Not gate-able.
    * ``"aws_managed"`` — an AWS-managed service key (``aws/dynamodb``,
                          ``aws/rds``, ``aws/secretsmanager`` …). AWS owns
                          the key policy, so an attestation condition
                          cannot be attached. Not gate-able.
    * ``"customer"``    — a customer-managed CMK. Its key policy can gate
                          decrypt on the enclave's attestation (KMS-01).
    * ``"unknown"``     — the key could not be described (e.g. the audit
                          role lacks ``kms:DescribeKey``), so CMK status is
                          unverified. Callers must NOT treat this as a pass.

    A string check alone is not enough: DynamoDB, EFS, and RDS return the
    *resolved key ARN* even for an AWS-managed key, so an AWS-managed key
    is indistinguishable from a customer CMK by ARN. Only
    ``kms:DescribeKey`` → ``KeyMetadata.KeyManager`` tells them apart. The
    ``alias/aws/`` fast path avoids an API call (and SOC noise) when the
    reference is already an AWS service alias.
    """
    if not key_ref:
        return "none"
    if "alias/aws/" in key_ref.lower():
        return "aws_managed"
    try:
        kms = boto3.client("kms", region_name=region)
        meta = kms.describe_key(KeyId=key_ref).get("KeyMetadata", {})
    except ClientError:
        return "unknown"
    manager = meta.get("KeyManager")
    if manager == "CUSTOMER":
        return "customer"
    if manager == "AWS":
        return "aws_managed"
    return "unknown"


def cmk_issue(key_class: str, subject: str) -> str | None:
    """Turn a ``classify_kms_key`` verdict into an issue string, or None.

    ``subject`` is a short noun phrase for the resource, e.g. "the table"
    or "the filesystem". Returns None only when the key is a verified
    customer-managed CMK.
    """
    if key_class == "customer":
        return None
    if key_class == "none":
        return (
            f"{subject} is not encrypted with a customer-managed CMK "
            f"(AWS-owned/default key; attestation cannot gate access)"
        )
    if key_class == "aws_managed":
        return (
            f"{subject} uses an AWS-managed KMS key, not a customer-managed "
            f"CMK (attestation cannot gate access)"
        )
    return (
        f"could not verify {subject} uses a customer-managed CMK "
        f"(grant kms:DescribeKey to the audit role)"
    )


def _selectors_cover(
    selectors: dict, resource_type: str, resource_name: str | None
) -> bool:
    """True if the trail's selectors capture data events for the resource."""
    for sel in selectors.get("EventSelectors", []):
        for res in sel.get("DataResources", []):
            if res.get("Type") == resource_type:
                values = res.get("Values", [])
                if not values or resource_name is None:
                    return True
                if any(resource_name in v for v in values):
                    return True
    for adv in selectors.get("AdvancedEventSelectors", []):
        is_data = False
        matches_type = False
        for field in adv.get("FieldSelectors", []):
            fname = field.get("Field")
            equals = field.get("Equals", [])
            if fname == "eventCategory" and "Data" in equals:
                is_data = True
            if fname == "resources.type" and resource_type in equals:
                matches_type = True
        if is_data and matches_type:
            return True
    return False


def cloudtrail_data_events(
    region: str | None,
    resource_type: str,
    resource_name: str | None = None,
) -> dict:
    """Look up CloudTrail data-event coverage for a resource type.

    Returns a dict with:
      * ``logging``     — names of trails covering the region that are
                          actively logging;
      * ``data_events`` — subset of those that capture data events for
                          ``resource_type`` (e.g. ``AWS::DynamoDB::Table``);
      * ``error``       — a string if trails could not be read, else None.

    Data-event coverage is best-effort: if CloudTrail cannot be read the
    caller should degrade gracefully rather than error the whole check.
    """
    ct = boto3.client("cloudtrail", region_name=region)
    result: dict = {"logging": [], "data_events": [], "error": None}
    try:
        trails = ct.describe_trails(includeShadowTrails=True).get(
            "trailList", []
        )
    except ClientError as e:
        result["error"] = str(e)
        return result

    for trail in trails:
        covers = (
            trail.get("IsMultiRegionTrail")
            or region is None
            or trail.get("HomeRegion") == region
        )
        if not covers:
            continue
        name = trail.get("Name", "")
        arn = trail.get("TrailARN", name)
        try:
            status = ct.get_trail_status(Name=arn)
        except ClientError:
            continue
        if not status.get("IsLogging"):
            continue
        result["logging"].append(name)
        try:
            selectors = ct.get_event_selectors(TrailName=arn)
        except ClientError:
            selectors = {}
        if _selectors_cover(selectors, resource_type, resource_name):
            result["data_events"].append(name)
    return result
