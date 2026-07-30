"""CLOUDTRAIL-01: Audit trail for enclave KMS and S3 operations.

Live KMS-decrypt interception and S3 state tampering leave traces
only if CloudTrail is recording them.
AWS records the enclave's attestation measurements (PCR0/1/2/3/4/8 and
the image digest) in the ``additionalEventData`` of every attested KMS
call — but only if a trail is actually logging.

This check verifies that at least one trail covers the target region
and is actively logging, and that S3 object-level (data) events are
captured for the state bucket. KMS Decrypt is a management event and
is covered by management-event logging; S3 GetObject/PutObject on the
bootstrap state are data events and must be explicitly enabled.
"""
from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


def _covers_region(trail: dict, region: str | None) -> bool:
    if trail.get("IsMultiRegionTrail"):
        return True
    if region is None:
        return True
    return trail.get("HomeRegion") == region


def _logs_s3_data_events(selectors: dict, bucket: str | None) -> bool:
    """Detect S3 object-level data events in classic or advanced selectors."""
    for sel in selectors.get("EventSelectors", []):
        for res in sel.get("DataResources", []):
            if res.get("Type") == "AWS::S3::Object":
                values = res.get("Values", [])
                if not values:
                    return True
                if bucket is None:
                    return True
                if any("s3" in v and (bucket in v or v.endswith(":s3")) for v in values):
                    return True
                # A bare "arn:aws:s3" prefix means all buckets.
                if any(v.rstrip("/").endswith(":s3") for v in values):
                    return True
    for adv in selectors.get("AdvancedEventSelectors", []):
        is_data = False
        is_s3_obj = False
        for field in adv.get("FieldSelectors", []):
            fname = field.get("Field")
            equals = field.get("Equals", [])
            if fname == "eventCategory" and "Data" in equals:
                is_data = True
            if fname == "resources.type" and "AWS::S3::Object" in equals:
                is_s3_obj = True
        if is_data and is_s3_obj:
            return True
    return False


class CloudTrailAuditCheck(Check):
    check_id = "CLOUDTRAIL-01"
    title = "CloudTrail records enclave KMS and S3 operations"
    severity = Severity.MEDIUM

    def run(self, target: Target) -> Finding:
        ct = boto3.client("cloudtrail", region_name=target.region)

        try:
            trails = ct.describe_trails(includeShadowTrails=True).get(
                "trailList", []
            )
        except ClientError as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not describe CloudTrail trails: {e}",
            )

        candidates = [t for t in trails if _covers_region(t, target.region)]

        if not candidates:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    "No CloudTrail trail covers this region. Enclave KMS "
                    "Decrypt calls and S3 state operations are not being "
                    "recorded — the KMS-interception and state-tampering "
                    "attacks would be invisible."
                ),
                remediation=(
                    "Create a multi-region CloudTrail trail with management "
                    "events enabled, and add an S3 data-event selector for "
                    "the state bucket."
                ),
                evidence={"trails_in_region": 0},
            )

        logging_trails: list[str] = []
        s3_data_trails: list[str] = []

        for trail in candidates:
            name = trail.get("Name", "")
            trail_arn = trail.get("TrailARN", name)
            try:
                status = ct.get_trail_status(Name=trail_arn)
            except ClientError:
                continue
            if not status.get("IsLogging"):
                continue
            logging_trails.append(name)

            try:
                selectors = ct.get_event_selectors(TrailName=trail_arn)
            except ClientError:
                selectors = {}
            if _logs_s3_data_events(selectors, target.bucket):
                s3_data_trails.append(name)

        if not logging_trails:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    f"{len(candidates)} trail(s) exist for this region but "
                    f"none are actively logging. KMS and S3 activity is not "
                    f"being captured."
                ),
                remediation=(
                    "Start logging on the trail: "
                    "aws cloudtrail start-logging --name <trail>."
                ),
                evidence={"trails_in_region": len(candidates), "logging": 0},
            )

        if target.bucket and not s3_data_trails:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=(
                    "Management events are logged (KMS Decrypt is captured), "
                    "but no trail records S3 object-level data events for the "
                    "state bucket. Tampering with bootstrap state via "
                    "GetObject/PutObject would leave no audit trail."
                ),
                remediation=(
                    "Add an S3 data-event selector scoped to the state bucket "
                    "so object reads/writes are logged."
                ),
                evidence={
                    "logging_trails": logging_trails,
                    "s3_data_event_trails": [],
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                f"{len(logging_trails)} trail(s) logging; S3 data events "
                f"captured. Enclave KMS and state operations are auditable."
            ),
            evidence={
                "logging_trails": logging_trails,
                "s3_data_event_trails": s3_data_trails,
            },
        )
