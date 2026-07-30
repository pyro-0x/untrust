"""IMDS-01: EC2 Instance Metadata Service v2 enforcement.

Verifies that the EC2 instance running the enclave enforces IMDSv2
(HttpTokens: required). Without this, any process on the host — or the
enclave itself if NAT is not filtered — can query IMDS without a session
token, enabling credential theft via a simple HTTP GET.
"""
from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class ImdsEnforcementCheck(Check):
    check_id = "IMDS-01"
    title = "EC2 IMDSv2 enforcement"
    severity = Severity.HIGH

    def run(self, target: Target) -> Finding:
        if not target.instance_id:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.SKIP,
                severity=self.severity,
                summary="No instance ID specified; skipping check.",
            )

        ec2 = boto3.client("ec2", region_name=target.region)

        try:
            response = ec2.describe_instances(InstanceIds=[target.instance_id])
        except ClientError as e:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Could not describe instance: {e}",
            )

        reservations = response.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.ERROR,
                severity=self.severity,
                summary=f"Instance {target.instance_id} not found.",
            )

        instance = reservations[0]["Instances"][0]
        metadata_options = instance.get("MetadataOptions", {})
        http_tokens = metadata_options.get("HttpTokens", "optional")
        http_endpoint = metadata_options.get("HttpEndpoint", "enabled")
        hop_limit = metadata_options.get("HttpPutResponseHopLimit", 1)

        issues: list[str] = []

        if http_tokens != "required":
            issues.append(
                f"HttpTokens is '{http_tokens}' (should be 'required' for IMDSv2-only)"
            )

        if hop_limit > 1:
            issues.append(
                f"HttpPutResponseHopLimit is {hop_limit} (should be 1 to prevent "
                "container/enclave token forwarding)"
            )

        if issues:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=" | ".join(issues),
                remediation=(
                    "Enforce IMDSv2: aws ec2 modify-instance-metadata-options "
                    f"--instance-id {target.instance_id} "
                    "--http-tokens required --http-put-response-hop-limit 1 "
                    "--http-endpoint enabled"
                ),
                evidence={
                    "http_tokens": http_tokens,
                    "http_endpoint": http_endpoint,
                    "hop_limit": hop_limit,
                },
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary="IMDSv2 enforced (HttpTokens: required, hop limit: 1).",
            evidence={
                "http_tokens": http_tokens,
                "hop_limit": hop_limit,
            },
        )
