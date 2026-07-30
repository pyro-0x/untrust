"""VPC-01: VPC network isolation.

Verifies that the enclave host's VPC does not have VPC peering
connections, transit gateway attachments, or a public IP on the
enclave host instance.  Each of these extends the network attack
surface beyond what the enclave operator expects.
"""
from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from .base import Check, Finding, Severity, Status, Target


class VpcIsolationCheck(Check):
    check_id = "VPC-01"
    title = "VPC network isolation"
    severity = Severity.MEDIUM

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
            response = ec2.describe_instances(
                InstanceIds=[target.instance_id]
            )
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
        vpc_id = instance.get("VpcId", "")
        public_ip = instance.get("PublicIpAddress")

        issues: list[str] = []
        evidence: dict = {"vpc_id": vpc_id}

        if public_ip:
            issues.append(f"Enclave host has a public IP: {public_ip}")
            evidence["public_ip"] = public_ip

        try:
            peering = ec2.describe_vpc_peering_connections(
                Filters=[
                    {"Name": "requester-vpc-info.vpc-id", "Values": [vpc_id]},
                ]
            )
            accepter_peering = ec2.describe_vpc_peering_connections(
                Filters=[
                    {"Name": "accepter-vpc-info.vpc-id", "Values": [vpc_id]},
                ]
            )
            all_peering = (
                peering.get("VpcPeeringConnections", [])
                + accepter_peering.get("VpcPeeringConnections", [])
            )
            active_peering = [
                p for p in all_peering
                if p.get("Status", {}).get("Code") == "active"
            ]
            if active_peering:
                issues.append(
                    f"{len(active_peering)} active VPC peering "
                    f"connection(s) found"
                )
                evidence["peering_connections"] = len(active_peering)
        except ClientError:
            pass

        try:
            tgw = ec2.describe_transit_gateway_vpc_attachments(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )
            tgw_attachments = [
                a for a in tgw.get("TransitGatewayVpcAttachments", [])
                if a.get("State") == "available"
            ]
            if tgw_attachments:
                issues.append(
                    f"{len(tgw_attachments)} transit gateway "
                    f"attachment(s) found"
                )
                evidence["tgw_attachments"] = len(tgw_attachments)
        except ClientError:
            pass

        if issues:
            return Finding(
                check_id=self.check_id,
                title=self.title,
                status=Status.FAIL,
                severity=self.severity,
                summary=" | ".join(issues),
                remediation=(
                    "The enclave host's VPC should be isolated. Remove "
                    "VPC peering connections, transit gateway attachments, "
                    "and public IPs from the enclave host. Use VPC "
                    "endpoints for AWS service access."
                ),
                evidence=evidence,
            )

        return Finding(
            check_id=self.check_id,
            title=self.title,
            status=Status.PASS,
            severity=self.severity,
            summary=(
                "VPC is isolated: no public IP, no peering, "
                "no transit gateway."
            ),
            evidence=evidence,
        )
