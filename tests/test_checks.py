"""Tests for individual audit checks using mocked AWS responses."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from untrust.checks.audit_log import AuditLogCheck
from untrust.checks.base import Status, Target
from untrust.checks.bootstrap_input import BootstrapInputCheck
from untrust.checks.bucket_policy import BucketPolicyCheck
from untrust.checks.cloudtrail_audit import CloudTrailAuditCheck
from untrust.checks.core_dump import CoreDumpCheck
from untrust.checks.dns_dnat import DnsDnatCheck
from untrust.checks.dynamodb_state import DynamoDbStateCheck
from untrust.checks.efs_state import EfsStateCheck
from untrust.checks.enclave_cotenant import EnclaveCotenantCheck
from untrust.checks.enclave_debug import EnclaveDebugCheck
from untrust.checks.enclave_pcr import EnclavePcrCheck
from untrust.checks.enclave_signed import EnclaveSignedCheck
from untrust.checks.env_var_semantic import EnvVarSemanticCheck
from untrust.checks.exec_permissions import ExecPermissionsCheck
from untrust.checks.host_permissions import HostPermissionsCheck
from untrust.checks.host_services import HostServicesCheck
from untrust.checks.iam_scope import IamScopeCheck
from untrust.checks.imds_enforcement import ImdsEnforcementCheck
from untrust.checks.kms_attestation import KmsAttestationCheck
from untrust.checks.log_exposure import LogExposureCheck
from untrust.checks.nat_egress import NatEgressCheck
from untrust.checks.open_ports import OpenPortsCheck
from untrust.checks.rds_state import RdsStateCheck
from untrust.checks.restart_persistence import RestartPersistenceCheck
from untrust.checks.s3_encryption import S3EncryptionCheck
from untrust.checks.s3_public_access import S3PublicAccessCheck
from untrust.checks.secrets_manager import SecretsManagerCheck
from untrust.checks.ssh_hardening import SshHardeningCheck
from untrust.checks.ssm_parameter import SsmParameterCheck
from untrust.checks.state_rollback import StateRollbackCheck
from untrust.checks.swap_exposure import SwapExposureCheck
from untrust.checks.vpc_isolation import VpcIsolationCheck
from untrust.checks.vsock_exposure import VsockExposureCheck


class TestBootstrapInput:
    def test_skip_without_bucket(self) -> None:
        check = BootstrapInputCheck()
        target = Target(bucket=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.bootstrap_input.boto3")
    def test_fail_on_accepted_traversal(self, mock_boto3) -> None:
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.put_object.return_value = {}
        mock_s3.delete_object.return_value = {}

        check = BootstrapInputCheck()
        target = Target(bucket="test-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "path-traversal" in finding.summary.lower()
        assert "precondition" in finding.summary.lower()

    @patch("untrust.checks.bootstrap_input.boto3")
    def test_pass_on_rejected_traversal(self, mock_boto3) -> None:
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.put_object.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "PutObject",
        )

        check = BootstrapInputCheck()
        target = Target(bucket="test-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS
        assert "blocks" in finding.summary.lower()

    @patch("untrust.checks.bootstrap_input.boto3")
    def test_pass_on_400_rejected_write(self, mock_boto3) -> None:
        # A hardened bucket can reject the traversal write with a 400
        # (e.g. a policy/encryption condition surfaced as Bad Request),
        # not a 403 AccessDenied. The object still never lands, so this is
        # a PASS (blocked), not an ERROR.
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.put_object.side_effect = ClientError(
            {
                "Error": {"Code": "400", "Message": "Bad Request"},
                "ResponseMetadata": {"HTTPStatusCode": 400},
            },
            "PutObject",
        )

        check = BootstrapInputCheck()
        target = Target(bucket="test-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS
        assert "blocks" in finding.summary.lower()
        assert finding.evidence["block_reasons"]

    @patch("untrust.checks.bootstrap_input.boto3")
    def test_error_on_transient_5xx(self, mock_boto3) -> None:
        # Genuinely ambiguous server-side failures must not be reported as a
        # clean PASS — we cannot tell whether the write landed.
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.put_object.side_effect = ClientError(
            {
                "Error": {"Code": "InternalError", "Message": "We encountered an error"},
                "ResponseMetadata": {"HTTPStatusCode": 500},
            },
            "PutObject",
        )

        check = BootstrapInputCheck()
        target = Target(bucket="test-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.ERROR
        assert "transient" in finding.summary.lower()


class TestKmsAttestation:
    def test_skip_without_key(self) -> None:
        check = KmsAttestationCheck()
        target = Target(kms_key_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.kms_attestation.boto3")
    def test_fail_without_attestation(self, mock_boto3) -> None:
        mock_kms = MagicMock()
        mock_boto3.client.return_value = mock_kms
        mock_kms.get_key_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                }]
            })
        }

        check = KmsAttestationCheck()
        target = Target(kms_key_id="arn:aws:kms:us-west-2:111:key/abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "RecipientAttestation" in finding.summary

    @patch("untrust.checks.kms_attestation.boto3")
    def test_alias_is_resolved_before_get_key_policy(self, mock_boto3) -> None:
        # get_key_policy rejects aliases; the check must resolve via
        # describe_key first (regression for the live-run alias bug).
        mock_kms = MagicMock()
        mock_boto3.client.return_value = mock_kms
        mock_kms.describe_key.return_value = {
            "KeyMetadata": {"KeyId": "abcd-1234"}
        }
        mock_kms.get_key_policy.return_value = {"Policy": json.dumps({"Statement": []})}

        check = KmsAttestationCheck()
        target = Target(
            kms_key_id="alias/enclave-state-key",
            region="us-west-2",
        )
        finding = check.run(target)
        mock_kms.describe_key.assert_called_once_with(
            KeyId="alias/enclave-state-key"
        )
        mock_kms.get_key_policy.assert_called_once_with(
            KeyId="abcd-1234", PolicyName="default"
        )
        assert finding.status == Status.PASS

    @patch("untrust.checks.kms_attestation.boto3")
    def test_pass_with_attestation(self, mock_boto3) -> None:
        mock_kms = MagicMock()
        mock_boto3.client.return_value = mock_kms
        mock_kms.get_key_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111:role/enclave"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {
                        "StringEqualsIgnoreCase": {
                            "kms:RecipientAttestation:PCR0": "abc123"
                        }
                    },
                }]
            })
        }

        check = KmsAttestationCheck()
        target = Target(kms_key_id="arn:aws:kms:us-west-2:111:key/abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS

    @patch("untrust.checks.kms_attestation.boto3")
    def test_fail_attestation_in_deny_only(self, mock_boto3) -> None:
        """Attestation key in a Deny statement doesn't protect Allow+Decrypt."""
        mock_kms = MagicMock()
        mock_boto3.client.return_value = mock_kms
        mock_kms.get_key_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "kms:Decrypt",
                        "Resource": "*",
                        "Condition": {
                            "StringNotEquals": {
                                "kms:RecipientAttestation:PCR0": "abc123"
                            }
                        },
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::111:role/enc"},
                        "Action": "kms:Decrypt",
                        "Resource": "*",
                    },
                ]
            })
        }

        check = KmsAttestationCheck()
        target = Target(kms_key_id="arn:aws:kms:us-west-2:111:key/abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "1 of 1" in finding.summary

    @patch("untrust.checks.kms_attestation.boto3")
    def test_fail_mixed_statements(self, mock_boto3) -> None:
        """One Allow+Decrypt is protected, another is not."""
        mock_kms = MagicMock()
        mock_boto3.client.return_value = mock_kms
        mock_kms.get_key_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::111:role/enc"},
                        "Action": "kms:Decrypt",
                        "Resource": "*",
                        "Condition": {
                            "StringEqualsIgnoreCase": {
                                "kms:RecipientAttestation:PCR0": "abc"
                            }
                        },
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::111:root"},
                        "Action": ["kms:Decrypt", "kms:DescribeKey"],
                        "Resource": "*",
                    },
                ]
            })
        }

        check = KmsAttestationCheck()
        target = Target(kms_key_id="arn:aws:kms:us-west-2:111:key/abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "1 of 2" in finding.summary

    @patch("untrust.checks.kms_attestation.boto3")
    def test_pass_non_decrypt_without_attestation(self, mock_boto3) -> None:
        """Allow on kms:DescribeKey (not Decrypt) needs no attestation."""
        mock_kms = MagicMock()
        mock_boto3.client.return_value = mock_kms
        mock_kms.get_key_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111:root"},
                    "Action": "kms:DescribeKey",
                    "Resource": "*",
                }]
            })
        }

        check = KmsAttestationCheck()
        target = Target(kms_key_id="arn:aws:kms:us-west-2:111:key/abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS

    @patch("untrust.checks.kms_attestation.boto3")
    def test_fail_all_zeros_attestation(self, mock_boto3) -> None:
        """An all-zeros PCR value (debug bypass) must not count as protection."""
        mock_kms = MagicMock()
        mock_boto3.client.return_value = mock_kms
        mock_kms.get_key_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111:role/enc"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {
                        "StringEqualsIgnoreCase": {
                            "kms:RecipientAttestation:PCR0": "0" * 96
                        }
                    },
                }]
            })
        }

        check = KmsAttestationCheck()
        target = Target(kms_key_id="arn:aws:kms:us-west-2:111:key/abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "trivially satisfiable" in finding.summary

    @patch("untrust.checks.kms_attestation.boto3")
    def test_fail_identity_only_attestation(self, mock_boto3) -> None:
        """Binding only to PCR3/PCR4 (identity, not code) must fail."""
        mock_kms = MagicMock()
        mock_boto3.client.return_value = mock_kms
        mock_kms.get_key_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111:role/enc"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {
                        "StringEqualsIgnoreCase": {
                            "kms:RecipientAttestation:PCR3": "abc123",
                            "kms:RecipientAttestation:PCR4": "def456",
                        }
                    },
                }]
            })
        }

        check = KmsAttestationCheck()
        target = Target(kms_key_id="arn:aws:kms:us-west-2:111:key/abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "identity" in finding.summary.lower()

    @patch("untrust.checks.kms_attestation.boto3")
    def test_pass_pcr8_attestation(self, mock_boto3) -> None:
        """PCR8 (signing cert) is a valid code/identity measurement."""
        mock_kms = MagicMock()
        mock_boto3.client.return_value = mock_kms
        mock_kms.get_key_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111:role/enc"},
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {
                        "StringEqualsIgnoreCase": {
                            "kms:RecipientAttestation:PCR8": "a" * 96,
                            "kms:RecipientAttestation:PCR4": "def456",
                        }
                    },
                }]
            })
        }

        check = KmsAttestationCheck()
        target = Target(kms_key_id="arn:aws:kms:us-west-2:111:key/abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


class TestAuditLog:
    def test_skip_without_bucket(self) -> None:
        check = AuditLogCheck()
        target = Target(bucket=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.audit_log.boto3")
    def test_fail_versioning_disabled(self, mock_boto3) -> None:
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.get_bucket_versioning.return_value = {"Status": "Suspended"}
        mock_s3.get_bucket_logging.return_value = {}

        check = AuditLogCheck()
        target = Target(bucket="test-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL

    @patch("untrust.checks.audit_log.boto3")
    def test_pass_versioning_enabled(self, mock_boto3) -> None:
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
        mock_s3.get_bucket_logging.return_value = {
            "LoggingEnabled": {"TargetBucket": "logs"}
        }

        check = AuditLogCheck()
        target = Target(bucket="test-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


def _make_ssm_mocks(mock_boto3, stdout="", status="Success"):
    """Helper: wire up SSM send_command + get_command_invocation mocks."""
    mock_ssm = MagicMock()
    mock_boto3.client.return_value = mock_ssm
    mock_ssm.send_command.return_value = {
        "Command": {"CommandId": "cmd-123"}
    }
    mock_ssm.get_command_invocation.return_value = {
        "Status": status,
        "StandardOutputContent": stdout,
    }
    return mock_ssm


class TestNatEgress:
    def test_skip_without_instance(self) -> None:
        check = NatEgressCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.nat_egress.time")
    @patch("untrust.checks.nat_egress.boto3")
    def test_fail_no_imds_rules(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(mock_boto3, stdout="0")
        check = NatEgressCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "169.254.169.254" in finding.summary

    @patch("untrust.checks.nat_egress.time")
    @patch("untrust.checks.nat_egress.boto3")
    def test_pass_imds_blocked(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(mock_boto3, stdout="2")
        check = NatEgressCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS
        assert finding.evidence["imds_filter_rules"] == 2

    @patch("untrust.checks.nat_egress.boto3")
    def test_error_ssm_send_denied(self, mock_boto3) -> None:
        mock_ssm = MagicMock()
        mock_boto3.client.return_value = mock_ssm
        mock_ssm.send_command.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "SendCommand",
        )
        check = NatEgressCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.ERROR

    @patch("untrust.checks.nat_egress.time")
    @patch("untrust.checks.nat_egress.boto3")
    def test_error_ssm_timeout(self, mock_boto3, mock_time) -> None:
        mock_ssm = MagicMock()
        mock_boto3.client.return_value = mock_ssm
        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-123"}}
        mock_ssm.get_command_invocation.side_effect = ClientError(
            {"Error": {"Code": "InvocationDoesNotExist", "Message": ""}},
            "GetCommandInvocation",
        )
        check = NatEgressCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.ERROR
        assert "timeout" in finding.summary.lower()


class TestEnvVarSemantic:
    def test_skip_without_instance(self) -> None:
        check = EnvVarSemanticCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.env_var_semantic.time")
    @patch("untrust.checks.env_var_semantic.boto3")
    def test_pass_no_env_files(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(mock_boto3, stdout="NOT_FOUND")
        check = EnvVarSemanticCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS

    @patch("untrust.checks.env_var_semantic.time")
    @patch("untrust.checks.env_var_semantic.boto3")
    def test_fail_dangerous_vars(self, mock_boto3, mock_time) -> None:
        mock_ssm = MagicMock()
        mock_boto3.client.return_value = mock_ssm
        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-123"}}
        mock_ssm.get_command_invocation.side_effect = [
            {"Status": "Success", "StandardOutputContent": "HTTPS_PROXY=http://evil.com\nBUCKET_NAME=ok\n"},
            {"Status": "Success", "StandardOutputContent": "600 /opt/app/environment.conf\n"},
        ]
        check = EnvVarSemanticCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "HTTPS_PROXY" in finding.summary

    @patch("untrust.checks.env_var_semantic.time")
    @patch("untrust.checks.env_var_semantic.boto3")
    def test_fail_world_readable(self, mock_boto3, mock_time) -> None:
        mock_ssm = MagicMock()
        mock_boto3.client.return_value = mock_ssm
        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-123"}}
        mock_ssm.get_command_invocation.side_effect = [
            {"Status": "Success", "StandardOutputContent": "BUCKET_NAME=safe\n"},
            {"Status": "Success", "StandardOutputContent": "644 /opt/app/environment.conf\n"},
        ]
        check = EnvVarSemanticCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "world-readable" in finding.summary.lower()

    @patch("untrust.checks.env_var_semantic.time")
    @patch("untrust.checks.env_var_semantic.boto3")
    def test_pass_clean_config(self, mock_boto3, mock_time) -> None:
        mock_ssm = MagicMock()
        mock_boto3.client.return_value = mock_ssm
        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-123"}}
        mock_ssm.get_command_invocation.side_effect = [
            {"Status": "Success", "StandardOutputContent": "BUCKET_NAME=safe\nLOG_LEVEL=INFO\n"},
            {"Status": "Success", "StandardOutputContent": "600 /opt/app/environment.conf\n"},
        ]
        check = EnvVarSemanticCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


class TestBucketPolicy:
    def test_skip_without_bucket(self) -> None:
        check = BucketPolicyCheck()
        target = Target(bucket=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.bucket_policy.boto3")
    def test_fail_no_policy(self, mock_boto3) -> None:
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.get_bucket_policy.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": ""}},
            "GetBucketPolicy",
        )
        check = BucketPolicyCheck()
        target = Target(bucket="test-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "No bucket policy" in finding.summary

    @patch("untrust.checks.bucket_policy.boto3")
    def test_pass_with_deny(self, mock_boto3) -> None:
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.get_bucket_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [{
                    "Effect": "Deny",
                    "Action": "s3:PutObject",
                    "Principal": "*",
                    "Resource": "arn:aws:s3:::test-bucket/*",
                    "Condition": {
                        "StringNotEquals": {
                            "aws:PrincipalArn": "arn:aws:iam::111:role/enclave"
                        }
                    },
                }]
            })
        }
        check = BucketPolicyCheck()
        target = Target(bucket="test-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


class TestImdsEnforcement:
    def test_skip_without_instance(self) -> None:
        check = ImdsEnforcementCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.imds_enforcement.boto3")
    def test_fail_imdsv1(self, mock_boto3) -> None:
        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{
                "InstanceId": "i-abc",
                "MetadataOptions": {
                    "HttpTokens": "optional",
                    "HttpEndpoint": "enabled",
                    "HttpPutResponseHopLimit": 1,
                },
            }]}]
        }
        check = ImdsEnforcementCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "optional" in finding.summary

    @patch("untrust.checks.imds_enforcement.boto3")
    def test_pass_imdsv2(self, mock_boto3) -> None:
        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{
                "InstanceId": "i-abc",
                "MetadataOptions": {
                    "HttpTokens": "required",
                    "HttpEndpoint": "enabled",
                    "HttpPutResponseHopLimit": 1,
                },
            }]}]
        }
        check = ImdsEnforcementCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


class TestIamScope:
    def test_skip_without_instance(self) -> None:
        check = IamScopeCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.iam_scope.boto3")
    def test_fail_wildcard_resource(self, mock_boto3) -> None:
        mock_ec2 = MagicMock()
        mock_iam = MagicMock()

        def client_factory(service, **kwargs):
            if service == "ec2":
                return mock_ec2
            return mock_iam

        mock_boto3.client.side_effect = client_factory
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{
                "InstanceId": "i-abc",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111:instance-profile/my-profile"
                },
            }]}]
        }
        mock_iam.get_instance_profile.return_value = {
            "InstanceProfile": {
                "Roles": [{"RoleName": "my-role"}]
            }
        }
        mock_iam.list_role_policies.return_value = {
            "PolicyNames": ["S3Access"]
        }
        mock_iam.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "*",
                }]
            }
        }
        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": []
        }

        check = IamScopeCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "wildcard" in finding.summary.lower()


class TestSshHardening:
    def test_skip_without_instance(self) -> None:
        check = SshHardeningCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.ssh_hardening.time")
    @patch("untrust.checks.ssh_hardening.boto3")
    def test_fail_ssh_active(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout="SSH_STATUS=active\nEC2IC_INSTALLED=ec2-instance-connect-1.0\nSSH_PORT=0.0.0.0:22\n",
        )
        check = SshHardeningCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "SSH" in finding.summary

    @patch("untrust.checks.ssh_hardening.time")
    @patch("untrust.checks.ssh_hardening.boto3")
    def test_pass_ssh_disabled(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout="SSH_STATUS=inactive\nEC2IC_INSTALLED=not_installed\nSSH_PORT=none\n",
        )
        check = SshHardeningCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


class TestHostPermissions:
    def test_skip_without_instance(self) -> None:
        check = HostPermissionsCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.host_permissions.time")
    @patch("untrust.checks.host_permissions.boto3")
    def test_fail_world_readable(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout=(
                "644 /opt/enclave/environment.conf\n"
                "644 /opt/enclave/enclave-app.eif\n"
                "600 /opt/enclave/db.key\n"
            ),
        )
        check = HostPermissionsCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "2 sensitive file" in finding.summary

    @patch("untrust.checks.host_permissions.time")
    @patch("untrust.checks.host_permissions.boto3")
    def test_pass_restricted(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout="600 /opt/enclave/environment.conf\n600 /opt/enclave/db.key\n",
        )
        check = HostPermissionsCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


class TestHostServices:
    def test_skip_without_instance(self) -> None:
        check = HostServicesCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.host_services.time")
    @patch("untrust.checks.host_services.boto3")
    def test_fail_root_services(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout="enclave-app.service:root\nenclave-app-networking.service:root\n",
        )
        check = HostServicesCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "2 enclave service" in finding.summary

    @patch("untrust.checks.host_services.time")
    @patch("untrust.checks.host_services.boto3")
    def test_pass_unprivileged(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout="enclave-app.service:enclave\nenclave-app-networking.service:enclave\n",
        )
        check = HostServicesCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


class TestDnsDnat:
    def test_skip_without_instance(self) -> None:
        check = DnsDnatCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.dns_dnat.time")
    @patch("untrust.checks.dns_dnat.boto3")
    def test_fail_dnat_found(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout="18 1405 DNAT udp -- * * 1.1.1.1 0.0.0.0/0 udp dpt:53 to:10.0.0.2:53\n",
        )
        check = DnsDnatCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "DNAT" in finding.summary

    @patch("untrust.checks.dns_dnat.time")
    @patch("untrust.checks.dns_dnat.boto3")
    def test_pass_no_dnat(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(mock_boto3, stdout="NONE")
        check = DnsDnatCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


class TestOpenPorts:
    def test_skip_without_instance(self) -> None:
        check = OpenPortsCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.open_ports.time")
    @patch("untrust.checks.open_ports.boto3")
    def test_fail_unexpected_ports(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(mock_boto3, stdout="22\n8080\n")
        check = OpenPortsCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "22" in finding.summary

    @patch("untrust.checks.open_ports.time")
    @patch("untrust.checks.open_ports.boto3")
    def test_pass_no_listeners(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(mock_boto3, stdout="")
        check = OpenPortsCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


class TestVsockExposure:
    def test_skip_without_instance(self) -> None:
        check = VsockExposureCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.vsock_exposure.time")
    @patch("untrust.checks.vsock_exposure.boto3")
    def test_fail_vsock_listeners(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout="u_str LISTEN 0 5 vm(3):9000\nu_str LISTEN 0 5 vm(3):9001\n",
        )
        check = VsockExposureCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "2 vsock" in finding.summary

    @patch("untrust.checks.vsock_exposure.time")
    @patch("untrust.checks.vsock_exposure.boto3")
    def test_pass_no_vsock(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(mock_boto3, stdout="NONE")
        check = VsockExposureCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


class TestS3PublicAccess:
    def test_skip_without_bucket(self) -> None:
        check = S3PublicAccessCheck()
        target = Target(bucket=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.s3_public_access.boto3")
    def test_fail_no_config(self, mock_boto3) -> None:
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.get_public_access_block.side_effect = ClientError(
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": ""}},
            "GetPublicAccessBlock",
        )
        check = S3PublicAccessCheck()
        target = Target(bucket="test-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "No PublicAccessBlock" in finding.summary

    @patch("untrust.checks.s3_public_access.boto3")
    def test_pass_all_enabled(self, mock_boto3) -> None:
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        check = S3PublicAccessCheck()
        target = Target(bucket="test-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


class TestVpcIsolation:
    def test_skip_without_instance(self) -> None:
        check = VpcIsolationCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.vpc_isolation.boto3")
    def test_fail_public_ip(self, mock_boto3) -> None:
        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{
                "InstanceId": "i-abc",
                "VpcId": "vpc-123",
                "PublicIpAddress": "1.2.3.4",
            }]}]
        }
        mock_ec2.describe_vpc_peering_connections.return_value = {
            "VpcPeeringConnections": []
        }
        mock_ec2.describe_transit_gateway_vpc_attachments.return_value = {
            "TransitGatewayVpcAttachments": []
        }
        check = VpcIsolationCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "public IP" in finding.summary

    @patch("untrust.checks.vpc_isolation.boto3")
    def test_pass_isolated(self, mock_boto3) -> None:
        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{
                "InstanceId": "i-abc",
                "VpcId": "vpc-123",
            }]}]
        }
        mock_ec2.describe_vpc_peering_connections.return_value = {
            "VpcPeeringConnections": []
        }
        mock_ec2.describe_transit_gateway_vpc_attachments.return_value = {
            "TransitGatewayVpcAttachments": []
        }
        check = VpcIsolationCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


class TestEnclaveDebug:
    def test_skip_without_instance(self) -> None:
        check = EnclaveDebugCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.enclave_debug.time")
    @patch("untrust.checks.enclave_debug.boto3")
    def test_fail_debug_mode(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout=json.dumps([{
                "EnclaveID": "i-abc-enc-001",
                "Flags": "DEBUG_MODE",
                "State": "RUNNING",
                "Measurements": {},
            }]),
        )
        check = EnclaveDebugCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "debug" in finding.summary.lower()

    @patch("untrust.checks.enclave_debug.time")
    @patch("untrust.checks.enclave_debug.boto3")
    def test_pass_production(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout=json.dumps([{
                "EnclaveID": "i-abc-enc-001",
                "Flags": "NONE",
                "State": "RUNNING",
                "Measurements": {"PCR0": "abc123"},
            }]),
        )
        check = EnclaveDebugCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


class TestEnclavePcr:
    def test_skip_without_instance(self) -> None:
        check = EnclavePcrCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.enclave_pcr.time")
    @patch("untrust.checks.enclave_pcr.boto3")
    def test_fail_zeroed_pcr(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout=json.dumps([{
                "EnclaveID": "i-abc-enc-001",
                "State": "RUNNING",
                "Measurements": {
                    "PCR0": "0" * 96,
                    "PCR1": "0" * 96,
                    "PCR2": "0" * 96,
                },
            }]),
        )
        check = EnclavePcrCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "zeroed" in finding.summary.lower()

    @patch("untrust.checks.enclave_pcr.time")
    @patch("untrust.checks.enclave_pcr.boto3")
    def test_pass_valid_pcr(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout=json.dumps([{
                "EnclaveID": "i-abc-enc-001",
                "State": "RUNNING",
                "Measurements": {
                    "PCR0": "a" * 96,
                    "PCR1": "b" * 96,
                    "PCR2": "c" * 96,
                },
            }]),
        )
        check = EnclavePcrCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


class TestExecPermissions:
    def test_skip_without_instance(self) -> None:
        check = ExecPermissionsCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.exec_permissions.time")
    @patch("untrust.checks.exec_permissions.boto3")
    def test_fail_executable_files(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout="/opt/enclave/run.sh\n/opt/enclave/migrate.py\n",
        )
        check = ExecPermissionsCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "2 file(s)" in finding.summary

    @patch("untrust.checks.exec_permissions.time")
    @patch("untrust.checks.exec_permissions.boto3")
    def test_pass_no_executables(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(mock_boto3, stdout="NONE")
        check = ExecPermissionsCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


# ── CORE-01: Core dump exposure ─────────────────────────────────────


class TestCoreDump:
    def test_skip_without_instance(self) -> None:
        check = CoreDumpCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.core_dump.time")
    @patch("untrust.checks.core_dump.boto3")
    def test_fail_dumps_enabled(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout=(
                "CORE_PATTERN=|/usr/lib/systemd/systemd-coredump\n"
                "ULIMIT_CORE=unlimited"
            ),
        )
        check = CoreDumpCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "core_pattern" in finding.summary.lower() or "Core dump" in finding.summary

    @patch("untrust.checks.core_dump.time")
    @patch("untrust.checks.core_dump.boto3")
    def test_pass_dumps_disabled(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout="CORE_PATTERN=|/bin/false\nULIMIT_CORE=0",
        )
        check = CoreDumpCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


# ── SWAP-01: Swap exposure ──────────────────────────────────────────


class TestSwapExposure:
    def test_skip_without_instance(self) -> None:
        check = SwapExposureCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.swap_exposure.time")
    @patch("untrust.checks.swap_exposure.boto3")
    def test_fail_swap_active(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout="/dev/xvda2 partition 2G 0B -2",
        )
        check = SwapExposureCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "1 swap device" in finding.summary

    @patch("untrust.checks.swap_exposure.time")
    @patch("untrust.checks.swap_exposure.boto3")
    def test_pass_no_swap(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(mock_boto3, stdout="NONE")
        check = SwapExposureCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


# ── LOG-01: Enclave log exposure ────────────────────────────────────


class TestLogExposure:
    def test_skip_without_instance(self) -> None:
        check = LogExposureCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.log_exposure.time")
    @patch("untrust.checks.log_exposure.boto3")
    def test_fail_world_readable(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout=(
                "STORAGE=Storage=auto\n"
                "JOURNAL_PERMS=755\n"
                "JOURNAL_GROUP=systemd-journal\n"
                "JOURNAL_USERS=ssm-user"
            ),
        )
        check = LogExposureCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        summary = finding.summary.lower()
        assert "world-readable" in summary or "accessible" in summary

    @patch("untrust.checks.log_exposure.time")
    @patch("untrust.checks.log_exposure.boto3")
    def test_pass_restricted(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout=(
                "STORAGE=Storage=auto\n"
                "JOURNAL_PERMS=750\n"
                "JOURNAL_GROUP=root\n"
                "JOURNAL_USERS=none"
            ),
        )
        check = LogExposureCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


# ── ENCLAVE-03: Multi-enclave co-tenancy ────────────────────────────


class TestEnclaveCotenant:
    def test_skip_without_instance(self) -> None:
        check = EnclaveCotenantCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.enclave_cotenant.time")
    @patch("untrust.checks.enclave_cotenant.boto3")
    def test_fail_multiple_enclaves(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout=json.dumps([
                {"EnclaveID": "enc-001", "State": "RUNNING"},
                {"EnclaveID": "enc-002", "State": "RUNNING"},
            ]),
        )
        check = EnclaveCotenantCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "2 enclaves" in finding.summary

    @patch("untrust.checks.enclave_cotenant.time")
    @patch("untrust.checks.enclave_cotenant.boto3")
    def test_pass_single_enclave(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout=json.dumps([
                {"EnclaveID": "enc-001", "State": "RUNNING"},
            ]),
        )
        check = EnclaveCotenantCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


# ── RESTART-01: Crash handler re-download persistence ───────────────


class TestRestartPersistence:
    def test_skip_without_instance(self) -> None:
        check = RestartPersistenceCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.restart_persistence.time")
    @patch("untrust.checks.restart_persistence.boto3")
    def test_fail_restart_always(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout="enclave-app.service:always:s3\n",
        )
        check = RestartPersistenceCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "auto-restart" in finding.summary

    @patch("untrust.checks.restart_persistence.time")
    @patch("untrust.checks.restart_persistence.boto3")
    def test_pass_no_restart(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(mock_boto3, stdout="NONE")
        check = RestartPersistenceCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


# ── S3-02: State bucket encryption + TLS-only ───────────────────────


class TestS3Encryption:
    def test_skip_without_bucket(self) -> None:
        check = S3EncryptionCheck()
        target = Target(bucket=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.s3_encryption.boto3")
    def test_pass_kms_and_tls(self, mock_boto3) -> None:
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms"
                    }
                }]
            }
        }
        mock_s3.get_bucket_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [{
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }]
            })
        }
        check = S3EncryptionCheck()
        target = Target(bucket="state-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS

    @patch("untrust.checks.s3_encryption.boto3")
    def test_fail_no_encryption_no_tls(self, mock_boto3) -> None:
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.get_bucket_encryption.side_effect = ClientError(
            {"Error": {
                "Code": "ServerSideEncryptionConfigurationNotFoundError",
                "Message": "",
            }},
            "GetBucketEncryption",
        )
        mock_s3.get_bucket_policy.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": ""}},
            "GetBucketPolicy",
        )
        check = S3EncryptionCheck()
        target = Target(bucket="state-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "encryption" in finding.summary.lower()
        assert "tls" in finding.summary.lower() or "securetransport" in finding.summary.lower()

    @patch("untrust.checks.s3_encryption.boto3")
    def test_fail_aes256_flagged(self, mock_boto3) -> None:
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }]
            }
        }
        mock_s3.get_bucket_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [{
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }]
            })
        }
        check = S3EncryptionCheck()
        target = Target(bucket="state-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "SSE-KMS" in finding.summary


# ── ROLLBACK-01: Anti-rollback (S3 Object Lock) ─────────────────────


class TestStateRollback:
    def test_skip_without_bucket(self) -> None:
        check = StateRollbackCheck()
        target = Target(bucket=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.state_rollback.boto3")
    def test_fail_no_object_lock(self, mock_boto3) -> None:
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.get_object_lock_configuration.side_effect = ClientError(
            {"Error": {
                "Code": "ObjectLockConfigurationNotFoundError",
                "Message": "",
            }},
            "GetObjectLockConfiguration",
        )
        check = StateRollbackCheck()
        target = Target(bucket="state-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "roll" in finding.summary.lower()

    @patch("untrust.checks.state_rollback.boto3")
    def test_pass_object_lock_enabled(self, mock_boto3) -> None:
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.get_object_lock_configuration.return_value = {
            "ObjectLockConfiguration": {
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 30}},
            }
        }
        check = StateRollbackCheck()
        target = Target(bucket="state-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS

    @patch("untrust.checks.state_rollback.boto3")
    def test_fail_enabled_no_retention(self, mock_boto3) -> None:
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.get_object_lock_configuration.return_value = {
            "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}
        }
        check = StateRollbackCheck()
        target = Target(bucket="state-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "retention" in finding.summary.lower()


# ── CLOUDTRAIL-01: Audit trail for enclave ops ──────────────────────


class TestCloudTrailAudit:
    @patch("untrust.checks.cloudtrail_audit.boto3")
    def test_fail_no_trail(self, mock_boto3) -> None:
        mock_ct = MagicMock()
        mock_boto3.client.return_value = mock_ct
        mock_ct.describe_trails.return_value = {"trailList": []}
        check = CloudTrailAuditCheck()
        target = Target(region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "No CloudTrail" in finding.summary

    @patch("untrust.checks.cloudtrail_audit.boto3")
    def test_fail_not_logging(self, mock_boto3) -> None:
        mock_ct = MagicMock()
        mock_boto3.client.return_value = mock_ct
        mock_ct.describe_trails.return_value = {
            "trailList": [{
                "Name": "t1", "TrailARN": "arn:t1",
                "IsMultiRegionTrail": True,
            }]
        }
        mock_ct.get_trail_status.return_value = {"IsLogging": False}
        mock_ct.get_event_selectors.return_value = {}
        check = CloudTrailAuditCheck()
        target = Target(region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "logging" in finding.summary.lower()

    @patch("untrust.checks.cloudtrail_audit.boto3")
    def test_fail_no_s3_data_events(self, mock_boto3) -> None:
        mock_ct = MagicMock()
        mock_boto3.client.return_value = mock_ct
        mock_ct.describe_trails.return_value = {
            "trailList": [{
                "Name": "t1", "TrailARN": "arn:t1",
                "IsMultiRegionTrail": True,
            }]
        }
        mock_ct.get_trail_status.return_value = {"IsLogging": True}
        mock_ct.get_event_selectors.return_value = {
            "EventSelectors": [{"DataResources": []}]
        }
        check = CloudTrailAuditCheck()
        target = Target(bucket="state-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "data event" in finding.summary.lower()

    @patch("untrust.checks.cloudtrail_audit.boto3")
    def test_pass_logging_with_s3_data(self, mock_boto3) -> None:
        mock_ct = MagicMock()
        mock_boto3.client.return_value = mock_ct
        mock_ct.describe_trails.return_value = {
            "trailList": [{
                "Name": "t1", "TrailARN": "arn:t1",
                "IsMultiRegionTrail": True,
            }]
        }
        mock_ct.get_trail_status.return_value = {"IsLogging": True}
        mock_ct.get_event_selectors.return_value = {
            "EventSelectors": [{
                "DataResources": [{
                    "Type": "AWS::S3::Object",
                    "Values": ["arn:aws:s3:::state-bucket/"],
                }]
            }]
        }
        check = CloudTrailAuditCheck()
        target = Target(bucket="state-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS

    @patch("untrust.checks.cloudtrail_audit.boto3")
    def test_pass_advanced_selectors(self, mock_boto3) -> None:
        mock_ct = MagicMock()
        mock_boto3.client.return_value = mock_ct
        mock_ct.describe_trails.return_value = {
            "trailList": [{
                "Name": "t1", "TrailARN": "arn:t1",
                "IsMultiRegionTrail": True,
            }]
        }
        mock_ct.get_trail_status.return_value = {"IsLogging": True}
        mock_ct.get_event_selectors.return_value = {
            "AdvancedEventSelectors": [{
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                ]
            }]
        }
        check = CloudTrailAuditCheck()
        target = Target(bucket="state-bucket", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS


# ── ENCLAVE-04: Signed EIF / PCR8 ───────────────────────────────────


class TestEnclaveSigned:
    def test_skip_without_instance(self) -> None:
        check = EnclaveSignedCheck()
        target = Target(instance_id=None, region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks.enclave_signed.time")
    @patch("untrust.checks.enclave_signed.boto3")
    def test_pass_signed(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout=json.dumps({
                "Measurements": {"PCR0": "a" * 96, "PCR8": "b" * 96},
                "SignatureCheck": True,
            }),
        )
        check = EnclaveSignedCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS

    @patch("untrust.checks.enclave_signed.time")
    @patch("untrust.checks.enclave_signed.boto3")
    def test_fail_unsigned(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout=json.dumps({
                "Measurements": {"PCR0": "a" * 96, "PCR1": "c" * 96},
            }),
        )
        check = EnclaveSignedCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "unsigned" in finding.summary.lower()

    @patch("untrust.checks.enclave_signed.time")
    @patch("untrust.checks.enclave_signed.boto3")
    def test_fail_bad_signature(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(
            mock_boto3,
            stdout=json.dumps({
                "Measurements": {"PCR8": "b" * 96},
                "SignatureCheck": False,
            }),
        )
        check = EnclaveSignedCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "signature" in finding.summary.lower()

    @patch("untrust.checks.enclave_signed.time")
    @patch("untrust.checks.enclave_signed.boto3")
    def test_error_no_eif(self, mock_boto3, mock_time) -> None:
        _make_ssm_mocks(mock_boto3, stdout="NO_EIF")
        check = EnclaveSignedCheck()
        target = Target(instance_id="i-abc", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.ERROR


# ── Alternative state backends (DynamoDB/Secrets/SSM/EFS/RDS) ────────

_CMK_ARN = "arn:aws:kms:us-west-2:111122223333:key/abcd-1234"
_AUDITED = {"logging": ["t1"], "data_events": ["t1"], "error": None}
_UNAUDITED = {"logging": ["t1"], "data_events": [], "error": None}


def _util_kms(mock_util_boto3, key_manager: str = "CUSTOMER") -> None:
    """Wire untrust.checks._backend_util.boto3 so classify_kms_key resolves
    a key to the given KeyManager ("CUSTOMER" or "AWS")."""
    mock_kms = MagicMock()
    mock_util_boto3.client.return_value = mock_kms
    mock_kms.describe_key.return_value = {
        "KeyMetadata": {"KeyManager": key_manager}
    }


# ── DDB-01: DynamoDB state table ────────────────────────────────────


class TestDynamoDbState:
    def test_skip_without_table(self) -> None:
        check = DynamoDbStateCheck()
        target = Target(region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks._backend_util.boto3")
    @patch("untrust.checks.dynamodb_state.cloudtrail_data_events")
    @patch("untrust.checks.dynamodb_state.boto3")
    def test_pass_hardened(self, mock_boto3, mock_ct, mock_util) -> None:
        _util_kms(mock_util)
        mock_ddb = MagicMock()
        mock_boto3.client.return_value = mock_ddb
        mock_ddb.describe_table.return_value = {
            "Table": {
                "TableArn": "arn:aws:dynamodb:us-west-2:111:table/state",
                "SSEDescription": {
                    "SSEType": "KMS",
                    "KMSMasterKeyArn": _CMK_ARN,
                },
                "DeletionProtectionEnabled": True,
            }
        }
        mock_ddb.describe_continuous_backups.return_value = {
            "ContinuousBackupsDescription": {
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": "ENABLED"
                }
            }
        }
        mock_ddb.get_resource_policy.return_value = {"Policy": "{}"}
        mock_ct.return_value = _AUDITED
        check = DynamoDbStateCheck()
        target = Target(dynamodb_table="state", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS

    @patch("untrust.checks.dynamodb_state.cloudtrail_data_events")
    @patch("untrust.checks.dynamodb_state.boto3")
    def test_fail_aws_owned_key_no_pitr(self, mock_boto3, mock_ct) -> None:
        mock_ddb = MagicMock()
        mock_boto3.client.return_value = mock_ddb
        mock_ddb.describe_table.return_value = {
            "Table": {
                "TableArn": "arn:aws:dynamodb:us-west-2:111:table/state",
                "DeletionProtectionEnabled": False,
            }
        }
        mock_ddb.describe_continuous_backups.return_value = {
            "ContinuousBackupsDescription": {
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": "DISABLED"
                }
            }
        }
        mock_ddb.get_resource_policy.side_effect = ClientError(
            {"Error": {"Code": "PolicyNotFoundException", "Message": ""}},
            "GetResourcePolicy",
        )
        mock_ct.return_value = _UNAUDITED
        check = DynamoDbStateCheck()
        target = Target(dynamodb_table="state", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "aws-owned" in finding.summary.lower()
        assert "point-in-time" in finding.summary.lower()

    @patch("untrust.checks._backend_util.boto3")
    @patch("untrust.checks.dynamodb_state.cloudtrail_data_events")
    @patch("untrust.checks.dynamodb_state.boto3")
    def test_fail_aws_managed_key_resolved(
        self, mock_boto3, mock_ct, mock_util
    ) -> None:
        # KMSMasterKeyArn is a full key ARN (indistinguishable from a CMK by
        # string), but DescribeKey resolves it to an AWS-managed key. This is
        # the false-PASS the string heuristic used to allow.
        _util_kms(mock_util, key_manager="AWS")
        mock_ddb = MagicMock()
        mock_boto3.client.return_value = mock_ddb
        mock_ddb.describe_table.return_value = {
            "Table": {
                "TableArn": "arn:aws:dynamodb:us-west-2:111:table/state",
                "SSEDescription": {
                    "SSEType": "KMS",
                    "KMSMasterKeyArn": _CMK_ARN,
                },
                "DeletionProtectionEnabled": True,
            }
        }
        mock_ddb.describe_continuous_backups.return_value = {
            "ContinuousBackupsDescription": {
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": "ENABLED"
                }
            }
        }
        mock_ddb.get_resource_policy.return_value = {"Policy": "{}"}
        mock_ct.return_value = _AUDITED
        check = DynamoDbStateCheck()
        target = Target(dynamodb_table="state", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "aws-managed" in finding.summary.lower()

    @patch("untrust.checks._backend_util.boto3")
    @patch("untrust.checks.dynamodb_state.cloudtrail_data_events")
    @patch("untrust.checks.dynamodb_state.boto3")
    def test_fail_cmk_unverifiable(
        self, mock_boto3, mock_ct, mock_util
    ) -> None:
        # DescribeKey denied → CMK status cannot be verified; must not PASS.
        mock_kms = MagicMock()
        mock_util.client.return_value = mock_kms
        mock_kms.describe_key.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": ""}},
            "DescribeKey",
        )
        mock_ddb = MagicMock()
        mock_boto3.client.return_value = mock_ddb
        mock_ddb.describe_table.return_value = {
            "Table": {
                "TableArn": "arn:aws:dynamodb:us-west-2:111:table/state",
                "SSEDescription": {
                    "SSEType": "KMS",
                    "KMSMasterKeyArn": _CMK_ARN,
                },
                "DeletionProtectionEnabled": True,
            }
        }
        mock_ddb.describe_continuous_backups.return_value = {
            "ContinuousBackupsDescription": {
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": "ENABLED"
                }
            }
        }
        mock_ddb.get_resource_policy.return_value = {"Policy": "{}"}
        mock_ct.return_value = _AUDITED
        check = DynamoDbStateCheck()
        target = Target(dynamodb_table="state", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "could not verify" in finding.summary.lower()
        assert "kms:describekey" in finding.summary.lower()


# ── SECRETS-01: Secrets Manager secret ──────────────────────────────


class TestSecretsManager:
    def test_skip_without_secret(self) -> None:
        check = SecretsManagerCheck()
        target = Target(region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks._backend_util.boto3")
    @patch("untrust.checks.secrets_manager.cloudtrail_data_events")
    @patch("untrust.checks.secrets_manager.boto3")
    def test_pass_hardened(self, mock_boto3, mock_ct, mock_util) -> None:
        _util_kms(mock_util)
        mock_sm = MagicMock()
        mock_boto3.client.return_value = mock_sm
        mock_sm.describe_secret.return_value = {
            "KmsKeyId": _CMK_ARN,
            "RotationEnabled": True,
        }
        mock_sm.get_resource_policy.return_value = {
            "ResourcePolicy": json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111:role/enclave"},
                    "Action": "secretsmanager:GetSecretValue",
                }]
            })
        }
        mock_ct.return_value = _AUDITED
        check = SecretsManagerCheck()
        target = Target(secret_arn="arn:aws:secretsmanager:...:s", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS

    @patch("untrust.checks.secrets_manager.cloudtrail_data_events")
    @patch("untrust.checks.secrets_manager.boto3")
    def test_fail_default_key_wildcard(self, mock_boto3, mock_ct) -> None:
        mock_sm = MagicMock()
        mock_boto3.client.return_value = mock_sm
        mock_sm.describe_secret.return_value = {
            "KmsKeyId": "alias/aws/secretsmanager",
            "RotationEnabled": False,
        }
        mock_sm.get_resource_policy.return_value = {
            "ResourcePolicy": json.dumps({
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "secretsmanager:GetSecretValue",
                }]
            })
        }
        mock_ct.return_value = _UNAUDITED
        check = SecretsManagerCheck()
        target = Target(secret_arn="arn:aws:secretsmanager:...:s", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "aws-managed" in finding.summary.lower()
        assert "wildcard" in finding.summary.lower()


# ── SSM-01: Parameter Store ─────────────────────────────────────────


class TestSsmParameter:
    def test_skip_without_path(self) -> None:
        check = SsmParameterCheck()
        target = Target(region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks._backend_util.boto3")
    @patch("untrust.checks.ssm_parameter.boto3")
    def test_pass_securestring_cmk(self, mock_boto3, mock_util) -> None:
        _util_kms(mock_util)
        mock_ssm = MagicMock()
        mock_boto3.client.return_value = mock_ssm
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "Parameters": [
                {"Name": "/enclave/a", "Type": "SecureString", "KeyId": _CMK_ARN},
            ]
        }]
        mock_ssm.get_paginator.return_value = paginator
        check = SsmParameterCheck()
        target = Target(parameter_path="/enclave/", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS

    @patch("untrust.checks.ssm_parameter.boto3")
    def test_fail_plaintext_and_default_key(self, mock_boto3) -> None:
        mock_ssm = MagicMock()
        mock_boto3.client.return_value = mock_ssm
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "Parameters": [
                {"Name": "/enclave/a", "Type": "String"},
                {"Name": "/enclave/b", "Type": "SecureString",
                 "KeyId": "alias/aws/ssm"},
            ]
        }]
        mock_ssm.get_paginator.return_value = paginator
        check = SsmParameterCheck()
        target = Target(parameter_path="/enclave/", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "plaintext" in finding.summary.lower()
        assert "aws-managed" in finding.summary.lower()

    @patch("untrust.checks.ssm_parameter.boto3")
    def test_skip_when_no_params(self, mock_boto3) -> None:
        mock_ssm = MagicMock()
        mock_boto3.client.return_value = mock_ssm
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Parameters": []}]
        mock_ssm.get_paginator.return_value = paginator
        check = SsmParameterCheck()
        target = Target(parameter_path="/none/", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP


# ── EFS-01: EFS state filesystem ────────────────────────────────────


class TestEfsState:
    def test_skip_without_efs(self) -> None:
        check = EfsStateCheck()
        target = Target(region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks._backend_util.boto3")
    @patch("untrust.checks.efs_state.boto3")
    def test_pass_hardened(self, mock_boto3, mock_util) -> None:
        _util_kms(mock_util)
        mock_efs = MagicMock()
        mock_boto3.client.return_value = mock_efs
        mock_efs.describe_file_systems.return_value = {
            "FileSystems": [{"Encrypted": True, "KmsKeyId": _CMK_ARN}]
        }
        mock_efs.describe_file_system_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [{
                    "Effect": "Deny",
                    "Principal": {"AWS": "*"},
                    "Action": "*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }]
            })
        }
        mock_efs.describe_backup_policy.return_value = {
            "BackupPolicy": {"Status": "ENABLED"}
        }
        check = EfsStateCheck()
        target = Target(efs_id="fs-123", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS

    @patch("untrust.checks.efs_state.boto3")
    def test_fail_unencrypted_no_policy(self, mock_boto3) -> None:
        mock_efs = MagicMock()
        mock_boto3.client.return_value = mock_efs
        mock_efs.describe_file_systems.return_value = {
            "FileSystems": [{"Encrypted": False}]
        }
        mock_efs.describe_file_system_policy.side_effect = ClientError(
            {"Error": {"Code": "PolicyNotFound", "Message": ""}},
            "DescribeFileSystemPolicy",
        )
        mock_efs.describe_backup_policy.return_value = {
            "BackupPolicy": {"Status": "DISABLED"}
        }
        check = EfsStateCheck()
        target = Target(efs_id="fs-123", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "not encrypted" in finding.summary.lower()
        assert "no filesystem policy" in finding.summary.lower()


# ── RDS-01: RDS/Aurora state database ───────────────────────────────


class TestRdsState:
    def test_skip_without_db(self) -> None:
        check = RdsStateCheck()
        target = Target(region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.SKIP

    @patch("untrust.checks._backend_util.boto3")
    @patch("untrust.checks.rds_state.boto3")
    def test_pass_hardened(self, mock_boto3, mock_util) -> None:
        _util_kms(mock_util)
        mock_rds = MagicMock()
        mock_ec2 = MagicMock()

        def _client(name, **kwargs):
            return mock_rds if name == "rds" else mock_ec2

        mock_boto3.client.side_effect = _client
        mock_rds.describe_db_instances.return_value = {
            "DBInstances": [{
                "StorageEncrypted": True,
                "KmsKeyId": _CMK_ARN,
                "PubliclyAccessible": False,
                "VpcSecurityGroups": [
                    {"VpcSecurityGroupId": "sg-1", "Status": "active"}
                ],
                "IAMDatabaseAuthenticationEnabled": True,
                "DeletionProtection": True,
            }]
        }
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-1",
                "IpPermissions": [{
                    "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
                }],
            }]
        }
        mock_rds.describe_db_snapshots.return_value = {"DBSnapshots": []}
        check = RdsStateCheck()
        target = Target(db_instance="prod-db", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.PASS

    @patch("untrust.checks.rds_state.boto3")
    def test_fail_public_open_sg(self, mock_boto3) -> None:
        mock_rds = MagicMock()
        mock_ec2 = MagicMock()

        def _client(name, **kwargs):
            return mock_rds if name == "rds" else mock_ec2

        mock_boto3.client.side_effect = _client
        mock_rds.describe_db_instances.return_value = {
            "DBInstances": [{
                "StorageEncrypted": False,
                "PubliclyAccessible": True,
                "VpcSecurityGroups": [
                    {"VpcSecurityGroupId": "sg-1", "Status": "active"}
                ],
                "IAMDatabaseAuthenticationEnabled": False,
                "DeletionProtection": False,
            }]
        }
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-1",
                "IpPermissions": [{
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }],
            }]
        }
        mock_rds.describe_db_snapshots.return_value = {"DBSnapshots": []}
        check = RdsStateCheck()
        target = Target(db_instance="prod-db", region="us-west-2")
        finding = check.run(target)
        assert finding.status == Status.FAIL
        assert "publicly accessible" in finding.summary.lower()
        assert "0.0.0.0/0" in finding.summary
