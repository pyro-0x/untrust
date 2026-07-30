"""Demo mode — simulates a scan against a vulnerable deployment.

Used for conference demos and testing. Does not require AWS credentials
or a real deployment. Returns realistic findings that match the DEF CON 34
talk's scenario.

All output is watermarked with a SIMULATED banner to prevent
out-of-context screenshots being mistaken for live scan results.
"""
from __future__ import annotations

from .checks.base import Finding, Severity, Status, Target


def run_demo() -> tuple[Target, list[Finding]]:
    """Return a simulated target and findings for demo purposes."""
    target = Target(
        bucket="enclave-state-XXXXXXXXXXXX",
        kms_key_id="arn:aws:kms:us-west-2:XXXXXXXXXXXX:key/demo-key-id",
        instance_id="i-0abc123def456789a",
        region="us-west-2",
    )

    findings = [
        Finding(
            check_id="BOOTSTRAP-01",
            title="Bootstrap supply chain — path traversal precondition",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            summary=(
                "Bucket allows path-traversal-shaped key writes "
                "(4/4 probes accepted). S3 does not sanitize key names "
                "by design — exploitability depends on the enclave's "
                "download routine, but this precondition is necessary "
                "for the attack."
            ),
            remediation=(
                "Layer 1 (bucket policy): add a Deny statement that "
                "rejects s3:PutObject when the key contains '..' path "
                "components. Layer 2 (enclave code): sanitize downloaded "
                "key names with os.path.normpath() and reject any resolved "
                "path that escapes the expected directory."
            ),
            evidence={
                "accepted_keys": [
                    "app_module/../canary_untrust_probe",
                    "state/../../../tmp/canary_untrust_probe",
                    "prefix/..%2F..%2Fcanary_untrust_probe",
                    "prefix/....//canary_untrust_probe",
                ],
                "blocked_keys": [],
            },
        ),
        Finding(
            check_id="BOOTSTRAP-02",
            title="S3 bucket write scope",
            status=Status.FAIL,
            severity=Severity.HIGH,
            summary=(
                "No bucket policy exists. Any IAM principal with s3:PutObject "
                "permission can upload files to the state bucket."
            ),
            remediation=(
                "Add a bucket policy that restricts s3:PutObject to only the "
                "enclave's instance role ARN."
            ),
            evidence={"bucket_policy": "none"},
        ),
        Finding(
            check_id="KMS-01",
            title="KMS key policy enforces RecipientAttestation",
            status=Status.FAIL,
            severity=Severity.HIGH,
            summary=(
                "2 of 2 Allow+Decrypt statement(s) do not enforce meaningful "
                "attestation: 1 lack any RecipientAttestation condition; "
                "1 bind only to identity PCRs (PCR3/PCR4), not to a code "
                "measurement (PCR0/1/2/8 or ImageSha384)."
            ),
            remediation=(
                "Bind every Allow+Decrypt statement to a real code "
                "measurement: StringEqualsIgnoreCase on "
                "kms:RecipientAttestation:ImageSha384 (PCR0) or PCR8 with the "
                "expected non-zero hash. Never leave all-zeros debug values in "
                "a production policy, and do not rely on PCR3/PCR4 alone."
            ),
            evidence={
                "total_decrypt_statements": 2,
                "no_condition": 1,
                "trivial_value": 0,
                "identity_only": 1,
                "protected_keys": [],
            },
        ),
        Finding(
            check_id="IMDS-01",
            title="EC2 IMDSv2 enforcement",
            status=Status.FAIL,
            severity=Severity.HIGH,
            summary="HttpTokens is 'optional' (should be 'required' for IMDSv2-only)",
            remediation=(
                "Enforce IMDSv2: aws ec2 modify-instance-metadata-options "
                "--instance-id i-0abc123def456789a "
                "--http-tokens required --http-put-response-hop-limit 1"
            ),
            evidence={
                "http_tokens": "optional",
                "http_endpoint": "enabled",
                "hop_limit": 1,
            },
        ),
        Finding(
            check_id="IAM-01",
            title="Instance role least privilege",
            status=Status.FAIL,
            severity=Severity.HIGH,
            summary=(
                "Instance role has 2 overly permissive statement(s) with "
                "wildcard Resource on S3/KMS actions."
            ),
            remediation=(
                "Scope the instance role to the specific S3 bucket and KMS key "
                "ARN used by the enclave. Replace Resource: '*' with exact ARNs."
            ),
            evidence={
                "wildcard_statements": [
                    "inline:EnclaveStateAccess: s3:GetObject, s3:PutObject, "
                    "s3:ListBucket on Resource: *",
                    "inline:EnclaveStateAccess: kms:Decrypt, "
                    "kms:GenerateDataKey, kms:DescribeKey on Resource: *",
                ]
            },
        ),
        Finding(
            check_id="SSH-01",
            title="Remote access hardening",
            status=Status.FAIL,
            severity=Severity.HIGH,
            summary="SSH daemon (sshd) is running | EC2 Instance Connect is installed",
            remediation=(
                "Disable SSH: systemctl disable --now sshd\n"
                "Remove EC2 Instance Connect: dnf remove -y ec2-instance-connect\n"
                "Use SSM Session Manager for all shell access."
            ),
            evidence={
                "ssh_status": "active",
                "ec2ic_installed": True,
                "ssh_port": "0.0.0.0:22",
            },
        ),
        Finding(
            check_id="NAT-01",
            title="IMDS blocked from enclave NAT egress",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            summary=(
                "No iptables FORWARD rule found blocking 169.254.169.254. "
                "The enclave can reach the host's IAM credentials via IMDS."
            ),
            remediation=(
                "Add: iptables -I FORWARD -d 169.254.169.254 -i tun0 -j DROP"
            ),
            evidence={"imds_filter_rules": 0},
        ),
        Finding(
            check_id="HOST-01",
            title="Sensitive file permissions on enclave host",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            summary=(
                "3 sensitive file(s) are world-readable. "
                "Unprivileged host processes can read secrets, keys, and "
                "enclave images."
            ),
            remediation=(
                "Set chmod 600 on key/secret/env files. "
                "Set chmod 600 on the EIF to prevent offline reverse engineering."
            ),
            evidence={
                "world_readable_files": [
                    "/opt/enclave/environment.conf (644)",
                    "/opt/enclave/enclave-app.eif (644)",
                    "/opt/enclave/app_module/db.key (644)",
                ]
            },
        ),
        Finding(
            check_id="HOST-02",
            title="Enclave services running as root",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            summary=(
                "3 enclave service(s) run as root: enclave-app.service, "
                "enclave-app-networking.service, enclave-app-env-export.service"
            ),
            remediation=(
                "Create a dedicated unprivileged service account and add it to "
                "the 'ne' group for enclave management."
            ),
            evidence={
                "root_services": [
                    "enclave-app.service",
                    "enclave-app-networking.service",
                    "enclave-app-env-export.service",
                ],
                "non_root_services": [],
            },
        ),
        Finding(
            check_id="ENV-01",
            title="Host-supplied configuration validation",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            summary=(
                "Dangerous env vars present: HTTPS_PROXY | "
                "Environment file is world-readable"
            ),
            remediation=(
                "Remove proxy-related and path-injection env vars from "
                "host-supplied configuration. Restrict env files to root-only "
                "(chmod 600). Hardcode BUCKET_NAME and KEY_ARN in the EIF."
            ),
            evidence={
                "dangerous_vars": ["HTTPS_PROXY"],
                "infra_warnings": [],
                "world_readable": True,
                "permissions": "644 /opt/enclave/environment.conf",
            },
        ),
        Finding(
            check_id="S3-01",
            title="S3 public access block",
            status=Status.FAIL,
            severity=Severity.HIGH,
            summary=(
                "No PublicAccessBlockConfiguration exists on the "
                "state bucket."
            ),
            remediation=(
                "Enable all four PublicAccessBlock settings."
            ),
            evidence={"public_access_block": "none"},
        ),
        Finding(
            check_id="PORT-01",
            title="Unexpected listening TCP ports",
            status=Status.FAIL,
            severity=Severity.HIGH,
            summary="2 unexpected TCP port(s) listening: 22, 8080",
            remediation=(
                "Disable sshd and any other unnecessary services."
            ),
            evidence={
                "unexpected_ports": [22, 8080],
                "all_ports": [22, 8080],
            },
        ),
        Finding(
            check_id="EXEC-01",
            title="State files lack execute permissions",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            summary=(
                "3 file(s) in the state directory have execute "
                "permissions."
            ),
            remediation=(
                "Remove execute permissions from all files "
                "downloaded from S3."
            ),
            evidence={
                "executable_files": [
                    "/opt/enclave/app_module/run.sh",
                    "/opt/enclave/app_module/migrate.py",
                    "/opt/enclave/scripts/post_boot.sh",
                ],
            },
        ),
        Finding(
            check_id="VSOCK-01",
            title="Vsock service exposure",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            summary=(
                "3 vsock listener(s) found on the host. Verify "
                "each service requires authentication."
            ),
            remediation=(
                "Ensure every vsock service validates caller "
                "identity before processing requests."
            ),
            evidence={
                "vsock_listeners": [
                    "u_str LISTEN 0 5 vm(3):9000",
                    "u_str LISTEN 0 5 vm(3):9001",
                    "u_str LISTEN 0 5 vm(3):9998",
                ],
            },
        ),
        Finding(
            check_id="DNS-01",
            title="Host DNS DNAT rules",
            status=Status.FAIL,
            severity=Severity.LOW,
            summary=(
                "Found 1 DNS DNAT rule(s). The host redirects "
                "enclave DNS queries, enabling DNS-based MITM if "
                "TLS pinning is absent."
            ),
            remediation=(
                "If the enclave performs TLS certificate pinning, "
                "this is partially mitigated."
            ),
            evidence={
                "dnat_rules": [
                    "18 1405 DNAT udp -- * * 1.1.1.1 0.0.0.0/0 "
                    "udp dpt:53 to:10.0.0.2:53"
                ]
            },
        ),
        Finding(
            check_id="VPC-01",
            title="VPC network isolation",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            summary=(
                "Enclave host has a public IP: 52.40.0.99 | "
                "1 active VPC peering connection(s) found"
            ),
            remediation=(
                "Remove public IPs and VPC peering from the "
                "enclave host's VPC."
            ),
            evidence={
                "vpc_id": "vpc-0demo1234",
                "public_ip": "52.40.0.99",
                "peering_connections": 1,
            },
        ),
        Finding(
            check_id="ENCLAVE-01",
            title="Enclave debug mode is disabled",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            summary=(
                "1 enclave(s) running in debug mode: "
                "i-0abc123-enc-0001. Attestation is disabled "
                "and the console is accessible."
            ),
            remediation=(
                "Terminate debug enclaves and re-launch without "
                "--debug-mode."
            ),
            evidence={
                "debug_enclaves": ["i-0abc123-enc-0001"],
                "total_enclaves": 1,
            },
        ),
        Finding(
            check_id="ENCLAVE-02",
            title="Enclave PCR measurements are non-zero",
            status=Status.FAIL,
            severity=Severity.HIGH,
            summary=(
                "1 enclave(s) have zeroed or missing PCR values "
                "— attestation is not active."
            ),
            remediation=(
                "Re-launch the enclave in production mode."
            ),
            evidence={
                "zeroed_enclaves": ["i-0abc123-enc-0001"],
                "pcr_values": {
                    "i-0abc123-enc-0001": {
                        "PCR0": "0000000000000000...",
                        "PCR1": "0000000000000000...",
                        "PCR2": "0000000000000000...",
                    }
                },
            },
        ),
        Finding(
            check_id="CORE-01",
            title="Core dump exposure",
            status=Status.FAIL,
            severity=Severity.HIGH,
            summary=(
                "Core dumps are enabled: "
                "kernel.core_pattern=|/usr/lib/systemd/systemd-coredump | "
                "ulimit core=unlimited. A crash could write enclave "
                "secrets to host disk in plaintext."
            ),
            remediation=(
                "Disable core dumps: set kernel.core_pattern=|/bin/false "
                "and ulimit hard core 0."
            ),
            evidence={
                "core_pattern": "|/usr/lib/systemd/systemd-coredump",
                "ulimit_core": "unlimited",
            },
        ),
        Finding(
            check_id="SWAP-01",
            title="Swap exposure",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            summary=(
                "1 swap device(s) active. Enclave process memory "
                "could be paged to unencrypted disk."
            ),
            remediation="Disable swap: swapoff -a.",
            evidence={
                "swap_devices": ["/dev/xvda2 partition 2G 0B -2"],
            },
        ),
        Finding(
            check_id="LOG-01",
            title="Enclave log exposure",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            summary=(
                "Enclave logs are accessible to non-root users: "
                "Journal directory is world-readable (755)"
            ),
            remediation=(
                "Restrict journal access: chmod 750 /var/log/journal."
            ),
            evidence={
                "journal_perms": "755",
                "journal_group": "systemd-journal",
                "journal_users": "ssm-user",
            },
        ),
        Finding(
            check_id="RESTART-01",
            title="Crash handler re-download persistence",
            status=Status.FAIL,
            severity=Severity.HIGH,
            summary=(
                "2 enclave service(s) auto-restart on failure: "
                "enclave-app.service (Restart=always), "
                "enclave-app-networking.service (Restart=on-failure). "
                "If the boot sequence re-downloads state from S3, "
                "a single poisoned object persists across every "
                "restart."
            ),
            remediation=(
                "Set Restart=no or validate integrity of downloaded "
                "state before loading."
            ),
            evidence={
                "risky_services": [
                    "enclave-app.service (Restart=always)",
                    "enclave-app-networking.service (Restart=on-failure)",
                ],
            },
        ),
        Finding(
            check_id="ENCLAVE-03",
            title="Multi-enclave co-tenancy",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            summary=(
                "2 enclaves running on the same host: "
                "i-0abc123-enc-0001, i-0abc123-enc-0002. "
                "Shared hugepage pool and CPU contention create "
                "side-channel and resource starvation risks."
            ),
            remediation=(
                "Run exactly one enclave per host."
            ),
            evidence={
                "running_enclaves": [
                    "i-0abc123-enc-0001",
                    "i-0abc123-enc-0002",
                ],
                "total_count": 2,
            },
        ),
        Finding(
            check_id="ENCLAVE-04",
            title="Enclave booted from a signed image (PCR8)",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            summary=(
                "Enclave image is unsigned (no PCR8). KMS policies cannot "
                "bind to a signing identity, and there is no cryptographic "
                "link between the running image and your build pipeline."
            ),
            remediation=(
                "Build a signed EIF (nitro-cli build-enclave --private-key "
                "--signing-certificate, signed in CI) and pin PCR8 in the "
                "KMS key policy."
            ),
            evidence={"pcr8": "absent"},
        ),
        Finding(
            check_id="ROLLBACK-01",
            title="Anti-rollback protection on bootstrap state",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            summary=(
                "No S3 Object Lock on the state bucket. An attacker with "
                "s3:PutObject can roll state back to an older version, which "
                "the enclave re-downloads and loads on its next restart."
            ),
            remediation=(
                "Enable S3 Object Lock (WORM) with a default retention rule "
                "on the state bucket, and pin the expected version/digest "
                "from an external source the enclave verifies at boot."
            ),
            evidence={"object_lock": "none"},
        ),
        Finding(
            check_id="S3-02",
            title="State bucket encryption and TLS-only access",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            summary=(
                "State bucket baseline issues: default encryption is AES256 "
                "(SSE-KMS recommended for a secrets bucket); no bucket policy "
                "denying non-TLS (aws:SecureTransport) access."
            ),
            remediation=(
                "Enable default SSE-KMS encryption and add a bucket policy "
                "Deny with Condition Bool aws:SecureTransport=false."
            ),
            evidence={"sse_algorithm": "AES256", "tls_only_deny": False},
        ),
        Finding(
            check_id="CLOUDTRAIL-01",
            title="CloudTrail records enclave KMS and S3 operations",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            summary=(
                "Management events are logged (KMS Decrypt is captured), but "
                "no trail records S3 object-level data events for the state "
                "bucket. Tampering with bootstrap state via GetObject/"
                "PutObject would leave no audit trail."
            ),
            remediation=(
                "Add an S3 data-event selector scoped to the state bucket so "
                "object reads/writes are logged."
            ),
            evidence={
                "logging_trails": ["org-trail"],
                "s3_data_event_trails": [],
            },
        ),
        Finding(
            check_id="AUDIT-01",
            title="S3 versioning and logging on state bucket",
            status=Status.FAIL,
            severity=Severity.LOW,
            summary=(
                "S3 versioning is Disabled | "
                "S3 server access logging is disabled"
            ),
            remediation=(
                "Enable S3 versioning on the state bucket. Enable "
                "server access logging or CloudTrail S3 data events."
            ),
            evidence={
                "issues": [
                    "S3 versioning is Disabled",
                    "S3 server access logging is disabled",
                ]
            },
        ),
    ]

    return target, findings
