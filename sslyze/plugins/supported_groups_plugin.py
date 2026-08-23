from dataclasses import dataclass

from nassl.base_ssl_client import ClientCertificateRequested
from nassl.ephemeral_key_info import EcDhEphemeralKeyInfo, OpenSslGroupNameEnum
from nassl.errors import OpenSSLError
from nassl.openssl_4_0_0.ssl_client import SslClient_OpenSSL_4_0_0
from nassl.tls_version_enum import TlsVersionEnum

from sslyze.connection_helpers.tls_connection import OpenSslVersionEnum
from sslyze.errors import ServerRejectedTlsHandshake, TlsHandshakeTimedOut
from sslyze.json.pydantic_utils import BaseModelWithOrmModeAndForbid
from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.plugins.plugin_base import (
    ScanCommandCliConnector,
    ScanCommandExtraArgument,
    ScanCommandImplementation,
    ScanCommandResult,
    ScanCommandWrongUsageError,
    ScanJob,
    ScanJobResult,
)
from sslyze.server_connectivity import ServerConnectivityInfo, enable_ecdh_cipher_suites


@dataclass(frozen=True)
class SupportedGroupsScanResult(ScanCommandResult):
    """The result of testing a server for Supported Groups.
    TODO
    Attributes:
        supports_ecdh_key_exchange: True if the server supports at least one cipher suite with an ECDH key exchange.
        supported_pq_groups: The list of ML-KEM hybrid groups accepted by the server, or None if the
                server does not support TLS 1.3 (PQ groups require TLS 1.3). An empty list means TLS 1.3 is supported but no PQ hybrid groups were accepted.
        rejected_pq_groups: The list of ML-KEM hybrid groups rejected by the server, or None if the
                server does not support TLS 1.3 (PQ groups require TLS 1.3).
        supports_pq_key_exchange: True if the server accepted at least one PQ/hybrid group.
    """

    # TLS 1.2 or 1.3
    supported_elliptic_curve_groups: list[str] | None
    rejected_elliptic_curve_groups: list[str] | None
    supports_ecdh_cipher_suite: bool

    supported_finite_field_dh_groups: list[str]
    rejected_finite_field_dh_groups: list[str]

    # TLS 1.3 only
    supported_tls_1_3_post_quantum_ml_kem_groups: list[str] | None
    rejected_tls_1_3_post_quantum_ml_kem_groups: list[str] | None
    supports_post_quantum_key_agreement: bool  # TODO: Confusing with supports_ecdh_cipher_suite?

    def __post_init__(self) -> None:
        # Sort lists by name so that the output is deterministic
        for attr_name in [
            "supported_elliptic_curve_groups",
            "rejected_elliptic_curve_groups",
            "supported_finite_field_dh_groups",
            "rejected_finite_field_dh_groups",
            "supported_tls_1_3_post_quantum_ml_kem_groups",
            "rejected_tls_1_3_post_quantum_ml_kem_groups",
        ]:
            attr_value = getattr(self, attr_name)
            if attr_value is not None:
                attr_value.sort()


class SupportedGroupsScanResultAsJson(BaseModelWithOrmModeAndForbid):
    supported_elliptic_curve_groups: list[str] | None
    rejected_elliptic_curve_groups: list[str] | None
    supports_ecdh_cipher_suite: bool

    supported_finite_field_dh_groups: list[str]
    rejected_finite_field_dh_groups: list[str]

    supported_tls_1_3_post_quantum_ml_kem_groups: list[str] | None
    rejected_tls_1_3_post_quantum_ml_kem_groups: list[str] | None
    supports_post_quantum_key_agreement: bool


assert SupportedGroupsScanResult.__doc__
SupportedGroupsScanResultAsJson.__doc__ = SupportedGroupsScanResult.__doc__


class SupportedGroupsScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: SupportedGroupsScanResultAsJson | None


class _SupportedGroupsCliConnector(ScanCommandCliConnector[SupportedGroupsScanResult, None]):
    _cli_option = "supported_groups"
    _cli_description = (
        "Test a server for Supported Groups, including Post-Quantum/Hybrid key exchange and Elliptic Curve groups."
    )

    @classmethod
    def result_to_console_output(cls, result: SupportedGroupsScanResult) -> list[str]:
        result_as_txt = [cls._format_title("Supported Groups")]
        """
        supported_elliptic_curve_groups: list[str] | None
        rejected_elliptic_curve_groups: list[str] | None
        supports_ecdh_cipher_suite: bool

        supported_finite_field_dh_groups: list[str]
        rejected_finite_field_dh_groups: list[str]

        # TLS 1.3 only
        supported_tls_1_3_post_quantum_ml_kem_groups: list[str] | None
        rejected_tls_1_3_post_quantum_ml_kem_groups: list[str] | None
        supports_post_quantum_key_agreement: bool
        """
        if result.supported_elliptic_curve_groups is None:
            result_as_txt.append(
                cls._format_subtitle(
                    "VULNERABLE - TLS 1.3 is not supported; PQ key exchange support is only available in TLS 1.3."
                )
            )
        else:
            if result.supported_elliptic_curve_groups:
                result_as_txt.append(
                    cls._format_field("Supported PQ groups:", ", ".join(result.supported_elliptic_curve_groups))
                )
            else:
                result_as_txt.append(
                    cls._format_subtitle(
                        "VULNERABLE - Server does not support any PQ/hybrid key exchange groups."
                        " It is not protected against 'harvest now, decrypt later' attacks."
                    )
                )

            assert result.supported_elliptic_curve_groups
            result_as_txt.append(
                cls._format_field("Rejected PQ groups:", ", ".join(result.rejected_elliptic_curve_groups))
            )

        return result_as_txt


class SupportedGroupsImplementation(ScanCommandImplementation[SupportedGroupsScanResult, None]):
    """Test a server for Supported Groups, including Post-Quantum/Hybrid key exchange and Elliptic Curve groups."""

    cli_connector_cls = _SupportedGroupsCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: ScanCommandExtraArgument | None = None
    ) -> list[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        all_scan_jobs = []
        highest_tls_version_supported = server_info.tls_probing_result.highest_tls_version_supported

        # TODO: Need an enum in nassl to classify the groups : EC, PQ, FFDH
        if not server_info.tls_probing_result.supports_ecdh_key_exchange:
            # TODO: Same as elliptic curve plugin - > don't scan for EC groups if not ECDH cipher suites are supported
            pass

        if highest_tls_version_supported.value < TlsVersionEnum.TLS_1_0.value:
            # TODO: Nothing to test
            pass

        elif highest_tls_version_supported.value < TlsVersionEnum.TLS_1_3.value:
            # The server does not support TLS 1.3
            # So some TLS 1.3-only groups (like PQ/hybrid groups) cannot be tested
            # Test all TLS 1.0-1.2 groups
            all_tls_1_2_groups = OpenSslGroupNameEnum.get_supported_by_tls_version(highest_tls_version_supported)

            if not server_info.tls_probing_result.supports_ecdh_key_exchange:
                # TODO: Same as elliptic curve plugin
                pass

            all_scan_jobs.extend(
                [
                    ScanJob(
                        function_to_call=_test_group,
                        function_arguments=[server_info, highest_tls_version_supported, group],
                    )
                    for group in all_tls_1_2_groups
                ]
            )

        else:
            # The server does support TLS 1.3 : we test as many groups as possible on TLS 1.3, and the rest on TLS 1.2
            #  (so we assume the server supports TLS 1.2 as well)
            all_tls_1_3_groups = OpenSslGroupNameEnum.get_supported_by_tls_version(TlsVersionEnum.TLS_1_3)
            all_tls_1_2_groups = OpenSslGroupNameEnum.get_supported_by_tls_version(TlsVersionEnum.TLS_1_2)
            all_tls_1_2_groups_to_test = all_tls_1_2_groups - all_tls_1_3_groups
            all_scan_jobs.extend(
                [
                    ScanJob(
                        function_to_call=_test_pq_or_ffdh_group,
                        function_arguments=[server_info, TlsVersionEnum.TLS_1_3, group],
                    )
                    for group in all_tls_1_3_groups
                ]
            )
            all_scan_jobs.extend(
                [
                    ScanJob(
                        function_to_call=_test_pq_or_ffdh_group,
                        function_arguments=[server_info, TlsVersionEnum.TLS_1_2, group],
                    )
                    for group in all_tls_1_2_groups_to_test
                ]
            )

        return all_scan_jobs

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: list[ScanJobResult]
    ) -> SupportedGroupsScanResult:
        if len(scan_job_results) < 1:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        if not server_info.tls_probing_result.supports_ecdh_key_exchange:
            supports_ecdh_cipher_suite = None  # TODO

        all_results = [job.get_result() for job in scan_job_results]
        supported_groups = [r.group.value for r in all_results if r.was_accepted_by_server]
        rejected_groups = [r.group.value for r in all_results if not r.was_accepted_by_server]
        return SupportedGroupsScanResult(
            supported_elliptic_curve_groups=supported_groups,
            rejected_elliptic_curve_groups=rejected_groups,
            supports_elliptic_curve_agreement=bool([]),
            supported_finite_field_dh_groups=[],
            rejected_finite_field_dh_groups=[],
            supported_tls_1_3_post_quantum_ml_kem_groups=[],
            rejected_tls_1_3_post_quantum_ml_kem_groups=[],
            supports_post_quantum_key_agreement=bool([]),
        )


@dataclass(frozen=True)
class _SupportedGroupResult:
    tls_version: TlsVersionEnum
    group: OpenSslGroupNameEnum
    was_accepted_by_server: bool


def _test_group(
    server_info: ServerConnectivityInfo, tls_version: TlsVersionEnum, group: OpenSslGroupNameEnum
) -> _SupportedGroupResult:
    if OpenSslGroupNameEnum.is_elliptic_curve(group):
        # The logic for EC groups is slightly different as an ECDH cipher suite has to be enabled
        return _test_ec_group(server_info, tls_version, group)
    else:
        return _test_pq_or_ffdh_group(server_info, tls_version, group)


def _test_pq_or_ffdh_group(
    server_info: ServerConnectivityInfo, tls_version: TlsVersionEnum, group: OpenSslGroupNameEnum
) -> _SupportedGroupResult:
    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version,
        # Only the 4.0.0 client has support for the PQ groups
        openssl_version=OpenSslVersionEnum.OPENSSL_4_0_0,
    )
    assert isinstance(ssl_connection.ssl_client, SslClient_OpenSSL_4_0_0), "Should never happen"

    ssl_connection.ssl_client.set_groups_list([group])

    negotiated_group: str | None = None
    try:
        ssl_connection.connect()
        negotiated_group = ssl_connection.ssl_client.get_group_name()

    except ClientCertificateRequested:
        negotiated_group = ssl_connection.ssl_client.get_group_name()

    except (ServerRejectedTlsHandshake, TlsHandshakeTimedOut):
        negotiated_group = None

    finally:
        ssl_connection.close()

    if negotiated_group:
        assert negotiated_group == group, f"Should never happen: group should be {group} but got {negotiated_group}"

    return _SupportedGroupResult(
        tls_version=tls_version, group=group, was_accepted_by_server=negotiated_group is not None
    )


def _test_ec_group(
    server_info: ServerConnectivityInfo, tls_version: TlsVersionEnum, curve_group: OpenSslGroupNameEnum
) -> _SupportedGroupResult:
    assert server_info.tls_probing_result.supports_ecdh_key_exchange, "Should never happen"

    tls_version = server_info.tls_probing_result.highest_tls_version_supported
    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version, openssl_version=OpenSslVersionEnum.OPENSSL_4_0_0
    )
    assert isinstance(ssl_connection.ssl_client, SslClient_OpenSSL_4_0_0), "Should never happen"

    # Set curve to test whether it is supported by the server
    enable_ecdh_cipher_suites(tls_version, ssl_connection.ssl_client)
    ssl_connection.ssl_client.set_groups_list([curve_group])

    try:
        ssl_connection.connect()
        negotiated_ephemeral_key = ssl_connection.ssl_client.get_ephemeral_key()

    # Error handling here is similar to test_cipher_suite.py
    except ClientCertificateRequested:
        negotiated_ephemeral_key = ssl_connection.ssl_client.get_ephemeral_key()

    except (TlsHandshakeTimedOut, ServerRejectedTlsHandshake):
        negotiated_ephemeral_key = None

    except OpenSSLError as e:
        # The following errors can be triggered by some servers when they don't support the specific curve enabled
        # in the client
        if "ossl_statem_client_read_transition:unexpected message" in e.args[0]:
            # Related to https://github.com/nabla-c0d3/sslyze/issues/466
            negotiated_ephemeral_key = None
        elif "tls_process_ske_ecdhe:wrong curve" in e.args[0] or "sslv3 alert unexpected message" in e.args[0]:
            # https://github.com/nabla-c0d3/sslyze/issues/490
            negotiated_ephemeral_key = None
        elif "wrong curve" in e.args[0]:
            # https://github.com/nabla-c0d3/sslyze/issues/579
            negotiated_ephemeral_key = None
        else:
            raise

    finally:
        ssl_connection.close()

    if negotiated_ephemeral_key and isinstance(negotiated_ephemeral_key, EcDhEphemeralKeyInfo):
        # Ensure the negotiated curve is the one we requested
        negotiated_group = ssl_connection.ssl_client.get_group_name()
        assert negotiated_group == curve_group, (
            f"Should never happen: group should be {curve_group} but got {negotiated_group}"
        )
        assert negotiated_ephemeral_key.curve_name == curve_group, "Should never happen"
        was_accepted_by_server = True
    else:
        was_accepted_by_server = False

    return _SupportedGroupResult(
        tls_version=tls_version,
        group=curve_group,
        was_accepted_by_server=was_accepted_by_server,
    )
