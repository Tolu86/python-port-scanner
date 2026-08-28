import socket
import time
import argparse
import json
import csv
import sys

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from service_detector import detect_service
from udp_scanner import udp_scan
from os_fingerprint import fingerprint_target
from security_checks import run_security_analysis
from vulnerability_scanner import run_vulnerability_scan
from report_generator import generate_html_report


# ============================================================
# TCP PORT PROFILES
# ============================================================

QUICK_PORTS = [
    21, 22, 23, 25, 53,
    80, 110, 143, 443,
    445, 3306, 5432,
    6379, 8080, 8443
]


COMMON_PORTS = [
    20, 21, 22, 23, 25,
    53, 67, 68, 69, 80,
    81, 88, 110, 111,
    119, 123, 135, 137,
    138, 139, 143, 161,
    162, 389, 443, 445,
    465, 514, 587, 631,
    636, 993, 995, 1433,
    1521, 2049, 2375, 3000,
    3306, 3389, 5000, 5432,
    5900, 5985, 6379, 6443,
    8000, 8080, 8443, 8888,
    9200, 27017
]


# ============================================================
# TCP PORT SCANNER
# ============================================================

def scan_port(target, port, timeout):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(timeout)

    try:
        result = sock.connect_ex(
            (target, port)
        )

    except socket.error:
        result = 1

    finally:
        sock.close()

    if result == 0:
        return port

    return None


# ============================================================
# TARGET VALIDATION
# ============================================================

def validate_target(target):

    try:
        socket.gethostbyname(target)
        return True

    except socket.gaierror:
        return False


# ============================================================
# PORT VALIDATION
# ============================================================

def validate_port(port):

    if port < 1 or port > 65535:

        raise ValueError(
            f"Invalid port: {port}"
        )


# ============================================================
# CUSTOM PORT PARSER
# ============================================================

def parse_ports(port_input):

    ports = set()

    for section in port_input.split(","):

        section = section.strip()

        if "-" in section:

            start, end = map(
                int,
                section.split("-")
            )

            validate_port(start)
            validate_port(end)

            if start > end:

                raise ValueError(
                    f"Invalid range: {section}"
                )

            ports.update(
                range(
                    start,
                    end + 1
                )
            )

        else:

            port = int(section)

            validate_port(port)

            ports.add(port)

    return sorted(ports)


# ============================================================
# PROFILE PORTS
# ============================================================

def get_profile_ports(profile):

    if profile == "quick":

        return sorted(
            set(QUICK_PORTS)
        )

    if profile == "common":

        return sorted(
            set(COMMON_PORTS)
        )

    if profile == "full":

        return list(
            range(1, 65536)
        )

    return None


# ============================================================
# PROGRESS BAR
# ============================================================

def show_progress(
    completed,
    total
):

    if total == 0:
        return

    percentage = (
        completed / total
    ) * 100

    bar_length = 30

    filled = int(
        bar_length *
        completed /
        total
    )

    bar = (
        "#" * filled +
        "-" * (
            bar_length - filled
        )
    )

    sys.stdout.write(
        f"\rProgress: "
        f"[{bar}] "
        f"{percentage:6.2f}% "
        f"({completed}/{total})"
    )

    sys.stdout.flush()


# ============================================================
# SAVE JSON
# ============================================================

def save_json(
    filename,
    results
):

    try:

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                results,
                file,
                indent=4,
                default=str
            )

        print(
            f"\nJSON report saved to: "
            f"{filename}"
        )

    except OSError as error:

        print(
            f"\nCould not save JSON: "
            f"{error}"
        )


# ============================================================
# SAVE CSV
# ============================================================

def save_csv(
    filename,
    results
):

    try:

        with open(
            filename,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Target",
                "Protocol",
                "Port",
                "State",
                "Service",
                "Version",
                "Confidence",
                "Detection Method",
                "TLS Version",
                "Cipher",
                "Cipher Bits",
                "Certificate Subject",
                "Certificate Issuer",
                "Certificate Valid From",
                "Certificate Valid Until",
                "Certificate Currently Valid",
                "Banner",
                "Information"
            ])

            # ------------------------------------------------
            # TCP
            # ------------------------------------------------

            for port_data in results.get(
                "open_ports",
                []
            ):

                tls = port_data.get(
                    "tls",
                    {}
                )

                writer.writerow([

                    results.get(
                        "target",
                        ""
                    ),

                    "TCP",

                    port_data.get(
                        "port",
                        ""
                    ),

                    "OPEN",

                    port_data.get(
                        "service",
                        "Unknown"
                    ),

                    port_data.get(
                        "version",
                        ""
                    ),

                    port_data.get(
                        "confidence",
                        ""
                    ),

                    port_data.get(
                        "detection_method",
                        ""
                    ),

                    tls.get(
                        "tls_version",
                        ""
                    ),

                    tls.get(
                        "cipher",
                        ""
                    ),

                    tls.get(
                        "cipher_bits",
                        ""
                    ),

                    tls.get(
                        "certificate_subject",
                        ""
                    ),

                    tls.get(
                        "certificate_issuer",
                        ""
                    ),

                    tls.get(
                        "certificate_valid_from",
                        ""
                    ),

                    tls.get(
                        "certificate_valid_until",
                        ""
                    ),

                    tls.get(
                        "certificate_currently_valid",
                        ""
                    ),

                    port_data.get(
                        "banner",
                        ""
                    ),

                    port_data.get(
                        "information",
                        ""
                    )
                ])

            # ------------------------------------------------
            # UDP
            # ------------------------------------------------

            for udp_data in results.get(
                "udp_results",
                []
            ):

                writer.writerow([

                    results.get(
                        "target",
                        ""
                    ),

                    "UDP",

                    udp_data.get(
                        "port",
                        ""
                    ),

                    udp_data.get(
                        "state",
                        ""
                    ),

                    udp_data.get(
                        "service",
                        "Unknown"
                    ),

                    "",

                    "",

                    "UDP probe",

                    "",

                    "",

                    "",

                    "",

                    "",

                    "",

                    "",

                    "",

                    udp_data.get(
                        "response_text",
                        ""
                    ),

                    udp_data.get(
                        "message",
                        ""
                    )
                ])

        print(
            f"\nCSV report saved to: "
            f"{filename}"
        )

    except OSError as error:

        print(
            f"\nCould not save CSV: "
            f"{error}"
        )


# ============================================================
# TCP SERVICE DETECTION
# ============================================================

def detect_tcp_services(
    target,
    open_ports
):

    detected_services = []

    if not open_ports:

        print(
            "\nNo open TCP ports found."
        )

        return detected_services

    print()

    print(
        "OPEN TCP PORTS"
    )

    print(
        "-" * 110
    )

    print(
        f"{'PORT':<9}"
        f"{'STATE':<9}"
        f"{'SERVICE':<20}"
        f"{'VERSION':<25}"
        f"{'CONFIDENCE':<13}"
        f"METHOD"
    )

    print(
        "-" * 110
    )

    for port in sorted(
        open_ports
    ):

        try:

            result = detect_service(
                target,
                port,
                timeout=4
            )

        except Exception as error:

            print(
                f"\nService detection error "
                f"on port {port}: {error}"
            )

            result = {}

        port_result = {

            "port":
                port,

            "service":
                result.get(
                    "service",
                    "Unknown"
                ),

            "version":
                result.get(
                    "version"
                ),

            "banner":
                result.get(
                    "banner"
                ),

            "information":
                result.get(
                    "information"
                ),

            "confidence":
                result.get(
                    "confidence",
                    "LOW"
                ),

            "detection_method":
                result.get(
                    "detection_method",
                    "Unknown"
                ),

            "tls":
                result.get(
                    "tls",
                    {}
                )
        }

        detected_services.append(
            port_result
        )

        version = (
            port_result["version"]
            or "Unknown"
        )

        print(
            f"{port:<9}"
            f"{'OPEN':<9}"
            f"{port_result['service']:<20}"
            f"{version:<25}"
            f"{port_result['confidence']:<13}"
            f"{port_result['detection_method']}"
        )

        # ----------------------------------------------------
        # TLS
        # ----------------------------------------------------

        tls = port_result.get(
            "tls",
            {}
        )

        if tls:

            print()

            print(
                "          TLS INFORMATION"
            )

            print(
                f"          TLS Version: "
                f"{tls.get('tls_version') or 'Unknown'}"
            )

            print(
                f"          Cipher: "
                f"{tls.get('cipher') or 'Unknown'}"
            )

            print(
                f"          Cipher Bits: "
                f"{tls.get('cipher_bits') or 'Unknown'}"
            )

            print(
                f"          Certificate Subject: "
                f"{tls.get('certificate_subject') or 'Unknown'}"
            )

            print(
                f"          Certificate Issuer: "
                f"{tls.get('certificate_issuer') or 'Unknown'}"
            )

            print(
                f"          Valid From: "
                f"{tls.get('certificate_valid_from') or 'Unknown'}"
            )

            print(
                f"          Valid Until: "
                f"{tls.get('certificate_valid_until') or 'Unknown'}"
            )

            print(
                f"          Currently Valid: "
                f"{tls.get('certificate_currently_valid')}"
            )

        # ----------------------------------------------------
        # BANNER
        # ----------------------------------------------------

        if port_result.get(
            "banner"
        ):

            print(
                f"          Banner: "
                f"{port_result['banner']}"
            )

        # ----------------------------------------------------
        # INFORMATION
        # ----------------------------------------------------

        if port_result.get(
            "information"
        ):

            print(
                f"          Info: "
                f"{port_result['information']}"
            )

    return detected_services


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Python Port Scanner with "
            "TCP, UDP, Service, Version, "
            "TLS, OS, Security and "
            "Vulnerability Detection"
        )
    )

    # ========================================================
    # TARGET
    # ========================================================

    parser.add_argument(
        "target",
        help=(
            "Target IP address "
            "or hostname"
        )
    )

    # ========================================================
    # CUSTOM PORTS
    # ========================================================

    parser.add_argument(
        "-p",
        "--ports",
        help=(
            "Custom ports, "
            "e.g. 22,80,443 "
            "or 1-1000"
        )
    )

    # ========================================================
    # TCP PROFILES
    # ========================================================

    parser.add_argument(
        "--quick",
        action="store_true",
        help="Scan common quick ports"
    )

    parser.add_argument(
        "--common",
        action="store_true",
        help=(
            "Scan a larger set "
            "of common ports"
        )
    )

    parser.add_argument(
        "--full",
        action="store_true",
        help="Scan all TCP ports"
    )

    # ========================================================
    # UDP
    # ========================================================

    parser.add_argument(
        "--udp",
        action="store_true",
        help="Perform UDP scan"
    )

    # ========================================================
    # SETTINGS
    # ========================================================

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help=(
            "TCP connection timeout"
        )
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=50,
        help=(
            "Number of concurrent "
            "TCP workers"
        )
    )

    # ========================================================
    # OUTPUT
    # ========================================================

    parser.add_argument(
        "--output",
        help="Save results as JSON"
    )

    parser.add_argument(
        "--csv",
        help="Save results as CSV"
    )

    parser.add_argument(
        "--html",
        help=(
            "Save results as "
            "HTML security report"
        )
    )

    args = parser.parse_args()

    # ========================================================
    # PROFILE CHECK
    # ========================================================

    profiles = sum([
        args.quick,
        args.common,
        args.full
    ])

    if profiles > 1:

        print(
            "Choose only one TCP profile:"
        )

        print(
            "--quick OR --common OR --full"
        )

        return

    # ========================================================
    # TARGET VALIDATION
    # ========================================================

    if not validate_target(
        args.target
    ):

        print(
            f"Could not resolve target: "
            f"{args.target}"
        )

        return

    # ========================================================
    # PORT SELECTION
    # ========================================================

    if args.quick:

        ports = get_profile_ports(
            "quick"
        )

        profile = "quick"

    elif args.common:

        ports = get_profile_ports(
            "common"
        )

        profile = "common"

    elif args.full:

        ports = get_profile_ports(
            "full"
        )

        profile = "full"

    elif args.ports:

        try:

            ports = parse_ports(
                args.ports
            )

        except (
            ValueError,
            TypeError
        ) as error:

            print(
                f"Port error: {error}"
            )

            return

        profile = "custom"

    else:

        ports = get_profile_ports(
            "quick"
        )

        profile = "quick"

    # ========================================================
    # VALIDATE SETTINGS
    # ========================================================

    if args.timeout <= 0:

        print(
            "Timeout must be greater than 0."
        )

        return

    if args.workers < 1:

        print(
            "Workers must be at least 1."
        )

        return

    # ========================================================
    # HEADER
    # ========================================================

    print()

    print(
        "=" * 110
    )

    print(
        "                         PORT SCANNER"
    )

    print(
        "=" * 110
    )

    print(
        f"Target       : "
        f"{args.target}"
    )

    print(
        f"TCP Profile  : "
        f"{profile}"
    )

    print(
        f"TCP Ports    : "
        f"{len(ports)}"
    )

    print(
        f"UDP Scan     : "
        f"{'YES' if args.udp else 'NO'}"
    )

    print(
        f"TCP Timeout  : "
        f"{args.timeout}s"
    )

    print(
        f"Workers      : "
        f"{args.workers}"
    )

    print(
        "=" * 110
    )

    print()

    # ========================================================
    # START TIME
    # ========================================================

    start_time = time.time()

    start_datetime = (
        datetime.now().isoformat()
    )

    # ========================================================
    # TCP SCAN
    # ========================================================

    open_ports = []

    completed = 0

    total = len(ports)

    print(
        "Scanning TCP ports..."
    )

    print()

    with ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:

        futures = [

            executor.submit(
                scan_port,
                args.target,
                port,
                args.timeout
            )

            for port in ports
        ]

        for future in futures:

            try:

                result = future.result()

                if result is not None:

                    open_ports.append(
                        result
                    )

            except Exception as error:

                print(
                    f"\nTCP scan error: "
                    f"{error}"
                )

            completed += 1

            show_progress(
                completed,
                total
            )

    print("\n")

    # ========================================================
    # TCP SERVICE DETECTION
    # ========================================================

    detected_services = (
        detect_tcp_services(
            args.target,
            open_ports
        )
    )

    # ========================================================
    # UDP SCAN
    # ========================================================

    udp_results = []

    if args.udp:

        print()

        print(
            "Starting UDP scan..."
        )

        try:

            udp_results = udp_scan(
                args.target,
                timeout=2
            )

        except Exception as error:

            print(
                f"\nUDP scan error: "
                f"{error}"
            )

    # ========================================================
    # OS FINGERPRINT
    # ========================================================

    print()

    print(
        "Starting OS fingerprinting..."
    )

    try:

        os_fingerprint = (
            fingerprint_target(
                args.target,
                open_ports
            )
        )

    except Exception as error:

        print(
            f"\nOS fingerprinting error: "
            f"{error}"
        )

        os_fingerprint = {

            "target":
                args.target,

            "observed_ttl":
                None,

            "estimated_os":
                "Unknown",

            "confidence":
                "LOW",

            "reason":
                str(error),

            "service_clues":
                []
        }

    # ========================================================
    # SECURITY ANALYSIS
    # ========================================================

    print()

    print(
        "Starting security analysis..."
    )

    try:

        security_analysis = (
            run_security_analysis(
                detected_services
            )
        )

    except Exception as error:

        print(
            f"\nSecurity analysis error: "
            f"{error}"
        )

        security_analysis = {

            "overall_risk":
                "UNKNOWN",

            "summary":
                {},

            "findings":
                []
        }

    # ========================================================
    # VULNERABILITY INTELLIGENCE
    # ========================================================

    print()

    print(
        "Starting vulnerability analysis..."
    )

    try:

        vulnerability_results = (
            run_vulnerability_scan(
                detected_services
            )
        )

    except Exception as error:

        print(
            f"\nVulnerability analysis error: "
            f"{error}"
        )

        vulnerability_results = []

    # ========================================================
    # FINISH TIMING
    # ========================================================

    end_time = time.time()

    end_datetime = (
        datetime.now().isoformat()
    )

    scan_time = (
        end_time -
        start_time
    )

    total_ports = len(
        ports
    )

    open_count = len(
        open_ports
    )

    closed_count = (
        total_ports -
        open_count
    )

    # ========================================================
    # COMPLETE SCAN RESULTS
    # ========================================================

    scan_results = {

        "scanner":
            "Python Port Scanner",

        "version":
            "2.0",

        "target":
            args.target,

        "profile":
            profile,

        "scan_started":
            start_datetime,

        "scan_finished":
            end_datetime,

        "scan_duration_seconds":
            round(
                scan_time,
                2
            ),

        "ports_scanned":
            total_ports,

        "open_ports_count":
            open_count,

        "closed_ports_count":
            closed_count,

        "open_ports":
            detected_services,

        "udp_results":
            udp_results,

        "os_fingerprint":
            os_fingerprint,

        "security_analysis":
            security_analysis,

        "vulnerabilities":
            vulnerability_results
    }

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print()

    print(
        "=" * 110
    )

    print(
        "                         SCAN COMPLETE"
    )

    print(
        "=" * 110
    )

    print(
        f"TCP ports scanned : "
        f"{total_ports}"
    )

    print(
        f"TCP open ports    : "
        f"{open_count}"
    )

    print(
        f"TCP closed ports  : "
        f"{closed_count}"
    )

    if args.udp:

        print(
            f"UDP results       : "
            f"{len(udp_results)}"
        )

    print(
        f"OS estimate       : "
        f"{os_fingerprint.get(
            'estimated_os',
            'Unknown'
        )}"
    )

    print(
        f"OS confidence     : "
        f"{os_fingerprint.get(
            'confidence',
            'LOW'
        )}"
    )

    print(
        f"Overall risk      : "
        f"{security_analysis.get(
            'overall_risk',
            'UNKNOWN'
        )}"
    )

    print(
        f"Vulnerabilities   : "
        f"{len(vulnerability_results)}"
    )

    print(
        f"Scan time         : "
        f"{scan_time:.2f} seconds"
    )

    print(
        "=" * 110
    )

    # ========================================================
    # SAVE JSON
    # ========================================================

    if args.output:

        save_json(
            args.output,
            scan_results
        )

    # ========================================================
    # SAVE CSV
    # ========================================================

    if args.csv:

        save_csv(
            args.csv,
            scan_results
        )

    # ========================================================
    # SAVE HTML
    # ========================================================

    if args.html:

        generate_html_report(
            scan_results,
            args.html
        )


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    main()