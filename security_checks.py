# ============================================================
# SECURITY CHECKS
# Defensive security analysis for the port scanner
# ============================================================


# ============================================================
# RISK SCORES
# ============================================================

RISK_SCORES = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


# ============================================================
# RISK ORDER
# ============================================================

RISK_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


# ============================================================
# CREATE FINDING
# ============================================================

def create_finding(
    port,
    severity,
    title,
    description,
    recommendation
):

    return {

        "port": port,

        "severity": severity,

        "title": title,

        "description": description,

        "recommendation": recommendation
    }


# ============================================================
# PORT-BASED SECURITY CHECKS
# ============================================================

def check_port_security(
    port,
    service=None
):

    findings = []


    service_name = (
        str(service or "")
        .lower()
    )


    # ========================================================
    # FTP
    # ========================================================

    if port == 21:

        findings.append(
            create_finding(

                port,

                "MEDIUM",

                "FTP service exposed",

                (
                    "FTP is an older file-transfer "
                    "protocol and may transmit "
                    "credentials without encryption."
                ),

                (
                    "Prefer SFTP or another "
                    "encrypted file-transfer method "
                    "where possible."
                )
            )
        )


    # ========================================================
    # TELNET
    # ========================================================

    if port == 23:

        findings.append(
            create_finding(

                port,

                "HIGH",

                "Telnet service exposed",

                (
                    "Telnet is an insecure remote "
                    "administration protocol because "
                    "traffic may be transmitted "
                    "without encryption."
                ),

                (
                    "Disable Telnet and use SSH "
                    "for secure remote administration."
                )
            )
        )


    # ========================================================
    # SMTP
    # ========================================================

    if port == 25:

        findings.append(
            create_finding(

                port,

                "LOW",

                "SMTP service exposed",

                (
                    "An SMTP service is reachable. "
                    "Mail services should be reviewed "
                    "for secure configuration and "
                    "unauthorized relay."
                ),

                (
                    "Ensure authentication, encryption "
                    "and relay restrictions are properly "
                    "configured."
                )
            )
        )


    # ========================================================
    # SMB
    # ========================================================

    if port == 445:

        findings.append(
            create_finding(

                port,

                "HIGH",

                "SMB service exposed",

                (
                    "SMB is reachable over the network. "
                    "Exposed SMB services can increase "
                    "the attack surface of Windows systems."
                ),

                (
                    "Restrict SMB access to trusted "
                    "networks and hosts. Keep the "
                    "operating system and SMB software "
                    "patched."
                )
            )
        )


    # ========================================================
    # NETBIOS
    # ========================================================

    if port in [137, 138, 139]:

        findings.append(
            create_finding(

                port,

                "MEDIUM",

                "NetBIOS service exposed",

                (
                    "NetBIOS services are reachable. "
                    "These services can expose "
                    "information about Windows systems "
                    "on a network."
                ),

                (
                    "Disable NetBIOS where it is not "
                    "required and restrict access "
                    "with network controls."
                )
            )
        )


    # ========================================================
    # RDP
    # ========================================================

    if port == 3389:

        findings.append(
            create_finding(

                port,

                "HIGH",

                "Remote Desktop exposed",

                (
                    "RDP is reachable over the network. "
                    "Remote administration services "
                    "increase the attack surface."
                ),

                (
                    "Restrict RDP to trusted networks "
                    "or VPN access and enforce strong "
                    "authentication."
                )
            )
        )


    # ========================================================
    # MYSQL
    # ========================================================

    if port == 3306:

        findings.append(
            create_finding(

                port,

                "HIGH",

                "MySQL database exposed",

                (
                    "A MySQL database service is "
                    "reachable from the scanned host."
                ),

                (
                    "Restrict database access to "
                    "authorized hosts and avoid exposing "
                    "database ports directly to untrusted "
                    "networks."
                )
            )
        )


    # ========================================================
    # POSTGRESQL
    # ========================================================

    if port == 5432:

        findings.append(
            create_finding(

                port,

                "HIGH",

                "PostgreSQL database exposed",

                (
                    "A PostgreSQL database service "
                    "is reachable."
                ),

                (
                    "Restrict database access to "
                    "authorized systems and networks."
                )
            )
        )


    # ========================================================
    # REDIS
    # ========================================================

    if port == 6379:

        findings.append(
            create_finding(

                port,

                "HIGH",

                "Redis service exposed",

                (
                    "Redis is reachable over the "
                    "network. Improperly secured Redis "
                    "instances can expose sensitive "
                    "data."
                ),

                (
                    "Require authentication where "
                    "appropriate and restrict Redis "
                    "access to trusted systems."
                )
            )
        )


    # ========================================================
    # ELASTICSEARCH
    # ========================================================

    if port == 9200:

        findings.append(
            create_finding(

                port,

                "HIGH",

                "Elasticsearch service exposed",

                (
                    "Elasticsearch is reachable. "
                    "Exposed search databases may "
                    "contain sensitive information."
                ),

                (
                    "Require authentication and restrict "
                    "network access to trusted systems."
                )
            )
        )


    # ========================================================
    # HTTP
    # ========================================================

    if port == 80:

        findings.append(
            create_finding(

                port,

                "LOW",

                "HTTP service exposed",

                (
                    "An unencrypted HTTP service "
                    "is reachable."
                ),

                (
                    "Use HTTPS for sensitive traffic "
                    "and redirect HTTP requests where "
                    "appropriate."
                )
            )
        )


    # ========================================================
    # HTTPS
    # ========================================================

    if port == 443:

        findings.append(
            create_finding(

                port,

                "INFO",

                "HTTPS service detected",

                (
                    "An HTTPS service is reachable."
                ),

                (
                    "Continue monitoring TLS "
                    "configuration and certificate "
                    "validity."
                )
            )
        )


    # ========================================================
    # SSH
    # ========================================================

    if port == 22:

        findings.append(
            create_finding(

                port,

                "INFO",

                "SSH service detected",

                (
                    "SSH is reachable and provides "
                    "remote administration capability."
                ),

                (
                    "Use key-based authentication where "
                    "appropriate and restrict SSH access "
                    "to trusted networks."
                )
            )
        )


    # ========================================================
    # VNC
    # ========================================================

    if port == 5900:

        findings.append(
            create_finding(

                port,

                "HIGH",

                "VNC service exposed",

                (
                    "A remote desktop service is "
                    "reachable."
                ),

                (
                    "Restrict remote desktop access "
                    "to trusted networks or VPN."
                )
            )
        )


    # ========================================================
    # DOCKER API
    # ========================================================

    if port == 2375:

        findings.append(
            create_finding(

                port,

                "CRITICAL",

                "Docker API may be exposed",

                (
                    "TCP/2375 is commonly associated "
                    "with an unencrypted Docker API. "
                    "Exposing container management "
                    "interfaces can create significant "
                    "security risk."
                ),

                (
                    "Do not expose the Docker API to "
                    "untrusted networks. Use secure "
                    "authentication and encrypted "
                    "connections."
                )
            )
        )


    return findings


# ============================================================
# TLS SECURITY CHECKS
# ============================================================

def check_tls_security(
    port,
    tls_data
):

    findings = []


    if not tls_data:

        return findings


    tls_version = str(
        tls_data.get(
            "tls_version",
            ""
        )
    ).upper()


    # ========================================================
    # OLD TLS
    # ========================================================

    if (
        "TLSV1.0" in tls_version or
        "TLSV1.1" in tls_version
    ):

        findings.append(
            create_finding(

                port,

                "HIGH",

                "Outdated TLS version",

                (
                    f"The service appears to use "
                    f"{tls_version}, which is outdated."
                ),

                (
                    "Upgrade the service to a modern "
                    "TLS configuration."
                )
            )
        )


    # ========================================================
    # CERTIFICATE EXPIRATION
    # ========================================================

    currently_valid = tls_data.get(
        "certificate_currently_valid"
    )


    if currently_valid is False:

        findings.append(
            create_finding(

                port,

                "HIGH",

                "TLS certificate is not currently valid",

                (
                    "The certificate presented by "
                    "the service does not appear "
                    "to be currently valid."
                ),

                (
                    "Install a valid certificate and "
                    "verify the system clock."
                )
            )
        )


    return findings


# ============================================================
# GENERAL SECURITY ANALYSIS
# ============================================================

def analyze_security(
    open_ports
):

    findings = []


    for port_data in open_ports:

        port = port_data.get(
            "port"
        )

        service = port_data.get(
            "service",
            "Unknown"
        )


        # ----------------------------------------------------
        # PORT CHECKS
        # ----------------------------------------------------

        port_findings = (
            check_port_security(
                port,
                service
            )
        )


        findings.extend(
            port_findings
        )


        # ----------------------------------------------------
        # TLS CHECKS
        # ----------------------------------------------------

        tls_data = port_data.get(
            "tls",
            {}
        )


        tls_findings = (
            check_tls_security(
                port,
                tls_data
            )
        )


        findings.extend(
            tls_findings
        )


    return findings


# ============================================================
# OVERALL RISK
# ============================================================

def calculate_overall_risk(
    findings
):

    if not findings:

        return "INFO"


    highest = "INFO"


    for finding in findings:

        severity = finding.get(
            "severity",
            "INFO"
        )


        if (
            RISK_ORDER.get(
                severity,
                0
            )
            >
            RISK_ORDER.get(
                highest,
                0
            )
        ):

            highest = severity


    return highest


# ============================================================
# RISK SUMMARY
# ============================================================

def generate_risk_summary(
    findings
):

    summary = {

        "INFO": 0,

        "LOW": 0,

        "MEDIUM": 0,

        "HIGH": 0,

        "CRITICAL": 0
    }


    for finding in findings:

        severity = finding.get(
            "severity",
            "INFO"
        )


        if severity in summary:

            summary[
                severity
            ] += 1


    return summary


# ============================================================
# PRINT SECURITY REPORT
# ============================================================

def print_security_report(
    findings
):

    print()

    print(
        "=" * 100
    )

    print(
        "                       SECURITY ASSESSMENT"
    )

    print(
        "=" * 100
    )


    if not findings:

        print()

        print(
            "No security findings were generated."
        )

        print(
            "=" * 100
        )

        return


    # ========================================================
    # SUMMARY
    # ========================================================

    summary = generate_risk_summary(
        findings
    )


    overall = calculate_overall_risk(
        findings
    )


    print()

    print(
        f"Overall Risk: {overall}"
    )

    print()

    print(
        "Finding Summary:"
    )

    print(
        f"  CRITICAL : {summary['CRITICAL']}"
    )

    print(
        f"  HIGH     : {summary['HIGH']}"
    )

    print(
        f"  MEDIUM   : {summary['MEDIUM']}"
    )

    print(
        f"  LOW      : {summary['LOW']}"
    )

    print(
        f"  INFO     : {summary['INFO']}"
    )


    # ========================================================
    # FINDINGS
    # ========================================================

    print()

    print(
        "-" * 100
    )


    # Highest risk first

    sorted_findings = sorted(

        findings,

        key=lambda finding:
            RISK_ORDER.get(
                finding.get(
                    "severity",
                    "INFO"
                ),
                0
            ),

        reverse=True
    )


    for finding in sorted_findings:

        print()

        print(
            f"[{finding['severity']}] "
            f"Port {finding['port']} - "
            f"{finding['title']}"
        )

        print()

        print(
            f"Description:"
        )

        print(
            f"  {finding['description']}"
        )

        print()

        print(
            f"Recommendation:"
        )

        print(
            f"  {finding['recommendation']}"
        )

        print(
            "-" * 100
        )


    print()

    print(
        "=" * 100
    )


# ============================================================
# MAIN SECURITY FUNCTION
# ============================================================

def run_security_analysis(
    open_ports
):

    findings = analyze_security(
        open_ports
    )


    print_security_report(
        findings
    )


    return {

        "overall_risk":
            calculate_overall_risk(
                findings
            ),

        "summary":
            generate_risk_summary(
                findings
            ),

        "findings":
            findings
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_ports = [

        {
            "port": 22,
            "service": "SSH",
            "tls": {}
        },

        {
            "port": 80,
            "service": "HTTP",
            "tls": {}
        },

        {
            "port": 445,
            "service": "SMB",
            "tls": {}
        },

        {
            "port": 3389,
            "service": "RDP",
            "tls": {}
        }
    ]


    results = run_security_analysis(
        test_ports
    )