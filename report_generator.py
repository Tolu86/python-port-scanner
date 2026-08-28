from datetime import datetime
from html import escape


# ============================================================
# HTML HELPERS
# ============================================================

def safe(value):

    if value is None:
        return "Unknown"

    return escape(
        str(value)
    )


def severity_class(severity):

    if not severity:
        return "unknown"

    severity = str(
        severity
    ).upper()

    if severity in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"
    ]:

        return severity.lower()

    return "unknown"


# ============================================================
# SECURITY FINDINGS
# ============================================================

def build_security_findings(
    security_analysis
):

    findings = (
        security_analysis.get(
            "findings",
            []
        )
    )

    if not findings:

        return """
        <div class="empty">
            No security findings were reported.
        </div>
        """

    html = ""

    for finding in findings:

        if isinstance(
            finding,
            dict
        ):

            title = finding.get(
                "title",
                finding.get(
                    "name",
                    "Security Finding"
                )
            )

            severity = finding.get(
                "severity",
                finding.get(
                    "risk",
                    "UNKNOWN"
                )
            )

            description = finding.get(
                "description",
                finding.get(
                    "message",
                    ""
                )
            )

        else:

            title = "Security Finding"

            severity = "UNKNOWN"

            description = finding

        html += f"""
        <div class="finding">

            <div class="finding-header">

                <h3>{safe(title)}</h3>

                <span class="badge {severity_class(severity)}">
                    {safe(severity)}
                </span>

            </div>

            <p>
                {safe(description)}
            </p>

        </div>
        """

    return html


# ============================================================
# TCP PORT TABLE
# ============================================================

def build_tcp_table(
    open_ports
):

    if not open_ports:

        return """
        <div class="empty">
            No open TCP ports were detected.
        </div>
        """

    rows = ""

    for port in open_ports:

        tls = port.get(
            "tls",
            {}
        )

        tls_version = tls.get(
            "tls_version",
            ""
        )

        rows += f"""
        <tr>

            <td>
                {safe(port.get("port"))}
            </td>

            <td>
                TCP
            </td>

            <td>
                <span class="open">
                    OPEN
                </span>
            </td>

            <td>
                {safe(
                    port.get(
                        "service",
                        "Unknown"
                    )
                )}
            </td>

            <td>
                {safe(
                    port.get(
                        "version",
                        "Unknown"
                    )
                )}
            </td>

            <td>
                {safe(
                    port.get(
                        "confidence",
                        "Unknown"
                    )
                )}
            </td>

            <td>
                {safe(
                    tls_version
                    or "-"
                )}
            </td>

        </tr>
        """

    return f"""
    <table>

        <thead>

            <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>State</th>
                <th>Service</th>
                <th>Version</th>
                <th>Confidence</th>
                <th>TLS</th>
            </tr>

        </thead>

        <tbody>
            {rows}
        </tbody>

    </table>
    """


# ============================================================
# UDP TABLE
# ============================================================

def build_udp_table(
    udp_results
):

    if not udp_results:

        return """
        <div class="empty">
            No UDP findings were reported.
        </div>
        """

    rows = ""

    for result in udp_results:

        rows += f"""
        <tr>

            <td>
                {safe(
                    result.get(
                        "port",
                        "Unknown"
                    )
                )}
            </td>

            <td>
                UDP
            </td>

            <td>
                {safe(
                    result.get(
                        "state",
                        "Unknown"
                    )
                )}
            </td>

            <td>
                {safe(
                    result.get(
                        "service",
                        "Unknown"
                    )
                )}
            </td>

            <td>
                {safe(
                    result.get(
                        "message",
                        ""
                    )
                )}
            </td>

        </tr>
        """

    return f"""
    <table>

        <thead>

            <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>State</th>
                <th>Service</th>
                <th>Information</th>
            </tr>

        </thead>

        <tbody>
            {rows}
        </tbody>

    </table>
    """


# ============================================================
# VULNERABILITY TABLE
# ============================================================

def build_vulnerability_table(
    vulnerabilities
):

    if not vulnerabilities:

        return """
        <div class="empty">
            No matching vulnerabilities were found.
        </div>
        """

    rows = ""

    for vulnerability in vulnerabilities:

        severity = vulnerability.get(
            "severity",
            "UNKNOWN"
        )

        score = vulnerability.get(
            "cvss"
        )

        match_status = vulnerability.get(
            "match_status",
            "UNKNOWN"
        )

        references = vulnerability.get(
            "references",
            []
        )

        reference_html = ""

        for reference in references[:3]:

            reference_html += f"""
            <a
                href="{safe(reference)}"
                target="_blank"
            >
                Reference
            </a>
            """

        rows += f"""
        <tr>

            <td>
                <strong>
                    {safe(
                        vulnerability.get(
                            "cve",
                            "Unknown"
                        )
                    )}
                </strong>
            </td>

            <td>
                {safe(
                    vulnerability.get(
                        "service",
                        "Unknown"
                    )
                )}
            </td>

            <td>
                {safe(
                    vulnerability.get(
                        "version",
                        "Unknown"
                    )
                )}
            </td>

            <td>
                <span class="badge {
                    severity_class(severity)
                }">
                    {safe(severity)}
                </span>
            </td>

            <td>
                {safe(
                    score
                    if score is not None
                    else "Unknown"
                )}
            </td>

            <td>
                {safe(match_status)}
            </td>

            <td>
                {reference_html or "-"}
            </td>

        </tr>
        """

    return f"""
    <table>

        <thead>

            <tr>
                <th>CVE</th>
                <th>Service</th>
                <th>Version</th>
                <th>Severity</th>
                <th>CVSS</th>
                <th>Match</th>
                <th>References</th>
            </tr>

        </thead>

        <tbody>
            {rows}
        </tbody>

    </table>
    """


# ============================================================
# TLS INFORMATION
# ============================================================

def build_tls_section(
    open_ports
):

    tls_entries = []

    for port in open_ports:

        tls = port.get(
            "tls",
            {}
        )

        if tls:

            tls_entries.append(
                (port, tls)
            )

    if not tls_entries:

        return """
        <div class="empty">
            No TLS information was detected.
        </div>
        """

    html = ""

    for port, tls in tls_entries:

        html += f"""
        <div class="tls-card">

            <h3>
                Port {safe(port.get("port"))}
            </h3>

            <p>
                <strong>TLS Version:</strong>
                {safe(
                    tls.get(
                        "tls_version"
                    )
                )}
            </p>

            <p>
                <strong>Cipher:</strong>
                {safe(
                    tls.get(
                        "cipher"
                    )
                )}
            </p>

            <p>
                <strong>Cipher Bits:</strong>
                {safe(
                    tls.get(
                        "cipher_bits"
                    )
                )}
            </p>

            <p>
                <strong>Certificate Subject:</strong>
                {safe(
                    tls.get(
                        "certificate_subject"
                    )
                )}
            </p>

            <p>
                <strong>Certificate Issuer:</strong>
                {safe(
                    tls.get(
                        "certificate_issuer"
                    )
                )}
            </p>

            <p>
                <strong>Valid Until:</strong>
                {safe(
                    tls.get(
                        "certificate_valid_until"
                    )
                )}
            </p>

        </div>
        """

    return html


# ============================================================
# HTML REPORT GENERATOR
# ============================================================

def generate_html_report(
    results,
    filename
):

    target = results.get(
        "target",
        "Unknown"
    )

    profile = results.get(
        "profile",
        "Unknown"
    )

    scan_started = results.get(
        "scan_started",
        ""
    )

    scan_finished = results.get(
        "scan_finished",
        ""
    )

    duration = results.get(
        "scan_duration_seconds",
        0
    )

    ports_scanned = results.get(
        "ports_scanned",
        0
    )

    open_ports_count = results.get(
        "open_ports_count",
        0
    )

    closed_ports_count = results.get(
        "closed_ports_count",
        0
    )

    open_ports = results.get(
        "open_ports",
        []
    )

    udp_results = results.get(
        "udp_results",
        []
    )

    os_fingerprint = results.get(
        "os_fingerprint",
        {}
    )

    security_analysis = results.get(
        "security_analysis",
        {}
    )

    vulnerabilities = results.get(
        "vulnerabilities",
        []
    )

    overall_risk = security_analysis.get(
        "overall_risk",
        "UNKNOWN"
    )

    security_summary = (
        security_analysis.get(
            "summary",
            {}
        )
    )

    security_findings = (
        build_security_findings(
            security_analysis
        )
    )

    tcp_table = (
        build_tcp_table(
            open_ports
        )
    )

    udp_table = (
        build_udp_table(
            udp_results
        )
    )

    vulnerability_table = (
        build_vulnerability_table(
            vulnerabilities
        )
    )

    tls_section = (
        build_tls_section(
            open_ports
        )
    )

    generated_at = (
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    html = f"""<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,
    initial-scale=1.0"
>

<title>
    Port Scanner Security Report
</title>


<style>

* {{
    box-sizing: border-box;
}}

body {{

    margin: 0;

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background:
        #f4f6f8;

    color:
        #1f2933;

}}

.container {{

    width: 92%;

    max-width: 1400px;

    margin:
        30px auto;

}}

.header {{

    background:
        #111827;

    color:
        white;

    padding:
        35px;

    border-radius:
        12px;

    margin-bottom:
        25px;

}}

.header h1 {{

    margin:
        0 0 10px 0;

    font-size:
        32px;

}}

.header p {{

    margin:
        5px 0;

}}

.grid {{

    display:
        grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                200px,
                1fr
            )
        );

    gap:
        15px;

    margin-bottom:
        25px;

}}

.card {{

    background:
        white;

    padding:
        22px;

    border-radius:
        10px;

    box-shadow:
        0 2px 8px
        rgba(
            0,
            0,
            0,
            0.06
        );

}}

.card h3 {{

    margin-top:
        0;

    color:
        #4b5563;

}}

.metric {{

    font-size:
        30px;

    font-weight:
        bold;

}}

section {{

    background:
        white;

    padding:
        25px;

    border-radius:
        10px;

    margin-bottom:
        25px;

    box-shadow:
        0 2px 8px
        rgba(
            0,
            0,
            0,
            0.06
        );

}}

section h2 {{

    margin-top:
        0;

    border-bottom:
        1px solid #e5e7eb;

    padding-bottom:
        12px;

}}

table {{

    width:
        100%;

    border-collapse:
        collapse;

    margin-top:
        15px;

}}

th,
td {{

    padding:
        12px;

    text-align:
        left;

    border-bottom:
        1px solid #e5e7eb;

    vertical-align:
        top;

}}

th {{

    background:
        #f9fafb;

}}

tr:hover {{

    background:
        #f9fafb;

}}

.open {{

    font-weight:
        bold;

}}

.badge {{

    display:
        inline-block;

    padding:
        5px 9px;

    border-radius:
        6px;

    font-size:
        12px;

    font-weight:
        bold;

}}

.critical {{

    background:
        #fee2e2;

}}

.high {{

    background:
        #ffedd5;

}}

.medium {{

    background:
        #fef3c7;

}}

.low {{

    background:
        #dcfce7;

}}

.unknown {{

    background:
        #e5e7eb;

}}

.finding {{

    border:
        1px solid #e5e7eb;

    padding:
        18px;

    margin-bottom:
        15px;

    border-radius:
        8px;

}}

.finding-header {{

    display:
        flex;

    justify-content:
        space-between;

    align-items:
        center;

    gap:
        15px;

}}

.finding-header h3 {{

    margin:
        0;

}}

.tls-card {{

    border:
        1px solid #e5e7eb;

    border-radius:
        8px;

    padding:
        18px;

    margin-bottom:
        15px;

}}

.empty {{

    padding:
        20px;

    background:
        #f9fafb;

    border-radius:
        8px;

}}

.footer {{

    text-align:
        center;

    color:
        #6b7280;

    padding:
        25px;

}}

a {{

    text-decoration:
        none;

}}

</style>

</head>


<body>


<div class="container">


<!-- =====================================================
     HEADER
====================================================== -->

<div class="header">

<h1>
    Port Scanner Security Report
</h1>

<p>
    <strong>Target:</strong>
    {safe(target)}
</p>

<p>
    <strong>Scan Profile:</strong>
    {safe(profile)}
</p>

<p>
    <strong>Started:</strong>
    {safe(scan_started)}
</p>

<p>
    <strong>Finished:</strong>
    {safe(scan_finished)}
</p>

<p>
    <strong>Generated:</strong>
    {safe(generated_at)}
</p>

</div>


<!-- =====================================================
     SUMMARY
====================================================== -->

<div class="grid">


<div class="card">

<h3>
    Ports Scanned
</h3>

<div class="metric">
    {safe(ports_scanned)}
</div>

</div>


<div class="card">

<h3>
    Open TCP Ports
</h3>

<div class="metric">
    {safe(open_ports_count)}
</div>

</div>


<div class="card">

<h3>
    Closed TCP Ports
</h3>

<div class="metric">
    {safe(closed_ports_count)}
</div>

</div>


<div class="card">

<h3>
    Vulnerabilities
</h3>

<div class="metric">
    {safe(len(vulnerabilities))}
</div>

</div>


<div class="card">

<h3>
    Overall Risk
</h3>

<div class="metric">

<span class="badge {
    severity_class(overall_risk)
}">

    {safe(overall_risk)}

</span>

</div>

</div>


<div class="card">

<h3>
    Scan Duration
</h3>

<div class="metric">

{safe(duration)}s

</div>

</div>


</div>


<!-- =====================================================
     TCP
====================================================== -->

<section>

<h2>
    TCP Port Findings
</h2>

{tcp_table}

</section>


<!-- =====================================================
     UDP
====================================================== -->

<section>

<h2>
    UDP Findings
</h2>

{udp_table}

</section>


<!-- =====================================================
     OS
====================================================== -->

<section>

<h2>
    Operating System Fingerprint
</h2>

<p>

<strong>
    Estimated OS:
</strong>

{safe(
    os_fingerprint.get(
        "estimated_os",
        "Unknown"
    )
)}

</p>

<p>

<strong>
    Confidence:
</strong>

{safe(
    os_fingerprint.get(
        "confidence",
        "Unknown"
    )
)}

</p>

<p>

<strong>
    Observed TTL:
</strong>

{safe(
    os_fingerprint.get(
        "observed_ttl",
        "Unknown"
    )
)}

</p>

<p>

<strong>
    Reason:
</strong>

{safe(
    os_fingerprint.get(
        "reason",
        ""
    )
)}

</p>

</section>


<!-- =====================================================
     SECURITY
====================================================== -->

<section>

<h2>
    Security Analysis
</h2>

{security_findings}

</section>


<!-- =====================================================
     VULNERABILITIES
====================================================== -->

<section>

<h2>
    Vulnerability Intelligence
</h2>

{vulnerability_table}

</section>


<!-- =====================================================
     TLS
====================================================== -->

<section>

<h2>
    TLS / Certificate Information
</h2>

{tls_section}

</section>


<!-- =====================================================
     FOOTER
====================================================== -->

<div class="footer">

Generated by
<strong>
    Python Port Scanner
</strong>

</div>


</div>

</body>

</html>
"""

    try:

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                html
            )

        print()

        print(
            f"HTML report saved to: "
            f"{filename}"
        )

        return True

    except OSError as error:

        print(
            f"Could not create HTML report: "
            f"{error}"
        )

        return False