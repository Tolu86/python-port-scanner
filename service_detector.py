import socket
import ssl
import re
from datetime import datetime, timezone


# ============================================================
# COMMON PORT SERVICES
# ============================================================

COMMON_SERVICES = {

    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP",
    8443: "HTTPS"
}


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_text(text):

    if not text:
        return None

    text = text.replace(
        "\r",
        " "
    )

    text = text.replace(
        "\n",
        " "
    )

    text = " ".join(
        text.split()
    )

    return text[:500]


# ============================================================
# TCP CONNECTION
# ============================================================

def create_connection(
    target,
    port,
    timeout
):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(
        timeout
    )

    try:

        sock.connect(
            (target, port)
        )

        return sock

    except (
        socket.timeout,
        socket.error
    ):

        sock.close()

        return None


# ============================================================
# GENERIC BANNER
# ============================================================

def grab_banner(
    target,
    port,
    timeout=2
):

    sock = create_connection(
        target,
        port,
        timeout
    )

    if not sock:

        return None

    try:

        data = sock.recv(
            2048
        )

        if not data:

            return None

        return clean_text(
            data.decode(
                "utf-8",
                errors="replace"
            )
        )

    except (
        socket.timeout,
        socket.error
    ):

        return None

    finally:

        sock.close()


# ============================================================
# VERSION EXTRACTION
# ============================================================

def extract_version(
    text
):

    if not text:

        return None

    text = clean_text(
        text
    )


    patterns = [

        r"(OpenSSH[_\-/]?[0-9]+(?:\.[0-9]+)*)",

        r"(Apache/[0-9]+(?:\.[0-9]+)+)",

        r"(nginx/[0-9]+(?:\.[0-9]+)+)",

        r"(Microsoft-IIS/[0-9]+(?:\.[0-9]+)*)",

        r"([A-Za-z][A-Za-z0-9_-]{1,30}"
        r"[/_-]"
        r"[0-9]+(?:\.[0-9]+){1,4})"
    ]


    for pattern in patterns:

        match = re.search(
            pattern,
            text,
            re.IGNORECASE
        )

        if match:

            return match.group(
                1
            )


    return None


# ============================================================
# HTTP PROBE
# ============================================================

def probe_http(
    target,
    port,
    timeout=2
):

    sock = create_connection(
        target,
        port,
        timeout
    )

    if not sock:

        return None

    try:

        request = (

            "HEAD / HTTP/1.1\r\n"

            f"Host: {target}\r\n"

            "Connection: close\r\n"

            "\r\n"
        )

        sock.sendall(
            request.encode()
        )

        response = sock.recv(
            4096
        )

        if not response:

            return None

        text = response.decode(
            "iso-8859-1",
            errors="replace"
        )

        lines = text.split(
            "\r\n"
        )

        if not lines:

            return None

        status = lines[0].strip()

        if not status.startswith(
            "HTTP/"
        ):

            return None

        server = None

        content_type = None


        for line in lines:

            lower = line.lower()

            if lower.startswith(
                "server:"
            ):

                server = line.split(
                    ":",
                    1
                )[1].strip()

            elif lower.startswith(
                "content-type:"
            ):

                content_type = line.split(
                    ":",
                    1
                )[1].strip()


        version = extract_version(
            server
        )


        return {

            "service": "HTTP",

            "status": status,

            "server": server,

            "version": version,

            "content_type":
                content_type,

            "confidence": "HIGH",

            "method":
                "HTTP response"
        }


    except (
        socket.timeout,
        socket.error
    ):

        return None

    finally:

        sock.close()


# ============================================================
# SSH PROBE
# ============================================================

def probe_ssh(
    target,
    port,
    timeout=2
):

    sock = create_connection(
        target,
        port,
        timeout
    )

    if not sock:

        return None

    try:

        data = sock.recv(
            2048
        )

        if not data:

            return None

        response = clean_text(
            data.decode(
                "utf-8",
                errors="replace"
            )
        )

        if response and response.startswith(
            "SSH-"
        ):

            version = extract_version(
                response
            )

            return {

                "service": "SSH",

                "status": response,

                "server": response,

                "version": version,

                "confidence": "HIGH",

                "method":
                    "SSH identification string"
            }

        return None


    except (
        socket.timeout,
        socket.error
    ):

        return None

    finally:

        sock.close()


# ============================================================
# FTP PROBE
# ============================================================

def probe_ftp(
    target,
    port,
    timeout=2
):

    sock = create_connection(
        target,
        port,
        timeout
    )

    if not sock:

        return None

    try:

        data = sock.recv(
            2048
        )

        if not data:

            return None

        response = clean_text(
            data.decode(
                "utf-8",
                errors="replace"
            )
        )

        if response and response.startswith(
            "220"
        ):

            version = extract_version(
                response
            )

            return {

                "service": "FTP",

                "status": response,

                "server": response,

                "version": version,

                "confidence": "HIGH",

                "method":
                    "FTP welcome message"
            }

        return None


    except (
        socket.timeout,
        socket.error
    ):

        return None

    finally:

        sock.close()


# ============================================================
# SMTP PROBE
# ============================================================

def probe_smtp(
    target,
    port,
    timeout=2
):

    sock = create_connection(
        target,
        port,
        timeout
    )

    if not sock:

        return None

    try:

        data = sock.recv(
            2048
        )

        if not data:

            return None

        response = clean_text(
            data.decode(
                "utf-8",
                errors="replace"
            )
        )

        if response and response.startswith(
            "220"
        ):

            version = extract_version(
                response
            )

            return {

                "service": "SMTP",

                "status": response,

                "server": response,

                "version": version,

                "confidence": "HIGH",

                "method":
                    "SMTP greeting"
            }

        return None


    except (
        socket.timeout,
        socket.error
    ):

        return None

    finally:

        sock.close()


# ============================================================
# TLS CERTIFICATE DATE CHECK
# ============================================================

def check_certificate_dates(
    certificate
):

    result = {

        "valid_from": None,

        "valid_until": None,

        "currently_valid": None
    }


    try:

        valid_from = certificate.get(
            "notBefore"
        )

        valid_until = certificate.get(
            "notAfter"
        )


        if valid_from:

            result["valid_from"] = (
                valid_from
            )


        if valid_until:

            result["valid_until"] = (
                valid_until
            )


        if valid_from and valid_until:

            start = ssl.cert_time_to_seconds(
                valid_from
            )

            end = ssl.cert_time_to_seconds(
                valid_until
            )

            now = datetime.now(
                timezone.utc
            ).timestamp()


            result[
                "currently_valid"
            ] = (
                start <= now <= end
            )


    except Exception:

        pass


    return result


# ============================================================
# TLS PROBE
# ============================================================

def probe_tls(
    target,
    port,
    timeout=4
):

    context = ssl.create_default_context()

    # We inspect the certificate ourselves.
    # This allows us to inspect certificates that
    # may not pass normal browser trust validation.

    context.check_hostname = False

    context.verify_mode = (
        ssl.CERT_NONE
    )


    raw_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    raw_socket.settimeout(
        timeout
    )


    try:

        raw_socket.connect(
            (target, port)
        )


        with context.wrap_socket(
            raw_socket,
            server_hostname=target
        ) as tls_socket:

            certificate = (
                tls_socket.getpeercert()
            )

            cipher = (
                tls_socket.cipher()
            )

            tls_version = (
                tls_socket.version()
            )


            certificate_dates = (
                check_certificate_dates(
                    certificate
                )
            )


            subject = certificate.get(
                "subject",
                ()
            )

            issuer = certificate.get(
                "issuer",
                ()
            )


            return {

                "service":
                    "HTTPS",

                "tls_version":
                    tls_version,

                "cipher":
                    cipher[0]
                    if cipher
                    else None,

                "cipher_bits":
                    cipher[2]
                    if cipher
                    else None,

                "certificate_subject":
                    str(subject),

                "certificate_issuer":
                    str(issuer),

                "certificate_valid_from":
                    certificate_dates[
                        "valid_from"
                    ],

                "certificate_valid_until":
                    certificate_dates[
                        "valid_until"
                    ],

                "certificate_currently_valid":
                    certificate_dates[
                        "currently_valid"
                    ],

                "confidence":
                    "HIGH",

                "method":
                    "TLS handshake"
            }


    except (
        socket.timeout,
        socket.error,
        ssl.SSLError
    ):

        return None

    except Exception:

        return None

    finally:

        try:

            raw_socket.close()

        except Exception:

            pass


# ============================================================
# HTTPS CANDIDATE
# ============================================================

def probe_https(
    target,
    port,
    timeout=4
):

    tls_result = probe_tls(
        target,
        port,
        timeout
    )


    if tls_result:

        return tls_result


    return {

        "service":
            "HTTPS",

        "tls_version":
            None,

        "cipher":
            None,

        "cipher_bits":
            None,

        "certificate_subject":
            None,

        "certificate_issuer":
            None,

        "certificate_valid_from":
            None,

        "certificate_valid_until":
            None,

        "certificate_currently_valid":
            None,

        "confidence":
            "LOW",

        "method":
            "TLS handshake failed"
    }


# ============================================================
# BEHAVIORAL DETECTION
# ============================================================

def behavioral_detection(
    target,
    port,
    timeout=2
):

    probes = [

        probe_http,

        probe_ssh,

        probe_ftp,

        probe_smtp
    ]


    for probe in probes:

        result = probe(
            target,
            port,
            timeout
        )

        if result:

            return result


    return None


# ============================================================
# MAIN DETECTOR
# ============================================================

def detect_service(
    target,
    port,
    timeout=2
):

    known_service = COMMON_SERVICES.get(
        port
    )


    # ========================================================
    # HTTPS / TLS
    # ========================================================

    if known_service == "HTTPS":

        result = probe_https(
            target,
            port,
            timeout
        )


        return {

            "port":
                port,

            "service":
                "HTTPS",

            "information":
                "TLS service",

            "version":
                None,

            "banner":
                None,

            "confidence":
                result[
                    "confidence"
                ],

            "detection_method":
                result[
                    "method"
                ],

            "tls":
                result
        }


    # ========================================================
    # HTTP
    # ========================================================

    if known_service == "HTTP":

        result = probe_http(
            target,
            port,
            timeout
        )

        if result:

            return {

                "port":
                    port,

                "service":
                    result[
                        "service"
                    ],

                "information":
                    result[
                        "status"
                    ],

                "version":
                    result[
                        "version"
                    ],

                "banner":
                    result[
                        "server"
                    ],

                "confidence":
                    result[
                        "confidence"
                    ],

                "detection_method":
                    result[
                        "method"
                    ]
            }


    # ========================================================
    # SSH
    # ========================================================

    if known_service == "SSH":

        result = probe_ssh(
            target,
            port,
            timeout
        )

        if result:

            return {

                "port":
                    port,

                "service":
                    result[
                        "service"
                    ],

                "information":
                    result[
                        "status"
                    ],

                "version":
                    result[
                        "version"
                    ],

                "banner":
                    result[
                        "server"
                    ],

                "confidence":
                    result[
                        "confidence"
                    ],

                "detection_method":
                    result[
                        "method"
                    ]
            }


    # ========================================================
    # FTP
    # ========================================================

    if known_service == "FTP":

        result = probe_ftp(
            target,
            port,
            timeout
        )

        if result:

            return {

                "port":
                    port,

                "service":
                    result[
                        "service"
                    ],

                "information":
                    result[
                        "status"
                    ],

                "version":
                    result[
                        "version"
                    ],

                "banner":
                    result[
                        "server"
                    ],

                "confidence":
                    result[
                        "confidence"
                    ],

                "detection_method":
                    result[
                        "method"
                    ]
            }


    # ========================================================
    # SMTP
    # ========================================================

    if known_service == "SMTP":

        result = probe_smtp(
            target,
            port,
            timeout
        )

        if result:

            return {

                "port":
                    port,

                "service":
                    result[
                        "service"
                    ],

                "information":
                    result[
                        "status"
                    ],

                "version":
                    result[
                        "version"
                    ],

                "banner":
                    result[
                        "server"
                    ],

                "confidence":
                    result[
                        "confidence"
                    ],

                "detection_method":
                    result[
                        "method"
                    ]
            }


    # ========================================================
    # UNKNOWN PORT
    # ========================================================

    result = behavioral_detection(
        target,
        port,
        timeout
    )

    if result:

        return {

            "port":
                port,

            "service":
                result[
                    "service"
                ],

            "information":
                result[
                    "status"
                ],

            "version":
                result[
                    "version"
                ],

            "banner":
                result[
                    "server"
                ],

            "confidence":
                result[
                    "confidence"
                ],

            "detection_method":
                result[
                    "method"
                ]
        }


    # ========================================================
    # GENERIC BANNER
    # ========================================================

    banner = grab_banner(
        target,
        port,
        timeout
    )

    if banner:

        return {

            "port":
                port,

            "service":
                "Unknown",

            "information":
                banner,

            "version":
                extract_version(
                    banner
                ),

            "banner":
                banner,

            "confidence":
                "LOW",

            "detection_method":
                "Generic banner"
        }


    # ========================================================
    # UNKNOWN
    # ========================================================

    return {

        "port":
            port,

        "service":
            "Unknown",

        "information":
            None,

        "version":
            None,

        "banner":
            None,

        "confidence":
            "LOW",

        "detection_method":
            "No protocol identified"
    }