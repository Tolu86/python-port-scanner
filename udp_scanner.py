import socket
import time
import struct


# ============================================================
# COMMON UDP PORTS
# ============================================================

COMMON_UDP_PORTS = [
    53,       # DNS
    67,       # DHCP
    69,       # TFTP
    123,      # NTP
    137,      # NetBIOS
    138,      # NetBIOS
    161,      # SNMP
    162,      # SNMP Trap
    500,      # IKE
    514,      # Syslog
    520,      # RIP
    631,      # IPP
    1434,     # MS SQL Monitor
    1900,     # SSDP
    4500,     # IPsec NAT-T
    5353,     # mDNS
    5355,     # LLMNR
    11211     # Memcached
]


# ============================================================
# SERVICE NAMES
# ============================================================

UDP_SERVICES = {

    53: "DNS",
    67: "DHCP",
    69: "TFTP",
    123: "NTP",
    137: "NetBIOS",
    138: "NetBIOS",
    161: "SNMP",
    162: "SNMP Trap",
    500: "IKE",
    514: "Syslog",
    520: "RIP",
    631: "IPP",
    1434: "MS SQL Monitor",
    1900: "SSDP",
    4500: "IPsec NAT-T",
    5353: "mDNS",
    5355: "LLMNR",
    11211: "Memcached"
}


# ============================================================
# DNS PROBE
# ============================================================

def dns_probe():

    # Transaction ID
    transaction_id = b"\x12\x34"

    # Standard DNS query
    flags = b"\x01\x00"

    # One question
    questions = b"\x00\x01"

    # No answers
    answers = b"\x00\x00"

    # No authority records
    authority = b"\x00\x00"

    # No additional records
    additional = b"\x00\x00"

    # Query: example.com
    domain = (
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    # Type A
    query_type = b"\x00\x01"

    # Class IN
    query_class = b"\x00\x01"

    return (
        transaction_id +
        flags +
        questions +
        answers +
        authority +
        additional +
        domain +
        query_type +
        query_class
    )


# ============================================================
# NTP PROBE
# ============================================================

def ntp_probe():

    # NTP client request
    packet = bytearray(48)

    # LI = 0
    # Version = 3
    # Mode = 3 (client)
    packet[0] = 0x1B

    return bytes(packet)


# ============================================================
# SNMP PROBE
# ============================================================

def snmp_probe():

    # SNMPv1 GET request
    #
    # Community: public
    #
    # Request ID: 1
    #
    # OID: sysDescr

    packet = bytes.fromhex(
        "301b"
        "020101"
        "04067075626c6963"
        "a00e"
        "020101"
        "020100"
        "020100"
        "3003"
        "3000"
    )

    return packet


# ============================================================
# SSDP PROBE
# ============================================================

def ssdp_probe():

    return (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n"
        b"\r\n"
    )


# ============================================================
# GENERIC PROBE
# ============================================================

def generic_probe():

    return b"\x00"


# ============================================================
# GET PROBE
# ============================================================

def get_probe(port):

    if port == 53:

        return dns_probe()

    if port == 123:

        return ntp_probe()

    if port == 161:

        return snmp_probe()

    if port == 1900:

        return ssdp_probe()

    return generic_probe()


# ============================================================
# RESPONSE ANALYSIS
# ============================================================

def analyze_response(
    port,
    data
):

    if not data:

        return False, None


    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    if port == 53:

        if len(data) >= 12:

            return (
                True,
                "DNS response received"
            )


    # --------------------------------------------------------
    # NTP
    # --------------------------------------------------------

    if port == 123:

        if len(data) >= 48:

            return (
                True,
                "NTP response received"
            )


    # --------------------------------------------------------
    # SNMP
    # --------------------------------------------------------

    if port == 161:

        # SNMP responses are ASN.1/BER encoded
        #
        # 0x30 = ASN.1 SEQUENCE

        if data[0] == 0x30:

            return (
                True,
                "SNMP response received"
            )


    # --------------------------------------------------------
    # SSDP
    # --------------------------------------------------------

    if port == 1900:

        try:

            text = data.decode(
                "utf-8",
                errors="ignore"
            )

            if (
                "HTTP/" in text or
                "ST:" in text or
                "USN:" in text
            ):

                return (
                    True,
                    "SSDP response received"
                )

        except Exception:

            pass


    # --------------------------------------------------------
    # GENERIC
    # --------------------------------------------------------

    return (
        True,
        "UDP response received"
    )


# ============================================================
# UDP PORT SCAN
# ============================================================

def scan_udp_port(
    target,
    port,
    timeout=2
):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.settimeout(
        timeout
    )


    probe = get_probe(
        port
    )


    start_time = time.time()


    try:

        sock.sendto(
            probe,
            (target, port)
        )


        try:

            data, address = sock.recvfrom(
                4096
            )


            elapsed = (
                time.time() -
                start_time
            )


            confirmed, message = (
                analyze_response(
                    port,
                    data
                )
            )


            if confirmed:

                state = "OPEN"

            else:

                state = "OPEN|FILTERED"


            return {

                "port":
                    port,

                "state":
                    state,

                "service":
                    UDP_SERVICES.get(
                        port,
                        "Unknown"
                    ),

                "response":
                    data,

                "response_length":
                    len(data),

                "response_text":
                    decode_response(
                        data
                    ),

                "response_time":
                    round(
                        elapsed,
                        4
                    ),

                "message":
                    message,

                "address":
                    address
            }


        except socket.timeout:

            return {

                "port":
                    port,

                "state":
                    "OPEN|FILTERED",

                "service":
                    UDP_SERVICES.get(
                        port,
                        "Unknown"
                    ),

                "response":
                    None,

                "response_length":
                    0,

                "response_text":
                    None,

                "response_time":
                    round(
                        time.time() -
                        start_time,
                        4
                    ),

                "message":
                    "No UDP response",

                "address":
                    None
            }


    except socket.error as error:

        return {

            "port":
                port,

            "state":
                "ERROR",

            "service":
                UDP_SERVICES.get(
                    port,
                    "Unknown"
                ),

            "response":
                None,

            "response_length":
                0,

            "response_text":
                None,

            "response_time":
                0,

            "message":
                str(error),

            "address":
                None
        }


    finally:

        sock.close()


# ============================================================
# RESPONSE DECODER
# ============================================================

def decode_response(
    response
):

    if not response:

        return None


    try:

        text = response.decode(
            "utf-8",
            errors="replace"
        )

        text = " ".join(
            text.split()
        )


        if text:

            return text[:300]


    except Exception:

        pass


    return response.hex()[:300]


# ============================================================
# UDP SCANNER
# ============================================================

def udp_scan(
    target,
    ports=None,
    timeout=2
):

    if ports is None:

        ports = COMMON_UDP_PORTS


    results = []


    print()

    print(
        "=" * 90
    )

    print(
        "                           UDP SCAN"
    )

    print(
        "=" * 90
    )

    print(
        f"Target: {target}"
    )

    print(
        f"Ports : {len(ports)}"
    )

    print(
        "=" * 90
    )

    print()


    for port in ports:

        print(
            f"Testing UDP/{port}...",
            end=" ",
            flush=True
        )


        result = scan_udp_port(
            target,
            port,
            timeout
        )


        results.append(
            result
        )


        print(
            result["state"]
        )


        if result.get(
            "message"
        ):

            print(
                f"    {result['message']}"
            )


        if result.get(
            "response_text"
        ):

            print(
                f"    Response: "
                f"{result['response_text'][:150]}"
            )


    # ========================================================
    # RESULTS TABLE
    # ========================================================

    print()

    print(
        "=" * 90
    )

    print(
        "                         UDP RESULTS"
    )

    print(
        "=" * 90
    )

    print(

        f"{'PORT':<10}"

        f"{'STATE':<20}"

        f"{'SERVICE':<20}"

        f"RESPONSE"
    )

    print(
        "-" * 90
    )


    for result in results:

        response = (
            result.get(
                "response_text"
            )
            or "-"
        )


        print(

            f"{result['port']:<10}"

            f"{result['state']:<20}"

            f"{result['service']:<20}"

            f"{response[:30]}"
        )


    print(
        "=" * 90
    )


    return results


# ============================================================
# COMMAND LINE
# ============================================================

if __name__ == "__main__":

    import argparse


    parser = argparse.ArgumentParser(
        description=
        "UDP Port Scanner"
    )


    parser.add_argument(
        "target",
        help=
        "Target IP or hostname"
    )


    parser.add_argument(
        "-p",
        "--ports",
        help=
        "Ports, e.g. 53,123,161"
    )


    parser.add_argument(
        "--timeout",
        type=float,
        default=2,
        help=
        "Timeout in seconds"
    )


    args = parser.parse_args()


    # --------------------------------------------------------
    # Parse ports
    # --------------------------------------------------------

    if args.ports:

        ports = []


        for part in args.ports.split(","):

            part = part.strip()


            if "-" in part:

                start, end = map(
                    int,
                    part.split("-")
                )


                ports.extend(
                    range(
                        start,
                        end + 1
                    )
                )


            else:

                ports.append(
                    int(part)
                )


    else:

        ports = COMMON_UDP_PORTS


    # --------------------------------------------------------
    # Validate target
    # --------------------------------------------------------

    try:

        socket.gethostbyname(
            args.target
        )

    except socket.gaierror:

        print(
            f"Could not resolve "
            f"{args.target}"
        )

        raise SystemExit(1)


    # --------------------------------------------------------
    # Run scanner
    # --------------------------------------------------------

    udp_scan(
        args.target,
        ports,
        args.timeout
    )