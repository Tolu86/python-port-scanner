import socket
import struct
import subprocess
import platform
import re


# ============================================================
# TTL RANGES
# ============================================================

TTL_SIGNATURES = {
    "Linux / Unix": range(50, 65),
    "Windows": range(120, 129),
    "Network Device": range(240, 256),
}


# ============================================================
# GET TTL USING PING
# ============================================================

def get_ping_ttl(target):

    system = platform.system().lower()

    if system == "windows":

        command = [
            "ping",
            "-n",
            "1",
            "-w",
            "2000",
            target
        ]

    else:

        command = [
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            target
        ]


    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5
        )


        output = (
            result.stdout +
            result.stderr
        )


        # Windows:
        # TTL=128
        #
        # Linux:
        # ttl=64

        match = re.search(
            r"TTL[=\s](\d+)",
            output,
            re.IGNORECASE
        )


        if not match:

            return None


        return int(
            match.group(1)
        )


    except (
        subprocess.TimeoutExpired,
        FileNotFoundError,
        OSError
    ):

        return None


# ============================================================
# ESTIMATE ORIGINAL TTL
# ============================================================

def estimate_original_ttl(
    observed_ttl
):

    if observed_ttl is None:

        return None


    possible_ttls = [
        32,
        60,
        64,
        128,
        255
    ]


    for ttl in possible_ttls:

        if observed_ttl <= ttl:

            return ttl


    return None


# ============================================================
# GUESS OS FROM TTL
# ============================================================

def guess_os_from_ttl(
    ttl
):

    if ttl is None:

        return {
            "os": "Unknown",
            "confidence": "LOW",
            "reason":
                "TTL could not be determined"
        }


    if 50 <= ttl <= 65:

        return {
            "os":
                "Linux / Unix-like",

            "confidence":
                "MEDIUM",

            "reason":
                f"Observed TTL={ttl}, "
                f"which is common for Linux/Unix systems"
        }


    if 120 <= ttl <= 128:

        return {
            "os":
                "Windows",

            "confidence":
                "MEDIUM",

            "reason":
                f"Observed TTL={ttl}, "
                f"which is common for Windows systems"
        }


    if 240 <= ttl <= 255:

        return {
            "os":
                "Network Device",

            "confidence":
                "LOW",

            "reason":
                f"Observed TTL={ttl}, "
                f"which may indicate a network device"
        }


    return {
        "os":
            "Unknown",

        "confidence":
            "LOW",

        "reason":
            f"TTL={ttl} does not match "
            f"a known basic signature"
    }


# ============================================================
# COMMON SERVICE CLUES
# ============================================================

def analyze_open_ports(
    open_ports
):

    ports = set(
        open_ports
    )


    clues = []


    # --------------------------------------------------------
    # Windows clues
    # --------------------------------------------------------

    if 135 in ports:

        clues.append(
            "TCP/135 RPC detected"
        )


    if 139 in ports:

        clues.append(
            "TCP/139 NetBIOS detected"
        )


    if 445 in ports:

        clues.append(
            "TCP/445 SMB detected"
        )


    if 3389 in ports:

        clues.append(
            "TCP/3389 RDP detected"
        )


    # --------------------------------------------------------
    # Linux / Unix clues
    # --------------------------------------------------------

    if 22 in ports:

        clues.append(
            "TCP/22 SSH detected"
        )


    if 111 in ports:

        clues.append(
            "TCP/111 RPCbind detected"
        )


    if 2049 in ports:

        clues.append(
            "TCP/2049 NFS detected"
        )


    return clues


# ============================================================
# FINGERPRINT TARGET
# ============================================================

def fingerprint_target(
    target,
    open_ports=None
):

    if open_ports is None:

        open_ports = []


    print()

    print(
        "=" * 80
    )

    print(
        "                       OS FINGERPRINT"
    )

    print(
        "=" * 80
    )

    print(
        f"Target: {target}"
    )

    print()


    # ========================================================
    # TTL
    # ========================================================

    print(
        "Checking TTL..."
    )


    ttl = get_ping_ttl(
        target
    )


    if ttl is not None:

        print(
            f"Observed TTL: {ttl}"
        )

    else:

        print(
            "Observed TTL: Unknown"
        )


    # ========================================================
    # OS GUESS
    # ========================================================

    fingerprint = (
        guess_os_from_ttl(
            ttl
        )
    )


    # ========================================================
    # PORT CLUES
    # ========================================================

    clues = analyze_open_ports(
        open_ports
    )


    print()

    print(
        "OS Estimate:"
    )

    print(
        f"  {fingerprint['os']}"
    )

    print(
        f"  Confidence: "
        f"{fingerprint['confidence']}"
    )

    print(
        f"  Reason: "
        f"{fingerprint['reason']}"
    )


    if clues:

        print()

        print(
            "Service clues:"
        )


        for clue in clues:

            print(
                f"  - {clue}"
            )


    print()

    print(
        "=" * 80
    )


    return {

        "target":
            target,

        "observed_ttl":
            ttl,

        "estimated_os":
            fingerprint["os"],

        "confidence":
            fingerprint["confidence"],

        "reason":
            fingerprint["reason"],

        "service_clues":
            clues
    }


# ============================================================
# COMMAND LINE TEST
# ============================================================

if __name__ == "__main__":

    import argparse


    parser = argparse.ArgumentParser(
        description=
        "Basic OS Fingerprinting Tool"
    )


    parser.add_argument(
        "target"
    )


    parser.add_argument(
        "-p",
        "--ports",
        default=""
    )


    args = parser.parse_args()


    # --------------------------------------------------------
    # Parse ports
    # --------------------------------------------------------

    if args.ports:

        ports = []

        for port in args.ports.split(","):

            try:

                ports.append(
                    int(port.strip())
                )

            except ValueError:

                pass

    else:

        ports = []


    fingerprint_target(
        args.target,
        ports
    )