from flask import (
    Flask,
    request,
    render_template_string,
    jsonify
)

import subprocess
import json
import os
import sys
import threading
import uuid
import time


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# SCAN STORAGE
# ============================================================

scans = {}

scan_lock = threading.Lock()


# ============================================================
# DASHBOARD HTML
# ============================================================

HTML = """
<!DOCTYPE html>

<html>

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width,
        initial-scale=1.0"
    >

    <title>
        Port Scanner Dashboard
    </title>


    <style>

        * {
            box-sizing: border-box;
        }


        body {

            margin: 0;

            font-family:
                Arial,
                Helvetica,
                sans-serif;

            background:
                #f3f4f6;

            color:
                #111827;
        }


        .container {

            width: 92%;

            max-width:
                1200px;

            margin:
                40px auto;
        }


        .header {

            background:
                #111827;

            color:
                white;

            padding:
                30px;

            border-radius:
                12px;

            margin-bottom:
                25px;
        }


        .header h1 {

            margin:
                0 0 10px 0;
        }


        .header p {

            margin:
                5px 0;

            color:
                #d1d5db;
        }


        .card {

            background:
                white;

            padding:
                25px;

            border-radius:
                12px;

            box-shadow:
                0 2px 10px
                rgba(
                    0,
                    0,
                    0,
                    0.06
                );

            margin-bottom:
                25px;
        }


        label {

            display:
                block;

            font-weight:
                bold;

            margin-bottom:
                8px;
        }


        input,
        select {

            width:
                100%;

            padding:
                12px;

            border:
                1px solid #d1d5db;

            border-radius:
                7px;

            font-size:
                16px;

            margin-bottom:
                18px;
        }


        button {

            background:
                #111827;

            color:
                white;

            border:
                none;

            padding:
                13px 25px;

            border-radius:
                7px;

            font-size:
                16px;

            cursor:
                pointer;
        }


        button:hover {

            opacity:
                0.85;
        }


        button:disabled {

            opacity:
                0.5;

            cursor:
                not-allowed;
        }


        .status {

            display:
                none;

            padding:
                20px;

            border-radius:
                8px;

            margin-top:
                20px;
        }


        .status.running {

            display:
                block;

            background:
                #dbeafe;

            color:
                #1e40af;
        }


        .status.complete {

            display:
                block;

            background:
                #dcfce7;

            color:
                #166534;
        }


        .status.failed {

            display:
                block;

            background:
                #fee2e2;

            color:
                #991b1b;
        }


        .spinner {

            display:
                inline-block;

            width:
                18px;

            height:
                18px;

            border:
                3px solid
                rgba(
                    0,
                    0,
                    0,
                    0.15
                );

            border-top-color:
                #111827;

            border-radius:
                50%;

            animation:
                spin 1s linear infinite;

            margin-right:
                8px;

            vertical-align:
                middle;
        }


        @keyframes spin {

            to {
                transform:
                    rotate(360deg);
            }

        }


        .grid {

            display:
                grid;

            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(
                        180px,
                        1fr
                    )
                );

            gap:
                15px;
        }


        .metric {

            background:
                #f9fafb;

            padding:
                20px;

            border-radius:
                8px;
        }


        .metric h3 {

            margin:
                0 0 10px 0;

            color:
                #6b7280;

            font-size:
                14px;
        }


        .metric strong {

            font-size:
                28px;
        }


        table {

            width:
                100%;

            border-collapse:
                collapse;
        }


        th,
        td {

            padding:
                12px;

            text-align:
                left;

            border-bottom:
                1px solid #e5e7eb;
        }


        th {

            background:
                #f9fafb;
        }


        .footer {

            text-align:
                center;

            color:
                #6b7280;

            margin-top:
                30px;
        }


        .hidden {

            display:
                none;
        }


        .error {

            background:
                #fee2e2;

            color:
                #991b1b;

            padding:
                15px;

            border-radius:
                8px;

            margin-bottom:
                20px;
        }


        .success {

            background:
                #dcfce7;

            color:
                #166534;

            padding:
                15px;

            border-radius:
                8px;

            margin-bottom:
                20px;
        }


        .section-title {

            margin-top:
                0;

            border-bottom:
                1px solid #e5e7eb;

            padding-bottom:
                12px;
        }

    </style>

</head>


<body>


<div class="container">


    <!-- ====================================================
         HEADER
    ===================================================== -->

    <div class="header">

        <h1>
            Port Scanner Dashboard
        </h1>

        <p>
            Network reconnaissance and
            security assessment tool
        </p>

    </div>


    <!-- ====================================================
         SCAN FORM
    ===================================================== -->

    <div class="card">

        <h2 class="section-title">
            Start Scan
        </h2>


        <div id="form-error"
             class="error hidden">
        </div>


        <label>
            Target
        </label>

        <input
            type="text"
            id="target"
            placeholder="127.0.0.1"
        >


        <label>
            TCP Scan Profile
        </label>

        <select id="profile">

            <option value="quick">
                Quick
            </option>

            <option value="common">
                Common
            </option>

            <option value="full">
                Full
            </option>

        </select>


        <label>
            UDP Scan
        </label>

        <select id="udp">

            <option value="no">
                No
            </option>

            <option value="yes">
                Yes
            </option>

        </select>


        <button
            id="start-button"
            onclick="startScan()"
        >

            START SCAN

        </button>


        <!-- =================================================
             STATUS
        ================================================== -->

        <div
            id="status"
            class="status"
        >

            <span id="status-content"></span>

        </div>

    </div>


    <!-- ====================================================
         RESULTS
    ===================================================== -->

    <div
        id="results"
        class="hidden"
    >

        <div class="card">

            <h2 class="section-title">
                Scan Summary
            </h2>


            <div class="grid">


                <div class="metric">

                    <h3>
                        Target
                    </h3>

                    <strong id="result-target">
                        -
                    </strong>

                </div>


                <div class="metric">

                    <h3>
                        Ports Scanned
                    </h3>

                    <strong id="ports-scanned">
                        -
                    </strong>

                </div>


                <div class="metric">

                    <h3>
                        Open Ports
                    </h3>

                    <strong id="open-ports">
                        -
                    </strong>

                </div>


                <div class="metric">

                    <h3>
                        Vulnerabilities
                    </h3>

                    <strong id="vulnerabilities">
                        -
                    </strong>

                </div>


                <div class="metric">

                    <h3>
                        Scan Time
                    </h3>

                    <strong id="scan-time">
                        -
                    </strong>

                </div>


            </div>

        </div>


        <!-- =================================================
             TCP RESULTS
        ================================================== -->

        <div class="card">

            <h2 class="section-title">
                Open TCP Ports
            </h2>

            <div id="tcp-results">
            </div>

        </div>


        <!-- =================================================
             OS
        ================================================== -->

        <div class="card">

            <h2 class="section-title">
                OS Fingerprint
            </h2>

            <p>

                <strong>
                    Estimated OS:
                </strong>

                <span id="os">
                    -
                </span>

            </p>


            <p>

                <strong>
                    Confidence:
                </strong>

                <span id="os-confidence">
                    -
                </span>

            </p>

        </div>


        <!-- =================================================
             VULNERABILITIES
        ================================================== -->

        <div class="card">

            <h2 class="section-title">
                Vulnerabilities
            </h2>

            <div id="vulnerability-results">
            </div>

        </div>

    </div>


    <div class="footer">

        Python Port Scanner

    </div>


</div>


<script>


// ==========================================================
// START SCAN
// ==========================================================

async function startScan() {


    const target =
        document.getElementById(
            "target"
        ).value.trim();


    const profile =
        document.getElementById(
            "profile"
        ).value;


    const udp =
        document.getElementById(
            "udp"
        ).value;


    const button =
        document.getElementById(
            "start-button"
        );


    const status =
        document.getElementById(
            "status"
        );


    const statusContent =
        document.getElementById(
            "status-content"
        );


    const formError =
        document.getElementById(
            "form-error"
        );


    // ------------------------------------------------------
    // Validation
    // ------------------------------------------------------

    if (!target) {

        formError.textContent =
            "Please enter a target.";

        formError.classList.remove(
            "hidden"
        );

        return;
    }


    formError.classList.add(
        "hidden"
    );


    // ------------------------------------------------------
    // Reset
    // ------------------------------------------------------

    document
        .getElementById("results")
        .classList.add("hidden");


    button.disabled = true;


    status.className =
        "status running";


    statusContent.innerHTML =
        '<span class="spinner"></span>' +
        'Starting scan...';


    // ------------------------------------------------------
    // Start background scan
    // ------------------------------------------------------

    try {

        const response =
            await fetch(
                "/api/scan",
                {

                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({

                        target:
                            target,

                        profile:
                            profile,

                        udp:
                            udp

                    })

                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Could not start scan."
            );
        }


        const scanId =
            data.scan_id;


        statusContent.innerHTML =
            '<span class="spinner"></span>' +
            'Scan running...';


        // --------------------------------------------------
        // Monitor scan
        // --------------------------------------------------

        monitorScan(
            scanId
        );


    }

    catch (error) {

        button.disabled = false;


        status.className =
            "status failed";


        statusContent.textContent =
            error.message;
    }

}


// ==========================================================
// MONITOR SCAN
// ==========================================================

async function monitorScan(
    scanId
) {


    const button =
        document.getElementById(
            "start-button"
        );


    const status =
        document.getElementById(
            "status"
        );


    const statusContent =
        document.getElementById(
            "status-content"
        );


    try {


        const response =
            await fetch(
                "/api/scan/" +
                scanId
            );


        const data =
            await response.json();


        // --------------------------------------------------
        // RUNNING
        // --------------------------------------------------

        if (
            data.status ===
            "running"
        ) {

            status.className =
                "status running";


            statusContent.innerHTML =
                '<span class="spinner"></span>' +
                'Scan running...';


            setTimeout(
                function() {

                    monitorScan(
                        scanId
                    );

                },
                1000
            );


            return;
        }


        // --------------------------------------------------
        // COMPLETE
        // --------------------------------------------------

        if (
            data.status ===
            "complete"
        ) {

            status.className =
                "status complete";


            statusContent.textContent =
                "Scan completed.";


            button.disabled = false;


            displayResults(
                data.results
            );


            return;
        }


        // --------------------------------------------------
        // FAILED
        // --------------------------------------------------

        if (
            data.status ===
            "failed"
        ) {

            status.className =
                "status failed";


            statusContent.textContent =
                data.error ||
                "Scan failed.";


            button.disabled = false;


            return;
        }


    }

    catch (error) {

        status.className =
            "status failed";


        statusContent.textContent =
            "Could not retrieve scan status: " +
            error.message;


        button.disabled = false;
    }

}


// ==========================================================
// DISPLAY RESULTS
// ==========================================================

function displayResults(
    results
) {


    document
        .getElementById(
            "results"
        )
        .classList.remove(
            "hidden"
        );


    // ------------------------------------------------------
    // Summary
    // ------------------------------------------------------

    document
        .getElementById(
            "result-target"
        )
        .textContent =
            results.target;


    document
        .getElementById(
            "ports-scanned"
        )
        .textContent =
            results.ports_scanned;


    document
        .getElementById(
            "open-ports"
        )
        .textContent =
            results.open_ports_count;


    document
        .getElementById(
            "vulnerabilities"
        )
        .textContent =
            results.vulnerabilities.length;


    document
        .getElementById(
            "scan-time"
        )
        .textContent =
            results.scan_duration_seconds +
            "s";


    // ------------------------------------------------------
    // TCP
    // ------------------------------------------------------

    const tcpContainer =
        document.getElementById(
            "tcp-results"
        );


    if (
        !results.open_ports ||
        results.open_ports.length === 0
    ) {

        tcpContainer.innerHTML =
            "<p>No open TCP ports detected.</p>";

    }

    else {


        let html = `

            <table>

                <thead>

                    <tr>

                        <th>
                            Port
                        </th>

                        <th>
                            Service
                        </th>

                        <th>
                            Version
                        </th>

                        <th>
                            Confidence
                        </th>

                    </tr>

                </thead>

                <tbody>
        `;


        results.open_ports.forEach(
            function(port) {

                html += `

                    <tr>

                        <td>
                            ${escapeHtml(
                                port.port
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                port.service
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                port.version ||
                                "Unknown"
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                port.confidence ||
                                "Unknown"
                            )}
                        </td>

                    </tr>

                `;

            }
        );


        html += `

                </tbody>

            </table>

        `;


        tcpContainer.innerHTML =
            html;
    }


    // ------------------------------------------------------
    // OS
    // ------------------------------------------------------

    const os =
        results.os_fingerprint || {};


    document
        .getElementById(
            "os"
        )
        .textContent =
            os.estimated_os ||
            "Unknown";


    document
        .getElementById(
            "os-confidence"
        )
        .textContent =
            os.confidence ||
            "Unknown";


    // ------------------------------------------------------
    // Vulnerabilities
    // ------------------------------------------------------

    const vulnerabilityContainer =
        document.getElementById(
            "vulnerability-results"
        );


    if (
        !results.vulnerabilities ||
        results.vulnerabilities.length === 0
    ) {

        vulnerabilityContainer.innerHTML =
            "<p>No matching vulnerabilities found.</p>";

    }

    else {


        let html = `

            <table>

                <thead>

                    <tr>

                        <th>
                            CVE
                        </th>

                        <th>
                            Service
                        </th>

                        <th>
                            Version
                        </th>

                        <th>
                            Severity
                        </th>

                        <th>
                            CVSS
                        </th>

                        <th>
                            Match
                        </th>

                    </tr>

                </thead>

                <tbody>

        `;


        results.vulnerabilities.forEach(
            function(vulnerability) {

                html += `

                    <tr>

                        <td>
                            ${escapeHtml(
                                vulnerability.cve
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                vulnerability.service
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                vulnerability.version
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                vulnerability.severity ||
                                "Unknown"
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                vulnerability.cvss ||
                                "Unknown"
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                vulnerability.match_status ||
                                "Unknown"
                            )}
                        </td>

                    </tr>

                `;

            }
        );


        html += `

                </tbody>

            </table>

        `;


        vulnerabilityContainer.innerHTML =
            html;
    }

}


// ==========================================================
// HTML ESCAPING
// ==========================================================

function escapeHtml(
    value
) {


    if (
        value === null ||
        value === undefined
    ) {

        return "";
    }


    return String(value)

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );
}


</script>


</body>

</html>
"""


# ============================================================
# BACKGROUND SCAN FUNCTION
# ============================================================

def perform_scan(
    scan_id,
    target,
    profile,
    udp
):

    output_file = (
        f"dashboard_{scan_id}.json"
    )


    command = [

        sys.executable,

        "scanner.py",

        target
    ]


    # --------------------------------------------------------
    # TCP profile
    # --------------------------------------------------------

    if profile == "quick":

        command.append(
            "--quick"
        )

    elif profile == "common":

        command.append(
            "--common"
        )

    elif profile == "full":

        command.append(
            "--full"
        )


    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    if udp == "yes":

        command.append(
            "--udp"
        )


    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    command.extend([

        "--output",

        output_file

    ])


    try:


        with scan_lock:

            scans[scan_id][
                "status"
            ] = "running"


        process = subprocess.run(

            command,

            capture_output=True,

            text=True,

            timeout=600
        )


        # ----------------------------------------------------
        # Process failed
        # ----------------------------------------------------

        if process.returncode != 0:

            error_message = (

                process.stderr

                or

                process.stdout

                or

                "Scanner failed."

            )


            with scan_lock:

                scans[scan_id][
                    "status"
                ] = "failed"

                scans[scan_id][
                    "error"
                ] = error_message


            return


        # ----------------------------------------------------
        # JSON missing
        # ----------------------------------------------------

        if not os.path.exists(
            output_file
        ):

            with scan_lock:

                scans[scan_id][
                    "status"
                ] = "failed"

                scans[scan_id][
                    "error"
                ] = (
                    "Scanner completed "
                    "but no JSON report "
                    "was created."
                )


            return


        # ----------------------------------------------------
        # Read JSON
        # ----------------------------------------------------

        with open(
            output_file,
            "r",
            encoding="utf-8"
        ) as file:

            results = json.load(
                file
            )


        # ----------------------------------------------------
        # Save result
        # ----------------------------------------------------

        with scan_lock:

            scans[scan_id][
                "status"
            ] = "complete"

            scans[scan_id][
                "results"
            ] = results


    except subprocess.TimeoutExpired:

        with scan_lock:

            scans[scan_id][
                "status"
            ] = "failed"

            scans[scan_id][
                "error"
            ] = (
                "Scan exceeded the "
                "10 minute timeout."
            )


    except Exception as error:

        with scan_lock:

            scans[scan_id][
                "status"
            ] = "failed"

            scans[scan_id][
                "error"
            ] = str(error)


    finally:

        # ----------------------------------------------------
        # Clean temporary JSON
        # ----------------------------------------------------

        try:

            if os.path.exists(
                output_file
            ):

                os.remove(
                    output_file
                )

        except OSError:

            pass


# ============================================================
# START SCAN API
# ============================================================

@app.route(
    "/api/scan",
    methods=["POST"]
)

def start_scan():

    data = request.get_json(
        silent=True
    )


    if not data:

        return jsonify({

            "error":
                "Invalid request."

        }), 400


    target = (
        data.get(
            "target",
            ""
        )
        .strip()
    )


    profile = (
        data.get(
            "profile",
            "quick"
        )
    )


    udp = (
        data.get(
            "udp",
            "no"
        )
    )


    # --------------------------------------------------------
    # Validate target
    # --------------------------------------------------------

    if not target:

        return jsonify({

            "error":
                "Target is required."

        }), 400


    # --------------------------------------------------------
    # Validate profile
    # --------------------------------------------------------

    if profile not in [
        "quick",
        "common",
        "full"
    ]:

        return jsonify({

            "error":
                "Invalid scan profile."

        }), 400


    # --------------------------------------------------------
    # Generate scan ID
    # --------------------------------------------------------

    scan_id = str(
        uuid.uuid4()
    )


    with scan_lock:

        scans[scan_id] = {

            "status":
                "starting",

            "target":
                target,

            "profile":
                profile,

            "udp":
                udp,

            "created":
                time.time(),

            "results":
                None,

            "error":
                None
        }


    # --------------------------------------------------------
    # Start background thread
    # --------------------------------------------------------

    thread = threading.Thread(

        target=perform_scan,

        args=(

            scan_id,

            target,

            profile,

            udp

        ),

        daemon=True
    )


    thread.start()


    return jsonify({

        "scan_id":
            scan_id,

        "status":
            "starting"

    })


# ============================================================
# SCAN STATUS API
# ============================================================

@app.route(
    "/api/scan/<scan_id>",
    methods=["GET"]
)

def scan_status(
    scan_id
):


    with scan_lock:

        scan = scans.get(
            scan_id
        )


        if not scan:

            return jsonify({

                "error":
                    "Scan not found."

            }), 404


        response = {

            "status":
                scan["status"],

            "target":
                scan["target"],

            "profile":
                scan["profile"],

            "udp":
                scan["udp"]
        }


        if scan["status"] == "complete":

            response[
                "results"
            ] = scan["results"]


        if scan["status"] == "failed":

            response[
                "error"
            ] = scan["error"]


    return jsonify(
        response
    )


# ============================================================
# MAIN DASHBOARD
# ============================================================

@app.route(
    "/",
    methods=["GET"]
)

def dashboard():

    return render_template_string(
        HTML
    )


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print()

    print(
        "=" * 60
    )

    print(
        "        PYTHON PORT SCANNER DASHBOARD"
    )

    print(
        "=" * 60
    )

    print()

    print(
        "Dashboard:"
    )

    print(
        "http://127.0.0.1:5000"
    )

    print()

    print(
        "Press CTRL+C to stop."
    )

    print()

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=False
    )