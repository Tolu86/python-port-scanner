from flask import Flask, render_template, jsonify, request
from flask import Response
import json
import os
import subprocess
import sys
import threading
import time


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

SCANNER_FILE = os.path.join(
    BASE_DIR,
    "scanner.py"
)

PROGRESS_FILE = os.path.join(
    BASE_DIR,
    "progress.json"
)

RESULTS_FILE = os.path.join(
    BASE_DIR,
    "scan_results.json"
)


# ============================================================
# GLOBAL SCANNER PROCESS
# ============================================================

scan_process = None


# ============================================================
# DEFAULT PROGRESS
# ============================================================

DEFAULT_PROGRESS = {
    "stage": "Idle",
    "current": 0,
    "total": 0,
    "percentage": 0,
    "open_ports": 0,
    "message": "Scanner is ready.",
    "timestamp": time.time()
}


# ============================================================
# READ PROGRESS
# ============================================================

def read_progress():

    if not os.path.exists(PROGRESS_FILE):
        return DEFAULT_PROGRESS.copy()

    try:

        with open(
            PROGRESS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (
        json.JSONDecodeError,
        OSError
    ):

        return DEFAULT_PROGRESS.copy()


# ============================================================
# READ RESULTS
# ============================================================

def read_results():

    if not os.path.exists(RESULTS_FILE):
        return {}

    try:

        with open(
            RESULTS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (
        json.JSONDecodeError,
        OSError
    ):

        return {}


# ============================================================
# WRITE PROGRESS
# ============================================================

def write_progress(data):

    try:

        with open(
            PROGRESS_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                data,
                file,
                indent=4
            )

    except OSError as error:

        print(
            f"Could not write progress: {error}"
        )


# ============================================================
# RUN SCANNER
# ============================================================

def run_scanner(
    target,
    options
):

    global scan_process

    command = [
        sys.executable,
        SCANNER_FILE,
        target
    ]

    # --------------------------------------------------------
    # TCP PROFILE
    # --------------------------------------------------------

    if options.get("quick"):

        command.append(
            "--quick"
        )

    elif options.get("common"):

        command.append(
            "--common"
        )

    elif options.get("full"):

        command.append(
            "--full"
        )

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    if options.get("udp"):

        command.append(
            "--udp"
        )

    # --------------------------------------------------------
    # JSON OUTPUT
    # --------------------------------------------------------

    command.extend([
        "--output",
        RESULTS_FILE
    ])

    print()
    print("=" * 70)
    print("STARTING SCANNER")
    print("=" * 70)

    print(
        "Target:",
        target
    )

    print(
        "Options:",
        options
    )

    print(
        "Command:"
    )

    print(
        " ".join(command)
    )

    print("=" * 70)

    try:

        write_progress({

            "stage": "Scanning",

            "current": 0,

            "total": 0,

            "percentage": 0,

            "open_ports": 0,

            "message":
                f"Scanning {target}...",

            "timestamp":
                time.time()
        })

        scan_process = subprocess.Popen(
            command,
            cwd=BASE_DIR
        )

        return_code = scan_process.wait()

        print()
        print(
            f"Scanner finished with code: "
            f"{return_code}"
        )

        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        if return_code == 0:

            write_progress({

                "stage": "Complete",

                "current": 100,

                "total": 100,

                "percentage": 100,

                "open_ports":
                    read_results().get(
                        "open_ports_count",
                        0
                    ),

                "message":
                    "Scan completed successfully.",

                "timestamp":
                    time.time()
            })

        # ----------------------------------------------------
        # FAILURE
        # ----------------------------------------------------

        else:

            write_progress({

                "stage": "Failed",

                "current": 0,

                "total": 0,

                "percentage": 0,

                "open_ports": 0,

                "message":
                    f"Scanner exited with code {return_code}.",

                "timestamp":
                    time.time()
            })

    except Exception as error:

        print()
        print(
            f"Scanner execution error: {error}"
        )

        write_progress({

            "stage": "Failed",

            "current": 0,

            "total": 0,

            "percentage": 0,

            "open_ports": 0,

            "message":
                str(error),

            "timestamp":
                time.time()
        })

    finally:

        scan_process = None


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# ============================================================
# START SCAN
# ============================================================

@app.route(
    "/scan",
    methods=["POST"]
)
def start_scan():

    global scan_process

    print()
    print("=" * 70)
    print("SCAN REQUEST RECEIVED")
    print("=" * 70)

    # --------------------------------------------------------
    # CHECK CONTENT TYPE
    # --------------------------------------------------------

    print(
        "Content-Type:",
        request.content_type
    )

    # --------------------------------------------------------
    # READ RAW REQUEST
    # --------------------------------------------------------

    print(
        "Raw request body:",
        request.get_data(
            as_text=True
        )
    )

    # --------------------------------------------------------
    # READ JSON
    # --------------------------------------------------------

    data = request.get_json(
        silent=True
    )

    print(
        "Parsed JSON:",
        data
    )

    # --------------------------------------------------------
    # VALIDATE JSON
    # --------------------------------------------------------

    if data is None:

        print(
            "ERROR: Request does not contain valid JSON."
        )

        return jsonify({

            "success": False,

            "message":
                "Invalid JSON request."

        }), 400

    # --------------------------------------------------------
    # TARGET
    # --------------------------------------------------------

    target = str(
        data.get(
            "target",
            ""
        )
    ).strip()

    print(
        "Received target:",
        repr(target)
    )

    # --------------------------------------------------------
    # TARGET VALIDATION
    # --------------------------------------------------------

    if not target:

        print(
            "ERROR: Target is empty."
        )

        return jsonify({

            "success": False,

            "message":
                "Target is required."

        }), 400

    # --------------------------------------------------------
    # PREVENT MULTIPLE SCANS
    # --------------------------------------------------------

    if (

        scan_process is not None

        and

        scan_process.poll() is None

    ):

        return jsonify({

            "success": False,

            "message":
                "A scan is already running."

        }), 409

    # --------------------------------------------------------
    # OPTIONS
    # --------------------------------------------------------

    options = {

        "quick":
            bool(
                data.get(
                    "quick",
                    False
                )
            ),

        "common":
            bool(
                data.get(
                    "common",
                    False
                )
            ),

        "full":
            bool(
                data.get(
                    "full",
                    False
                )
            ),

        "udp":
            bool(
                data.get(
                    "udp",
                    False
                )
            )
    }

    # --------------------------------------------------------
    # PROFILE VALIDATION
    # --------------------------------------------------------

    profile_count = sum([

        options["quick"],

        options["common"],

        options["full"]

    ])

    if profile_count == 0:

        options["quick"] = True

    elif profile_count > 1:

        return jsonify({

            "success": False,

            "message":
                "Choose only one TCP profile."

        }), 400

    # --------------------------------------------------------
    # REMOVE OLD RESULTS
    # --------------------------------------------------------

    try:

        if os.path.exists(
            RESULTS_FILE
        ):

            os.remove(
                RESULTS_FILE
            )

    except OSError as error:

        print(
            f"Could not remove old results: "
            f"{error}"
        )

    # --------------------------------------------------------
    # RESET PROGRESS
    # --------------------------------------------------------

    write_progress({

        "stage": "Starting",

        "current": 0,

        "total": 0,

        "percentage": 0,

        "open_ports": 0,

        "message":
            f"Starting scan of {target}...",

        "timestamp":
            time.time()
    })

    # --------------------------------------------------------
    # START BACKGROUND THREAD
    # --------------------------------------------------------

    thread = threading.Thread(

        target=run_scanner,

        args=(
            target,
            options
        ),

        daemon=True

    )

    thread.start()

    print(
        "Scanner thread started."
    )

    print("=" * 70)

    return jsonify({

        "success": True,

        "message":
            "Scan started.",

        "target":
            target,

        "options":
            options

    })


# ============================================================
# PROGRESS
# ============================================================

@app.route(
    "/progress"
)
def progress():

    data = read_progress()

    running = (

        scan_process is not None

        and

        scan_process.poll() is None

    )

    data["running"] = running

    return jsonify(
        data
    )


# ============================================================
# SERVER-SENT EVENTS (REAL-TIME STREAM)
# ============================================================


def event_stream(poll_interval=0.5):

    import json
    import time

    try:

        while True:

            payload = {
                "progress": read_progress(),
                "results": read_results(),
                "timestamp": time.time()
            }

            data = json.dumps(payload)

            yield f"data: {data}\n\n"

            time.sleep(poll_interval)

    except GeneratorExit:

        # client disconnected
        return


@app.route('/events')
def events():

    # Stream progress + results as Server-Sent Events
    return Response(event_stream(), mimetype='text/event-stream')


# ============================================================
# RESULTS
# ============================================================

@app.route(
    "/results"
)
def results():

    return jsonify(
        read_results()
    )


# ============================================================
# STATUS
# ============================================================

@app.route(
    "/api/status"
)
def status():

    running = (

        scan_process is not None

        and

        scan_process.poll() is None

    )

    return jsonify({

        "running":
            running,

        "progress":
            read_progress(),

        "results":
            read_results()

    })


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print("                    PORT SCANNER")
    print("                       DASHBOARD")
    print("=" * 70)
    print()

    print(
        "Dashboard:"
    )

    print(
        "http://127.0.0.1:5000"
    )

    print()

    print(
        "Scanner:"
    )

    print(
        SCANNER_FILE
    )

    print()

    print(
        "Results:"
    )

    print(
        RESULTS_FILE
    )

    print()

    print("=" * 70)

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=False

    )