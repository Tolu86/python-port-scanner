// ============================================================
// PORT SCANNER DASHBOARD
// FRONTEND CONTROLLER
// ============================================================

let scanRunning = false;
let progressTimer = null;
let statusTimer = null;


// ============================================================
// DOM HELPERS
// ============================================================

function get(id) {
    return document.getElementById(id);
}


function setText(id, value) {
    const element = get(id);

    if (element) {
        element.textContent = value ?? "";
    }
}


// ============================================================
// INITIALIZATION
// ============================================================

document.addEventListener("DOMContentLoaded", () => {

    console.log("Port Scanner dashboard loaded.");

    setupScanForm();

    loadInitialData();

});


// ============================================================
// FORM SETUP
// ============================================================

function setupScanForm() {

    const form = get("scanForm");

    if (!form) {
        console.warn("scanForm was not found.");
        return;
    }

    form.addEventListener("submit", async (event) => {

        event.preventDefault();

        await startScan();

    });

}


// ============================================================
// GET SCAN OPTIONS
// ============================================================

function getScanOptions() {

    const targetElement = get("target");

    const target = targetElement
        ? targetElement.value.trim()
        : "";

    const profileElement =
        document.querySelector(
            'input[name="profile"]:checked'
        );

    const profile =
        profileElement
            ? profileElement.value
            : "quick";

    const udpElement = get("udp");

    const udp =
        udpElement
            ? udpElement.checked
            : false;

    return {
        target,
        profile,
        udp
    };

}


// ============================================================
// START SCAN
// ============================================================

async function startScan() {

    if (scanRunning) {
        return;
    }

    const options = getScanOptions();

    if (!options.target) {

        showMessage(
            "Enter an IP address or hostname.",
            "error"
        );

        return;
    }


    scanRunning = true;

    setScanningState(true);

    resetDashboard();

    showMessage(
        "Starting scan...",
        "info"
    );


    const payload = {

        target: options.target,

        quick:
            options.profile === "quick",

        common:
            options.profile === "common",

        full:
            options.profile === "full",

        udp:
            options.udp

    };


    console.log(
        "Sending scan request:",
        payload
    );


    try {

        const response = await fetch(
            "/scan",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify(payload)
            }
        );


        const data = await response.json();


        console.log(
            "Scanner response:",
            data
        );


        if (!response.ok || !data.success) {

            throw new Error(
                data.message ||
                "Could not start scan."
            );

        }


        showMessage(
            "Scan started successfully.",
            "success"
        );


        startProgressPolling();

        startStatusPolling();

    }

    catch (error) {

        console.error(
            "Scan start error:",
            error
        );


        showMessage(
            error.message ||
            "Could not start scan.",
            "error"
        );


        scanRunning = false;

        setScanningState(false);

    }

}


// ============================================================
// PROGRESS POLLING
// ============================================================

function startProgressPolling() {

    stopProgressPolling();


    updateProgress();


    progressTimer = setInterval(
        updateProgress,
        700
    );

}


function stopProgressPolling() {

    if (progressTimer) {

        clearInterval(
            progressTimer
        );

        progressTimer = null;

    }

}


async function updateProgress() {

    try {

        const response = await fetch(
            "/progress",
            {
                cache: "no-store"
            }
        );


        if (!response.ok) {

            throw new Error(
                `Progress request failed: ${response.status}`
            );

        }


        const data =
            await response.json();


        console.log(
            "Progress:",
            data
        );


        renderProgress(data);


    }

    catch (error) {

        console.error(
            "Progress error:",
            error
        );

    }

}


// ============================================================
// STATUS POLLING
// ============================================================

function startStatusPolling() {

    stopStatusPolling();


    statusTimer = setInterval(
        updateStatus,
        1000
    );

}


function stopStatusPolling() {

    if (statusTimer) {

        clearInterval(
            statusTimer
        );

        statusTimer = null;

    }

}


async function updateStatus() {

    try {

        const response = await fetch(
            "/api/status",
            {
                cache: "no-store"
            }
        );


        if (!response.ok) {
            return;
        }


        const data =
            await response.json();


        if (!data.running) {

            const progress =
                data.progress || {};


            if (
                progress.stage === "Complete" ||
                progress.stage === "Completed"
            ) {

                await finishScan();

            }

        }

    }

    catch (error) {

        console.error(
            "Status error:",
            error
        );

    }

}


// ============================================================
// RENDER PROGRESS
// ============================================================

function renderProgress(data) {

    if (!data) {
        return;
    }


    const percentage =
        Number(
            data.percentage || 0
        );


    const safePercentage =
        Math.max(
            0,
            Math.min(
                100,
                percentage
            )
        );


    const progressBar =
        get("progressFill");


    if (progressBar) {

        progressBar.style.width =
            `${safePercentage}%`;

    }


    setText(
        "progressPercentage",
        `${safePercentage.toFixed(0)}%`
    );


    setText(
        "progressStage",
        data.stage || "Scanning"
    );


    setText(
        "progressMessage",
        data.message ||
        "Scanning..."
    );


    setText(
        "progressCurrent",
        data.current ?? 0
    );


    setText(
        "progressTotal",
        data.total ?? 0
    );


    setText(
        "progressOpenPorts",
        data.open_ports ?? 0
    );

}


// ============================================================
// FINISH SCAN
// ============================================================

async function finishScan() {

    stopProgressPolling();

    stopStatusPolling();


    await updateProgress();

    await loadResults();


    scanRunning = false;

    setScanningState(false);


    showMessage(
        "Scan completed.",
        "success"
    );

}


// ============================================================
// LOAD RESULTS
// ============================================================

async function loadResults() {

    try {

        const response = await fetch(
            "/results",
            {
                cache: "no-store"
            }
        );


        if (!response.ok) {

            throw new Error(
                `Results request failed: ${response.status}`
            );

        }


        const results =
            await response.json();


        console.log(
            "Results:",
            results
        );


        renderResults(results);

    }

    catch (error) {

        console.error(
            "Results error:",
            error
        );

    }

}


// ============================================================
// INITIAL DATA
// ============================================================

async function loadInitialData() {

    try {

        await updateProgress();

        await loadResults();

    }

    catch (error) {

        console.error(
            "Initial data error:",
            error
        );

    }

}


// ============================================================
// RENDER RESULTS
// ============================================================

function renderResults(results) {

    if (!results || !Object.keys(results).length) {
        return;
    }


    // --------------------------------------------------------
    // STATISTICS
    // --------------------------------------------------------

    setText(
        "statTarget",
        results.target || "—"
    );


    setText(
        "statScanned",
        results.ports_scanned ?? 0
    );


    setText(
        "statOpen",
        results.open_ports_count ?? 0
    );


    setText(
        "statRisk",
        results.security_analysis?.overall_risk ||
        "UNKNOWN"
    );


    setText(
        "osEstimate",
        results.os_fingerprint?.estimated_os ||
        "Unknown"
    );


    setText(
        "osConfidence",
        results.os_fingerprint?.confidence ||
        "Unknown"
    );


    setText(
        "scanDuration",
        results.scan_duration_seconds !== undefined
            ? `${results.scan_duration_seconds}s`
            : "—"
    );


    setText(
        "vulnerabilityCount",
        Array.isArray(results.vulnerabilities)
            ? results.vulnerabilities.length
            : 0
    );


    renderOpenPorts(
        results.open_ports || []
    );


    renderSecurityFindings(
        results.security_analysis?.findings || []
    );


    renderVulnerabilities(
        results.vulnerabilities || []
    );

}


// ============================================================
// OPEN PORT TABLE
// ============================================================

function renderOpenPorts(ports) {

    const tableBody =
        get("openPortsBody");


    if (!tableBody) {
        return;
    }


    tableBody.innerHTML = "";


    if (!ports.length) {

        tableBody.innerHTML = `
            <tr>
                <td colspan="6" class="empty-state">
                    No open TCP ports detected.
                </td>
            </tr>
        `;

        return;
    }


    ports.forEach(port => {

        const row =
            document.createElement("tr");


        const confidence =
            String(
                port.confidence || "LOW"
            ).toLowerCase();


        row.innerHTML = `

            <td>
                <span class="port-number">
                    ${escapeHtml(port.port)}
                </span>
            </td>

            <td>
                <span class="service-name">
                    ${escapeHtml(
                        port.service || "Unknown"
                    )}
                </span>
            </td>

            <td>
                ${escapeHtml(
                    port.version || "Unknown"
                )}
            </td>

            <td>
                <span class="confidence ${confidence}">
                    ${escapeHtml(
                        port.confidence || "LOW"
                    )}
                </span>
            </td>

            <td>
                ${escapeHtml(
                    port.detection_method ||
                    "Unknown"
                )}
            </td>

            <td>
                ${escapeHtml(
                    port.banner || "—"
                )}
            </td>

        `;


        tableBody.appendChild(row);

    });

}


// ============================================================
// SECURITY FINDINGS
// ============================================================

function renderSecurityFindings(findings) {

    const container =
        get("securityFindings");


    if (!container) {
        return;
    }


    container.innerHTML = "";


    if (!findings.length) {

        container.innerHTML = `
            <div class="empty-state">
                No security findings detected.
            </div>
        `;

        return;
    }


    findings.forEach(finding => {

        const severity =
            String(
                finding.severity || "INFO"
            ).toLowerCase();


        const element =
            document.createElement("div");


        element.className =
            "finding";


        element.innerHTML = `

            <div class="finding-header">

                <div class="finding-title">
                    ${escapeHtml(
                        finding.title ||
                        "Security Finding"
                    )}
                </div>

                <span class="severity ${severity}">
                    ${escapeHtml(
                        finding.severity ||
                        "INFO"
                    )}
                </span>

            </div>

            <div class="finding-description">
                ${escapeHtml(
                    finding.description ||
                    "No description available."
                )}
            </div>

            <div class="finding-recommendation">
                <strong>Recommendation:</strong>
                ${escapeHtml(
                    finding.recommendation ||
                    "No recommendation available."
                )}
            </div>

        `;


        container.appendChild(element);

    });

}


// ============================================================
// VULNERABILITIES
// ============================================================

function renderVulnerabilities(vulnerabilities) {

    const container =
        get("vulnerabilityList");


    if (!container) {
        return;
    }


    container.innerHTML = "";


    if (!vulnerabilities.length) {

        container.innerHTML = `
            <div class="empty-state">
                No known vulnerabilities detected.
            </div>
        `;

        return;
    }


    vulnerabilities.forEach(vulnerability => {

        const element =
            document.createElement("div");


        element.className =
            "finding";


        const severity =
            String(
                vulnerability.severity ||
                "INFO"
            ).toLowerCase();


        element.innerHTML = `

            <div class="finding-header">

                <div class="finding-title">
                    ${escapeHtml(
                        vulnerability.title ||
                        vulnerability.name ||
                        "Vulnerability"
                    )}
                </div>

                <span class="severity ${severity}">
                    ${escapeHtml(
                        vulnerability.severity ||
                        "INFO"
                    )}
                </span>

            </div>

            <div class="finding-description">
                ${escapeHtml(
                    vulnerability.description ||
                    vulnerability.message ||
                    "No description available."
                )}
            </div>

        `;


        container.appendChild(element);

    });

}


// ============================================================
// RESET DASHBOARD
// ============================================================

function resetDashboard() {

    setText(
        "statTarget",
        "Scanning..."
    );


    setText(
        "statScanned",
        "0"
    );


    setText(
        "statOpen",
        "0"
    );


    setText(
        "statRisk",
        "—"
    );


    setText(
        "osEstimate",
        "Scanning..."
    );


    setText(
        "osConfidence",
        "—"
    );


    setText(
        "scanDuration",
        "—"
    );


    setText(
        "vulnerabilityCount",
        "0"
    );

}


// ============================================================
// BUTTON / SCANNING STATE
// ============================================================

function setScanningState(running) {

    const button =
        get("scanButton");


    const buttonText =
        get("scanButtonText");


    const loader =
        get("scanLoader");


    if (button) {

        button.disabled =
            running;

    }


    if (buttonText) {

        buttonText.textContent =
            running
                ? "Scanning..."
                : "Start Scan";

    }


    if (loader) {

        loader.classList.toggle(
            "hidden",
            !running
        );

    }

}


// ============================================================
// MESSAGE SYSTEM
// ============================================================

function showMessage(
    message,
    type = "info"
) {

    const container =
        get("message");


    if (!container) {

        console.log(
            `[${type}] ${message}`
        );

        return;
    }


    container.textContent =
        message;


    container.className =
        `message ${type}`;

}


// ============================================================
// HTML ESCAPING
// ============================================================

function escapeHtml(value) {

    if (
        value === null ||
        value === undefined
    ) {
        return "";
    }


    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

}