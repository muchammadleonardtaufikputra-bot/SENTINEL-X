
from http.server import BaseHTTPRequestHandler, HTTPServer
import sqlite3
import json
from datetime import datetime

DB_NAME = "sentinel.db"
HOST = "127.0.0.1"
PORT = 8765

SECURITY_EVENT_INFO = {
    4624: {
        "title": "Successful Logon",
        "description": "A user successfully signed in to Windows.",
        "note": "Normal authentication activity; review context if needed."
    },
    4648: {
        "title": "Explicit Credentials",
        "description": "A logon attempt used explicitly supplied credentials.",
        "note": "Can occur during normal administrative activity."
    },
    4672: {
        "title": "Special Privileges Assigned",
        "description": "Special privileges were assigned to a new logon.",
        "note": "Common for system and administrator accounts."
    },
    4798: {
        "title": "Local Group Enumeration",
        "description": "A process queried a user's local group membership.",
        "note": "Can occur during normal Windows operations."
    },
    4907: {
        "title": "Auditing Settings Changed",
        "description": "Auditing settings on an object were changed.",
        "note": "Review the change and its administrative context."
    },
    5379: {
        "title": "Credential Manager Access",
        "description": "Credential Manager credentials were read.",
        "note": "Can occur during normal application activity."
    }
}

HTML = """
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SENTINEL X | SOC Dashboard</title>

<style>
*{box-sizing:border-box}

body{
    margin:0;
    background:#080d18;
    color:#e5edf7;
    font-family:Arial,sans-serif;
}

header{
    padding:24px;
    background:#101a2c;
    border-bottom:1px solid #26344b;
}

h1{
    margin:0;
    color:#38bdf8;
    letter-spacing:2px;
}

header p{color:#94a3b8}

main{
    max-width:1300px;
    margin:auto;
    padding:24px;
}

.cards{
    display:grid;
    grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
    gap:15px;
}

.card,.panel{
    background:#111c2e;
    border:1px solid #26344b;
    border-radius:12px;
    padding:20px;
}

.card h2{
    font-size:30px;
    margin:8px 0;
    color:#38bdf8;
}

.label{
    color:#94a3b8;
    font-size:13px;
}

.panel{
    margin-top:20px;
    overflow-x:auto;
}

.analytics-grid{
    display:grid;
    grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
    gap:16px;
}

.metric{
    background:#080d18;
    border:1px solid #26344b;
    border-radius:10px;
    padding:16px;
}

.metric h4{
    margin:0 0 18px;
    color:#38bdf8;
}

.metric-number{
    font-size:28px;
    font-weight:bold;
    margin:8px 0;
}

.metric-description{
    color:#94a3b8;
    font-size:12px;
}

.bar-row{margin:16px 0}

.bar-heading{
    display:flex;
    justify-content:space-between;
    font-size:13px;
    margin-bottom:7px;
}

.bar-track{
    width:100%;
    height:12px;
    background:#26344b;
    border-radius:20px;
    overflow:hidden;
}

.bar-fill{
    height:100%;
    width:0%;
    border-radius:20px;
    transition:width .4s ease;
}

.open-bar{background:#fbbf24}
.closed-bar{background:#22c55e}
.high-bar{background:#fb7185}
.medium-bar{background:#fbbf24}
.low-bar{background:#4ade80}
.system-bar{background:#38bdf8}
.security-bar{background:#a78bfa}

.resolution-track{
    height:16px;
    background:#26344b;
    border-radius:20px;
    overflow:hidden;
    margin:15px 0;
}

.resolution-fill{
    height:100%;
    width:0%;
    background:#22c55e;
    transition:width .4s ease;
}

table{
    width:100%;
    border-collapse:collapse;
    text-align:left;
}

th,td{
    padding:12px;
    border-bottom:1px solid #26344b;
    font-size:13px;
}

th{color:#38bdf8}

.low{color:#4ade80}
.medium{color:#fbbf24}
.high{color:#fb7185}

.open-status{color:#fbbf24}
.closed-status{color:#4ade80}

footer{
    color:#64748b;
    text-align:center;
    padding:25px;
}

.status{color:#4ade80}

select,input{
    background:#080d18;
    color:#e5edf7;
    border:1px solid #26344b;
    padding:9px;
    border-radius:7px;
}

input{min-width:200px}

.toolbar{
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:12px;
    flex-wrap:wrap;
}

.alert-row{cursor:pointer}
.alert-row:hover{background:#1b2a42}

.detail-overlay{
    display:none;
    position:fixed;
    inset:0;
    z-index:1000;
    background:rgba(0,0,0,.75);
    justify-content:center;
    align-items:center;
    padding:20px;
}

.detail-box{
    width:100%;
    max-width:550px;
    max-height:90vh;
    overflow-y:auto;
    background:#111c2e;
    border:1px solid #26344b;
    border-radius:12px;
    padding:24px;
}

.detail-box h2{color:#38bdf8}

.detail-item{
    margin:16px 0;
    padding:12px;
    background:#080d18;
    border-radius:8px;
    overflow-wrap:anywhere;
}

.detail-label{
    color:#94a3b8;
    font-size:12px;
    margin-bottom:7px;
}

.detail-value{
    color:#e5edf7;
    font-size:14px;
    white-space:pre-wrap;
}

button{
    padding:10px 18px;
    border:0;
    border-radius:7px;
    cursor:pointer;
    color:white;
    font-weight:bold;
}

button:disabled{
    opacity:.5;
    cursor:not-allowed;
}

.action-button{
    background:#16a34a;
    margin-right:8px;
}

.reopen-button{background:#2563eb}
.close-button{background:#dc2626}

.empty{
    text-align:center;
    color:#94a3b8;
    padding:20px;
}

#actionMessage{
    margin-top:12px;
    color:#4ade80;
    font-size:13px;
}

/* STAGE 9: SECURITY EVENT INSIGHTS */

.insight-grid{
    display:grid;
    grid-template-columns:repeat(auto-fit,minmax(260px,1fr));
    gap:14px;
}

.insight-card{
    background:#080d18;
    border:1px solid #26344b;
    border-radius:10px;
    padding:16px;
}

.insight-top{
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:10px;
    margin-bottom:12px;
}

.insight-id{
    color:#38bdf8;
    font-size:14px;
    font-weight:bold;
}

.insight-count{
    color:#a78bfa;
    font-size:23px;
    font-weight:bold;
}

.insight-title{
    font-size:14px;
    font-weight:bold;
    margin-bottom:8px;
}

.insight-description{
    color:#cbd5e1;
    font-size:13px;
    line-height:1.5;
}

.insight-note{
    color:#94a3b8;
    font-size:12px;
    line-height:1.5;
    margin-top:10px;
}

.insight-disclaimer{
    background:#17243a;
    border-left:3px solid #38bdf8;
    padding:12px;
    border-radius:6px;
    color:#cbd5e1;
    font-size:12px;
    line-height:1.6;
    margin-bottom:16px;
}

@media(max-width:600px){
    main{padding:14px}
    header{padding:18px}
    .card,.panel{padding:15px}
    th,td{font-size:12px;padding:9px}
}
</style>
</head>

<body>

<header>
    <h1>SENTINEL X</h1>
    <p>Personal Security Operations Center | Windows Monitoring</p>
    <div class="status">● LOCAL MONITORING DASHBOARD</div>
</header>

<main>

<!-- OVERVIEW -->

<div class="cards">

    <div class="card">
        <div class="label">TOTAL EVENTS</div>
        <h2 id="events">-</h2>
    </div>

    <div class="card">
        <div class="label">SYSTEM EVENTS</div>
        <h2 id="systemEvents">-</h2>
    </div>

    <div class="card">
        <div class="label">SECURITY EVENTS</div>
        <h2 id="securityEvents">-</h2>
    </div>

    <div class="card">
        <div class="label">TOTAL ALERTS</div>
        <h2 id="alerts">-</h2>
    </div>

    <div class="card">
        <div class="label">HIGH ALERTS</div>
        <h2 id="high">-</h2>
    </div>

    <div class="card">
        <div class="label">MEDIUM ALERTS</div>
        <h2 id="medium">-</h2>
    </div>

    <div class="card">
        <div class="label">LOW ALERTS</div>
        <h2 id="low">-</h2>
    </div>

</div>

<!-- SOC ANALYTICS -->

<div class="panel">

    <h3>SOC Analytics</h3>

    <p class="label">
        Visual overview of event sources, alert distribution and resolution.
    </p>

    <div class="analytics-grid">

        <div class="metric">
            <h4>Windows Event Sources</h4>

            <div class="bar-row">
                <div class="bar-heading">
                    <span>System</span>
                    <strong id="systemCount">0</strong>
                </div>
                <div class="bar-track">
                    <div id="systemBar" class="bar-fill system-bar"></div>
                </div>
            </div>

            <div class="bar-row">
                <div class="bar-heading">
                    <span>Security</span>
                    <strong id="securityCount">0</strong>
                </div>
                <div class="bar-track">
                    <div id="securityBar" class="bar-fill security-bar"></div>
                </div>
            </div>
        </div>

        <div class="metric">
            <h4>Alert Status Overview</h4>

            <div class="bar-row">
                <div class="bar-heading">
                    <span>OPEN</span>
                    <strong id="openCount">0</strong>
                </div>
                <div class="bar-track">
                    <div id="openBar" class="bar-fill open-bar"></div>
                </div>
            </div>

            <div class="bar-row">
                <div class="bar-heading">
                    <span>CLOSED</span>
                    <strong id="closedCount">0</strong>
                </div>
                <div class="bar-track">
                    <div id="closedBar" class="bar-fill closed-bar"></div>
                </div>
            </div>
        </div>

        <div class="metric">
            <h4>Severity Distribution</h4>

            <div class="bar-row">
                <div class="bar-heading">
                    <span>HIGH</span>
                    <strong id="highCount">0</strong>
                </div>
                <div class="bar-track">
                    <div id="highBar" class="bar-fill high-bar"></div>
                </div>
            </div>

            <div class="bar-row">
                <div class="bar-heading">
                    <span>MEDIUM</span>
                    <strong id="mediumCount">0</strong>
                </div>
                <div class="bar-track">
                    <div id="mediumBar" class="bar-fill medium-bar"></div>
                </div>
            </div>

            <div class="bar-row">
                <div class="bar-heading">
                    <span>LOW</span>
                    <strong id="lowCount">0</strong>
                </div>
                <div class="bar-track">
                    <div id="lowBar" class="bar-fill low-bar"></div>
                </div>
            </div>
        </div>

        <div class="metric">
            <h4>Alert Resolution Rate</h4>

            <div class="metric-number" id="resolutionRate">0%</div>

            <div class="resolution-track">
                <div id="resolutionBar" class="resolution-fill"></div>
            </div>

            <div class="metric-description" id="resolutionText">
                No alert data available.
            </div>
        </div>

    </div>
</div>

<!-- STAGE 9: SECURITY EVENT INSIGHTS -->

<div class="panel">

    <h3>Security Event Insights</h3>

    <p class="label">
        Analysis of Windows Security Event IDs collected by SENTINEL X.
    </p>

    <div class="insight-disclaimer">
        Informational analysis only. These event types can occur during
        normal Windows activity. An event count alone does not establish
        suspicious or malicious behavior.
    </div>

    <div class="insight-grid" id="securityInsightRows">
        <div class="empty">Loading Security Event Insights...</div>
    </div>

    <p class="label" id="securityInsightSummary">
        Waiting for event data...
    </p>

</div>

<!-- WINDOWS EVENTS -->

<div class="panel">

    <h3>Recent Windows Events</h3>

    <table>
        <thead>
            <tr>
                <th>Log</th>
                <th>Event ID</th>
                <th>Provider</th>
                <th>Level</th>
                <th>Event Time</th>
            </tr>
        </thead>

        <tbody id="eventRows"></tbody>
    </table>

</div>

<!-- SECURITY ALERTS -->

<div class="panel">

    <div class="toolbar">

        <h3>Security Alerts</h3>

        <input
            id="searchAlert"
            type="text"
            placeholder="Cari judul alert..."
            oninput="renderAlerts()"
        >

        <select id="severityFilter" onchange="renderAlerts()">
            <option value="ALL">All Severities</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
        </select>

        <select id="statusFilter" onchange="renderAlerts()">
            <option value="ALL">All Status</option>
            <option value="OPEN">OPEN</option>
            <option value="CLOSED">CLOSED</option>
        </select>

    </div>

    <p class="label">
        Klik alert untuk melihat detail dan mengelola status.
    </p>

    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Status</th>
            </tr>
        </thead>

        <tbody id="alertRows"></tbody>
    </table>

</div>

<!-- ACTIVITY HISTORY -->

<div class="panel">

    <div class="toolbar">
        <h3>Activity History</h3>
        <span class="label">Latest 20 activities</span>
    </div>

    <p class="label">
        Riwayat perubahan status alert yang tersimpan di SQLite.
    </p>

    <table>
        <thead>
            <tr>
                <th>Alert</th>
                <th>Previous Status</th>
                <th>New Status</th>
                <th>Changed At</th>
            </tr>
        </thead>

        <tbody id="historyRows"></tbody>
    </table>

</div>

</main>

<footer>
    SENTINEL X | Local data only | Refresh every 5 seconds
</footer>

<!-- ALERT DETAIL MODAL -->

<div class="detail-overlay" id="detailOverlay">

    <div class="detail-box">

        <h2>Alert Details</h2>

        <div class="detail-item">
            <div class="detail-label">TITLE</div>
            <div class="detail-value" id="detailTitle">-</div>
        </div>

        <div class="detail-item">
            <div class="detail-label">SEVERITY</div>
            <div class="detail-value" id="detailSeverity">-</div>
        </div>

        <div class="detail-item">
            <div class="detail-label">STATUS</div>
            <div class="detail-value" id="detailStatus">-</div>
        </div>

        <div class="detail-item">
            <div class="detail-label">DESCRIPTION</div>
            <div class="detail-value" id="detailDescription">-</div>
        </div>

        <div class="detail-item">
            <div class="detail-label">EVENT TIME</div>
            <div class="detail-value" id="detailTime">-</div>
        </div>

        <button
            id="actionButton"
            class="action-button"
            onclick="changeAlertStatus()">
            Mark as CLOSED
        </button>

        <button
            class="close-button"
            onclick="closeDetail()">
            Close
        </button>

        <div id="actionMessage"></div>

    </div>

</div>

<script>

let currentAlerts = [];
let selectedAlert = null;

function safeText(value){
    return String(value ?? "-");
}

function setText(id,value){
    document.getElementById(id).textContent = safeText(value);
}

function escapeHTML(value){

    return safeText(value).replace(/[&<>"']/g, character => ({
        "&":"&amp;",
        "<":"&lt;",
        ">":"&gt;",
        '"':"&quot;",
        "'":"&#39;"
    })[character]);

}


// ANALYTICS

function updateAnalytics(data){

    const total = Number(data.total_alerts) || 0;
    const totalEvents = Number(data.total_events) || 0;

    const systemEvents = Number(data.system_events) || 0;
    const securityEvents = Number(data.security_events) || 0;

    const open = Number(data.open) || 0;
    const closed = Number(data.closed) || 0;

    const high = Number(data.high) || 0;
    const medium = Number(data.medium) || 0;
    const low = Number(data.low) || 0;

    function percentage(value, denominator){

        if(denominator === 0){
            return 0;
        }

        return Math.round((value / denominator) * 100);
    }

    function setBar(id,value,denominator){

        document.getElementById(id).style.width =
            percentage(value,denominator) + "%";

    }

    setText("systemCount",systemEvents);
    setText("securityCount",securityEvents);

    setBar("systemBar",systemEvents,totalEvents);
    setBar("securityBar",securityEvents,totalEvents);

    setText("openCount",open);
    setText("closedCount",closed);

    setText("highCount",high);
    setText("mediumCount",medium);
    setText("lowCount",low);

    setBar("openBar",open,total);
    setBar("closedBar",closed,total);

    setBar("highBar",high,total);
    setBar("mediumBar",medium,total);
    setBar("lowBar",low,total);

    const rate = percentage(closed,total);

    setText("resolutionRate",rate + "%");

    document.getElementById("resolutionBar").style.width =
        rate + "%";

    if(total === 0){

        setText("resolutionText","No alert data available.");

    }else{

        setText(
            "resolutionText",
            closed + " of " + total + " alerts closed."
        );

    }

}


// STAGE 9: SECURITY EVENT INSIGHTS

function renderSecurityInsights(insights, total){

    const container =
        document.getElementById("securityInsightRows");

    if(!Array.isArray(insights) || insights.length === 0){

        container.innerHTML = `
            <div class="empty">
                No Security Event data available.
            </div>
        `;

        setText("securityInsightSummary","No Security Events found.");
        return;
    }

    container.innerHTML = insights.map(item => `

        <div class="insight-card">

            <div class="insight-top">
                <span class="insight-id">
                    EVENT ID ${escapeHTML(item.event_id)}
                </span>

                <span class="insight-count">
                    ${escapeHTML(item.count)}
                </span>
            </div>

            <div class="insight-title">
                ${escapeHTML(item.title)}
            </div>

            <div class="insight-description">
                ${escapeHTML(item.description)}
            </div>

            <div class="insight-note">
                ${escapeHTML(item.note)}
            </div>

        </div>

    `).join("");

    setText(
        "securityInsightSummary",
        "Security Events analyzed: " + Number(total || 0) +
        " | Event categories: " + insights.length
    );

}


// REFRESH DASHBOARD

async function refresh(){

    try{

        const response = await fetch("/api");

        if(!response.ok){
            throw new Error("API error");
        }

        const data = await response.json();

        setText("events",data.total_events);
        setText("systemEvents",data.system_events);
        setText("securityEvents",data.security_events);

        setText("alerts",data.total_alerts);
        setText("high",data.high);
        setText("medium",data.medium);
        setText("low",data.low);

        updateAnalytics(data);

        renderSecurityInsights(
            data.security_insights,
            data.security_events
        );

        document.getElementById("eventRows").innerHTML =
            data.events.map(e => `
                <tr>
                    <td>${escapeHTML(e.log_name)}</td>
                    <td>${escapeHTML(e.event_id)}</td>
                    <td>${escapeHTML(e.provider)}</td>
                    <td>${escapeHTML(e.level)}</td>
                    <td>${escapeHTML(e.event_time)}</td>
                </tr>
            `).join("");

        currentAlerts = data.alerts;

        renderAlerts();
        renderHistory(data.history);

        if(selectedAlert !== null){

            const updated = currentAlerts.find(
                a => Number(a.id) === Number(selectedAlert.id)
            );

            if(updated){
                selectedAlert = updated;
                showAlertDetails(updated);
            }

        }

    }catch(error){

        console.error("Dashboard error:",error);

    }

}


// FILTER ALERTS

function renderAlerts(){

    const severity =
        document.getElementById("severityFilter").value;

    const status =
        document.getElementById("statusFilter").value;

    const search =
        document.getElementById("searchAlert").value.toLowerCase();

    const filtered = currentAlerts.filter(a => {

        const matchSeverity =
            severity === "ALL" || a.severity === severity;

        const matchStatus =
            status === "ALL" || a.status === status;

        const matchSearch =
            safeText(a.title).toLowerCase().includes(search);

        return matchSeverity && matchStatus && matchSearch;

    });

    const rows = document.getElementById("alertRows");

    if(filtered.length === 0){

        rows.innerHTML = `
            <tr>
                <td colspan="3" class="empty">
                    Tidak ada alert pada filter ini.
                </td>
            </tr>
        `;

        return;
    }

    rows.innerHTML = filtered.map(a => {

        const severityClass =
            ["HIGH","MEDIUM","LOW"].includes(a.severity)
            ? a.severity.toLowerCase()
            : "";

        return `
            <tr class="alert-row" data-id="${Number(a.id)}">
                <td class="${severityClass}">
                    ${escapeHTML(a.severity)}
                </td>
                <td>${escapeHTML(a.title)}</td>
                <td>${escapeHTML(a.status)}</td>
            </tr>
        `;

    }).join("");

}


// ACTIVITY HISTORY

function renderHistory(history){

    const rows = document.getElementById("historyRows");

    if(!history || history.length === 0){

        rows.innerHTML = `
            <tr>
                <td colspan="4" class="empty">
                    Belum ada aktivitas perubahan status.
                </td>
            </tr>
        `;

        return;
    }

    rows.innerHTML = history.map(item => {

        const oldClass =
            item.old_status === "CLOSED"
            ? "closed-status"
            : "open-status";

        const newClass =
            item.new_status === "CLOSED"
            ? "closed-status"
            : "open-status";

        return `
            <tr>
                <td>${escapeHTML(item.alert_title)}</td>
                <td class="${oldClass}">
                    ${escapeHTML(item.old_status)}
                </td>
                <td class="${newClass}">
                    ${escapeHTML(item.new_status)}
                </td>
                <td>${escapeHTML(item.changed_at)}</td>
            </tr>
        `;

    }).join("");

}


// OPEN ALERT DETAILS

document.getElementById("alertRows").addEventListener(
    "click",
    event => {

        const row = event.target.closest("tr[data-id]");

        if(!row){
            return;
        }

        const alert = currentAlerts.find(
            a => Number(a.id) === Number(row.dataset.id)
        );

        if(!alert){
            return;
        }

        selectedAlert = alert;

        showAlertDetails(alert);

        document.getElementById("actionMessage").textContent = "";
        document.getElementById("detailOverlay").style.display = "flex";

    }
);


function showAlertDetails(alert){

    setText("detailTitle",alert.title);
    setText("detailSeverity",alert.severity);
    setText("detailStatus",alert.status);
    setText("detailDescription",alert.description);
    setText("detailTime",alert.event_time);

    const button = document.getElementById("actionButton");

    if(alert.status === "OPEN"){

        button.textContent = "Mark as CLOSED";
        button.className = "action-button";

    }else{

        button.textContent = "Reopen Alert";
        button.className = "reopen-button";

    }

}


// CHANGE ALERT STATUS

async function changeAlertStatus(){

    if(!selectedAlert){
        return;
    }

    const newStatus =
        selectedAlert.status === "OPEN" ? "CLOSED" : "OPEN";

    const button = document.getElementById("actionButton");
    const message = document.getElementById("actionMessage");

    button.disabled = true;
    message.textContent = "Menyimpan perubahan...";

    try{

        const response = await fetch("/api/alert-status",{

            method:"POST",

            headers:{
                "Content-Type":"application/json"
            },

            body:JSON.stringify({
                id:selectedAlert.id,
                status:newStatus
            })

        });

        const result = await response.json();

        if(!response.ok || !result.ok){
            throw new Error(result.error || "Gagal mengubah status");
        }

        message.textContent = result.changed
            ? "Status berhasil diperbarui."
            : "Status tidak berubah.";

        await refresh();

    }catch(error){

        message.textContent = "Error: " + error.message;

    }finally{

        button.disabled = false;

    }

}


// CLOSE DETAIL

function closeDetail(){

    document.getElementById("detailOverlay").style.display = "none";
    selectedAlert = null;

}


document.getElementById("detailOverlay").addEventListener(
    "click",
    event => {

        if(event.target.id === "detailOverlay"){
            closeDetail();
        }

    }
);


document.addEventListener("keydown",event => {

    if(event.key === "Escape"){
        closeDetail();
    }

});


refresh();
setInterval(refresh,5000);

</script>

</body>
</html>
"""


# DATABASE INITIALIZATION

def initialize_database():

    conn = sqlite3.connect(DB_NAME)

    try:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                alert_title TEXT NOT NULL,
                old_status TEXT NOT NULL,
                new_status TEXT NOT NULL,
                changed_at TEXT NOT NULL
            )
        """)

        conn.commit()

    finally:
        conn.close()


# DASHBOARD DATA

def get_data():

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row

    try:

        total_events = conn.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        system_events = conn.execute(
            "SELECT COUNT(*) FROM events WHERE log_name='System'"
        ).fetchone()[0]

        security_events = conn.execute(
            "SELECT COUNT(*) FROM events WHERE log_name='Security'"
        ).fetchone()[0]

        total_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        high = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity='HIGH'"
        ).fetchone()[0]

        medium = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM'"
        ).fetchone()[0]

        low = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity='LOW'"
        ).fetchone()[0]

        open_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status='OPEN'"
        ).fetchone()[0]

        closed_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status='CLOSED'"
        ).fetchone()[0]

        events = conn.execute("""
            SELECT log_name, event_id, provider, level, event_time
            FROM events
            ORDER BY id DESC
            LIMIT 20
        """).fetchall()

        alerts = conn.execute("""
            SELECT
                alerts.id,
                alerts.severity,
                alerts.title,
                alerts.description,
                alerts.status,
                events.event_time
            FROM alerts
            LEFT JOIN events
                ON events.id = alerts.event_id
            ORDER BY alerts.id DESC
            LIMIT 50
        """).fetchall()

        history = conn.execute("""
            SELECT
                id,
                alert_id,
                alert_title,
                old_status,
                new_status,
                changed_at
            FROM alert_history
            ORDER BY id DESC
            LIMIT 20
        """).fetchall()

        # STAGE 9: Count Security Event IDs

        security_counts = conn.execute("""
            SELECT event_id, COUNT(*) AS event_count
            FROM events
            WHERE log_name = 'Security'
            GROUP BY event_id
        """).fetchall()

        count_map = {
            int(row["event_id"]): int(row["event_count"])
            for row in security_counts
        }

        security_insights = []

        for event_id, info in SECURITY_EVENT_INFO.items():

            security_insights.append({
                "event_id": event_id,
                "count": count_map.get(event_id, 0),
                "title": info["title"],
                "description": info["description"],
                "note": info["note"]
            })

        return {
            "total_events": total_events,
            "system_events": system_events,
            "security_events": security_events,
            "total_alerts": total_alerts,
            "high": high,
            "medium": medium,
            "low": low,
            "open": open_count,
            "closed": closed_count,
            "events": [dict(x) for x in events],
            "alerts": [dict(x) for x in alerts],
            "history": [dict(x) for x in history],
            "security_insights": security_insights
        }

    finally:
        conn.close()


# HTTP SERVER

class DashboardHandler(BaseHTTPRequestHandler):

    def send_json(self, data, status=200):

        content = json.dumps(data).encode("utf-8")

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )

        self.send_header(
            "Content-Length",
            str(len(content))
        )

        self.end_headers()
        self.wfile.write(content)


    def do_GET(self):

        if self.path == "/":

            content = HTML.encode("utf-8")

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8"
            )

            self.send_header(
                "Content-Length",
                str(len(content))
            )

            self.end_headers()
            self.wfile.write(content)

        elif self.path == "/api":

            try:
                self.send_json(get_data())

            except sqlite3.Error:
                self.send_json(
                    {"ok": False, "error": "Database error"},
                    500
                )

        else:
            self.send_error(404)


    # UPDATE ALERT AND SAVE HISTORY

    def do_POST(self):

        if self.path != "/api/alert-status":
            self.send_error(404)
            return

        try:

            length = int(
                self.headers.get("Content-Length", 0)
            )

            if length <= 0 or length > 10000:

                self.send_json(
                    {"ok": False, "error": "Invalid request size"},
                    400
                )

                return

            body = self.rfile.read(length)
            data = json.loads(body.decode("utf-8"))

            alert_id = data.get("id")
            new_status = data.get("status")

            if type(alert_id) is not int or alert_id <= 0:

                self.send_json(
                    {"ok": False, "error": "Invalid alert ID"},
                    400
                )

                return

            if new_status not in ("OPEN", "CLOSED"):

                self.send_json(
                    {"ok": False, "error": "Invalid status"},
                    400
                )

                return

            conn = sqlite3.connect(DB_NAME)

            try:

                conn.execute("BEGIN IMMEDIATE")

                alert = conn.execute(
                    """
                    SELECT title, status
                    FROM alerts
                    WHERE id = ?
                    """,
                    (alert_id,)
                ).fetchone()

                if alert is None:

                    conn.rollback()

                    self.send_json(
                        {"ok": False, "error": "Alert tidak ditemukan"},
                        404
                    )

                    return

                alert_title, old_status = alert

                if old_status == new_status:

                    conn.rollback()

                    self.send_json({
                        "ok": True,
                        "changed": False,
                        "status": old_status
                    })

                    return

                conn.execute(
                    """
                    UPDATE alerts
                    SET status = ?
                    WHERE id = ?
                    """,
                    (new_status, alert_id)
                )

                changed_at = datetime.now().astimezone().isoformat(
                    timespec="seconds"
                )

                conn.execute(
                    """
                    INSERT INTO alert_history (
                        alert_id,
                        alert_title,
                        old_status,
                        new_status,
                        changed_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        alert_id,
                        alert_title,
                        old_status,
                        new_status,
                        changed_at
                    )
                )

                conn.commit()

                self.send_json({
                    "ok": True,
                    "changed": True,
                    "id": alert_id,
                    "old_status": old_status,
                    "new_status": new_status,
                    "changed_at": changed_at
                })

            except Exception:

                conn.rollback()
                raise

            finally:
                conn.close()

        except (ValueError, json.JSONDecodeError):

            self.send_json(
                {"ok": False, "error": "Invalid request data"},
                400
            )

        except sqlite3.Error:

            self.send_json(
                {"ok": False, "error": "Database error"},
                500
            )


    def log_message(self, format, *args):
        pass


# START APPLICATION

if __name__ == "__main__":

    initialize_database()

    server = HTTPServer(
        (HOST, PORT),
        DashboardHandler
    )

    print("================================")
    print("       SENTINEL X DASHBOARD")
    print("================================")
    print("SOC Analytics siap.")
    print("Event Source Analytics siap.")
    print("Security Event Insights siap.")
    print("Activity History siap.")
    print("Buka: http://127.0.0.1:8765")
    print("Tekan Ctrl+C untuk menghentikan.")

    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print("\\nSENTINEL X Dashboard dihentikan.")

    finally:

        server.server_close()
