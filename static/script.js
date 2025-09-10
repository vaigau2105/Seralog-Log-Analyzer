// Drag and drop functionality
const uploadZone = document.getElementById('uploadZone');
const fileInput = document.getElementById('fileInput');

uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('dragover');
});

uploadZone.addEventListener('dragleave', () => {
    uploadZone.classList.remove('dragover');
});

uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
handleFileUpload(files[0]);
    }
});

uploadZone.addEventListener('click', () => {
    fileInput.click();
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
handleFileUpload(e.target.files[0]);
    }
});

function handleFileUpload(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    document.getElementById('loadingSpinner').style.display = 'block';
    
    fetch('/upload', {
method: 'POST',
body: formData
    })
    .then(response => response.json())
    .then(data => {
document.getElementById('loadingSpinner').style.display = 'none';
if (data.success) {
    displayResults(data.results);
    document.querySelector('#results-tab').click();
} else {
    alert('Error: ' + data.message);
}
    })
    .catch(error => {
document.getElementById('loadingSpinner').style.display = 'none';
alert('Upload failed: ' + error);
    });
}

function loadSampleData() {
    document.getElementById('loadingSpinner').style.display = 'block';
    
    fetch('/sample')
    .then(response => response.json())
    .then(data => {
document.getElementById('loadingSpinner').style.display = 'none';
if (data.success) {
    displayResults(data.results);
    document.querySelector('#results-tab').click();
} else {
    alert('Error: ' + data.message);
}
    });
}

function checkPassword() {
    const password = document.getElementById('passwordInput').value;
    if (!password) {
alert('Please enter a password');
return;
    }
    
    fetch('/password', {
method: 'POST',
headers: {'Content-Type': 'application/json'},
body: JSON.stringify({password: password})
    })
    .then(response => response.json())
    .then(data => {
const result = document.getElementById('passwordResult');
result.innerHTML = `
    <div class="alert alert-${data.color} alert-custom">
<h6><i class="fas fa-shield-alt"></i> Strength: ${data.strength}</h6>
<p>Score: ${data.score}/6</p>
${data.feedback.length > 0 ? '<p><strong>Suggestions:</strong></p><ul>' + data.feedback.map(f => '<li>' + f + '</li>').join('') + '</ul>' : ''}
    </div>
`;
    });
}

function scanPorts() {
    const target = document.getElementById('scanTarget').value;
    const ports = document.getElementById('scanPorts').value;
    
    if (!target) {
alert('Please enter a target IP or domain');
return;
    }
    
    const resultDiv = document.getElementById('scanResult');
    resultDiv.innerHTML = '<div class="text-center"><div class="spinner-border text-info" role="status"></div><p>Scanning ports...</p></div>';
    
    fetch('/portscan', {
method: 'POST',
headers: {'Content-Type': 'application/json'},
body: JSON.stringify({target: target, ports: ports})
    })
    .then(response => response.json())
    .then(data => {
if (data.error) {
    resultDiv.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
} else {
    resultDiv.innerHTML = `
<div class="alert alert-info alert-custom">
    <h6><i class="fas fa-network-wired"></i> Scan Results for ${target}</h6>
    <p><strong>Open Ports:</strong> ${data.open_ports.length > 0 ? data.open_ports.join(', ') : 'None found'}</p>
    <p><strong>Ports Scanned:</strong> ${data.total_scanned}</p>
</div>
    `;
}
    });
}

function displayResults(results) {
    const analysisDiv = document.getElementById('analysisResults');
    
    let html = '<div class="row">';
    
    // Overview stats
    html += '<div class="col-12 mb-4">';
    html += '<div class="row">';
    html += `<div class="col-md-3"><div class="stat-card"><h3 class="text-primary">${results.total_entries || 0}</h3><p>Total Log Entries</p></div></div>`;
    html += `<div class="col-md-3"><div class="stat-card"><h3 class="text-info">${results.ip_analysis?.total_unique_ips || 0}</h3><p>Unique IP Addresses</p></div></div>`;
    html += `<div class="col-md-3"><div class="stat-card"><h3 class="text-warning">${results.status_analysis?.total_errors || 0}</h3><p>HTTP Errors</p></div></div>`;
    html += `<div class="col-md-3"><div class="stat-card"><h3 class="text-danger">${results.suspicious_activity?.total_suspicious || 0}</h3><p>Suspicious Activities</p></div></div>`;
    html += '</div></div>';
    
    // IP Analysis
    if (results.ip_analysis) {
html += '<div class="col-md-6 mb-4">';
html += '<div class="analysis-results">';
html += '<h5><i class="fas fa-globe text-primary"></i> Top IP Addresses</h5>';
html += '<div class="table-responsive">';
html += '<table class="table table-striped">';
html += '<thead><tr><th>IP Address</th><th>Requests</th></tr></thead><tbody>';

if (results.ip_analysis.top_ips) {
    results.ip_analysis.top_ips.slice(0, 5).forEach(([ip, count]) => {
html += `<tr><td>${ip}</td><td><span class="badge bg-primary">${count}</span></td></tr>`;
    });
}

html += '</tbody></table></div></div></div>';

// Suspicious IPs
html += '<div class="col-md-6 mb-4">';
html += '<div class="analysis-results">';
html += '<h5><i class="fas fa-exclamation-triangle text-danger"></i> Suspicious IPs</h5>';

if (results.ip_analysis.suspicious_ips && results.ip_analysis.suspicious_ips.length > 0) {
    html += '<div class="table-responsive">';
    html += '<table class="table table-striped">';
    html += '<thead><tr><th>IP Address</th><th>Count</th><th>Reason</th></tr></thead><tbody>';
    
    results.ip_analysis.suspicious_ips.slice(0, 5).forEach(ip => {
html += `<tr class="table-warning"><td>${ip.ip}</td><td><span class="badge bg-warning">${ip.count}</span></td><td>${ip.reason}</td></tr>`;
    });
    
    html += '</tbody></table></div>';
} else {
    html += '<div class="alert alert-success"><i class="fas fa-check-circle"></i> No suspicious IPs detected</div>';
}

html += '</div></div>';
    }
    
    // Status Code Analysis
    if (results.status_analysis) {
html += '<div class="col-md-6 mb-4">';
html += '<div class="analysis-results">';
html += '<h5><i class="fas fa-chart-bar text-info"></i> HTTP Status Codes</h5>';

if (results.status_analysis.status_distribution) {
    html += '<div class="table-responsive">';
    html += '<table class="table table-striped">';
    html += '<thead><tr><th>Status Code</th><th>Count</th><th>Type</th></tr></thead><tbody>';
    
    Object.entries(results.status_analysis.status_distribution).forEach(([code, count]) => {
let type = 'Success';
let badgeColor = 'success';

if (code >= 400 && code < 500) {
    type = 'Client Error';
    badgeColor = 'warning';
} else if (code >= 500) {
    type = 'Server Error';
    badgeColor = 'danger';
} else if (code >= 300) {
    type = 'Redirect';
    badgeColor = 'info';
}

html += `<tr><td>${code}</td><td><span class="badge bg-${badgeColor}">${count}</span></td><td>${type}</td></tr>`;
    });
    
    html += '</tbody></table></div>';
}

html += `<p class="text-muted">Error Rate: ${(results.status_analysis.error_rate || 0).toFixed(2)}%</p>`;
html += '</div></div>';
    }
    
    // Suspicious Activity
    if (results.suspicious_activity) {
html += '<div class="col-md-6 mb-4">';
html += '<div class="analysis-results">';
html += '<h5><i class="fas fa-shield-alt text-danger"></i> Attack Detection</h5>';

if (results.suspicious_activity.attack_types && Object.keys(results.suspicious_activity.attack_types).length > 0) {
    html += '<div class="table-responsive">';
    html += '<table class="table table-striped">';
    html += '<thead><tr><th>Attack Type</th><th>Attempts</th></tr></thead><tbody>';
    
    Object.entries(results.suspicious_activity.attack_types).forEach(([attack, count]) => {
html += `<tr class="table-danger"><td>${attack}</td><td><span class="badge bg-danger">${count}</span></td></tr>`;
    });
    
    html += '</tbody></table></div>';
} else {
    html += '<div class="alert alert-success"><i class="fas fa-check-circle"></i> No attacks detected</div>';
}

// Recent attacks
if (results.suspicious_activity.recent_attacks && results.suspicious_activity.recent_attacks.length > 0) {
    html += '<h6 class="mt-3">Recent Attack Attempts</h6>';
    html += '<div class="table-responsive">';
    html += '<table class="table table-sm">';
    html += '<thead><tr><th>Type</th><th>IP</th><th>Time</th></tr></thead><tbody>';
    
    results.suspicious_activity.recent_attacks.slice(0, 5).forEach(attack => {
html += `<tr><td><span class="badge bg-danger">${attack.type}</span></td><td>${attack.ip}</td><td>${attack.timestamp}</td></tr>`;
    });
    
    html += '</tbody></table></div>';
}

html += '</div></div>';
    }
    
    html += '</div>';
    
    // Generate Report Button
    html += '<div class="text-center mt-4">';
    html += '<button class="btn btn-success btn-custom btn-lg" onclick="generateReport()">';
    html += '<i class="fas fa-file-pdf"></i> Generate HTML Report';
    html += '</button></div>';
    
    analysisDiv.innerHTML = html;
}

function generateReport() {
    fetch('/report')
    .then(response => response.json())
    .then(data => {
if (data.success) {
    window.open('/download/' + data.filename, '_blank');
} else {
    alert('Error generating report: ' + data.message);
}
    });
}