// --- State Management ---
const AppState = {
    repositories: [],
    allVulnerabilities: [],
    dashboardData: null,
    activeRepoId: null,
    activeFindingId: null,
    chartInstances: {},
    cyInstance: null
};

// --- API Client ---
const API = {
    async fetchDashboard() {
        const res = await fetch('/api/dashboard');
        if (!res.ok) throw new Error('Failed to fetch dashboard');
        return await res.json();
    },
    async fetchRepositories() {
        const res = await fetch('/api/repositories');
        if (!res.ok) throw new Error('Failed to fetch repositories');
        return await res.json();
    },
    async fetchGraph(repoId) {
        const res = await fetch(`/api/graph/${repoId}`);
        if (!res.ok) throw new Error('Failed to fetch dependency graph');
        return await res.json();
    },
    async fetchVulnerabilities(repoId = '', priority = '') {
        let url = '/api/vulnerabilities';
        const params = [];
        if (repoId) params.push(`repository_id=${repoId}`);
        if (priority) params.push(`priority=${priority}`);
        if (params.length) url += `?${params.join('&')}`;
        
        const res = await fetch(url);
        if (!res.ok) throw new Error('Failed to fetch vulnerabilities');
        return await res.json();
    },
    async fetchRiskConfig() {
        const res = await fetch('/api/risk/config');
        if (!res.ok) throw new Error('Failed to fetch risk configuration');
        return await res.json();
    },
    async updateRiskConfig(config) {
        const res = await fetch('/api/risk/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        if (!res.ok) throw new Error('Failed to update risk configuration');
        return await res.json();
    },
    async fetchRemediationDetails(findingId) {
        const res = await fetch(`/api/remediation/${findingId}`);
        if (!res.ok) throw new Error('Failed to fetch remediation details');
        return await res.json();
    },
    async applyRemediation(findingId) {
        const res = await fetch(`/api/remediate/${findingId}`, { method: 'POST' });
        if (!res.ok) throw new Error('Failed to apply remediation');
        return await res.json();
    },
    async uploadSbom(formData) {
        const res = await fetch('/api/sbom/upload', {
            method: 'POST',
            body: formData
        });
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.detail || 'Failed to upload SBOM');
        }
        return await res.json();
    },
    async triggerScan(repoId) {
        const res = await fetch(`/api/scan/${repoId}`, { method: 'POST' });
        if (!res.ok) throw new Error('Failed to run re-scan');
        return await res.json();
    }
};

// --- Toast notification utility ---
function showToast(message, isSuccess = true) {
    const toast = document.getElementById('toast');
    const icon = document.getElementById('toast-icon');
    const msgSpan = document.getElementById('toast-message');
    
    msgSpan.textContent = message;
    
    if (isSuccess) {
        icon.className = 'fa-solid fa-circle-check toast-icon';
        icon.style.color = '#06d6a0';
        toast.style.borderColor = '#06d6a0';
    } else {
        icon.className = 'fa-solid fa-triangle-exclamation toast-icon';
        icon.style.color = '#ff3366';
        toast.style.borderColor = '#ff3366';
    }
    
    toast.classList.remove('hidden');
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 4000);
}

// --- Dynamic Navigation View Routing ---
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.view-section');
    const viewTitle = document.getElementById('view-title');
    const viewSubtitle = document.getElementById('view-subtitle');

    const titleDetails = {
        'dashboard-view': { title: 'Dashboard Overview', sub: 'Security intelligence and risk distribution summary' },
        'graph-view': { title: 'Dependency Graph Visualizer', sub: 'Explore structural dependencies, transitive scopes, and vulnerability reachability' },
        'vulns-view': { title: 'Vulnerabilities Catalog', sub: 'Prioritized security findings across all repositories' },
        'config-view': { title: 'Risk Configurator', sub: 'Tune CVSS, EPSS, patch lag, and depth decay weights' },
        'upload-view': { title: 'Ingest SBOM File', sub: 'Upload CycloneDX/SPDX JSON files to analyze software risk' }
    };

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const target = item.getAttribute('data-target');
            
            navItems.forEach(n => n.classList.remove('active'));
            sections.forEach(s => s.classList.remove('active'));
            
            item.classList.add('active');
            document.getElementById(target).classList.add('active');
            
            const meta = titleDetails[target];
            if (meta) {
                viewTitle.textContent = meta.title;
                viewSubtitle.textContent = meta.sub;
            }

            // Load data specific to selected views
            onViewChange(target);
        });
    });

    document.getElementById('btn-view-all-findings').addEventListener('click', () => {
        document.getElementById('nav-vulns').click();
    });
}

function onViewChange(viewId) {
    if (viewId === 'dashboard-view') {
        loadDashboardData();
    } else if (viewId === 'graph-view') {
        loadGraphRepoList();
    } else if (viewId === 'vulns-view') {
        loadVulnerabilitiesList();
    } else if (viewId === 'config-view') {
        loadRiskConfig();
    }
}

// --- Dashboard View Handler ---
async function loadDashboardData() {
    try {
        const data = await API.fetchDashboard();
        AppState.dashboardData = data;

        // Render metrics cards
        document.getElementById('val-repos').textContent = data.total_repositories;
        document.getElementById('val-deps').textContent = data.total_dependencies;
        document.getElementById('val-vulns').textContent = data.total_vulnerabilities;
        document.getElementById('val-critical-vulns').textContent = data.critical_vulnerabilities;
        document.getElementById('val-blocked-builds').textContent = data.blocked_builds;

        // Render distribution charts
        renderCharts(data);

        // Render high prioritized table rows
        renderRecentFindings(data.recent_findings);
    } catch (err) {
        showToast('Error fetching dashboard statistics: ' + err.message, false);
    }
}

function renderCharts(data) {
    // 1. Severity Distribution
    if (AppState.chartInstances['severity']) AppState.chartInstances['severity'].destroy();
    
    const sevCtx = document.getElementById('severityChart').getContext('2d');
    AppState.chartInstances['severity'] = new Chart(sevCtx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(data.severity_distribution),
            datasets: [{
                data: Object.values(data.severity_distribution),
                backgroundColor: ['#ff3366', '#ff9f1c', '#ffd166', '#4ea8de'],
                borderWidth: 1,
                borderColor: '#121426'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#94a3b8', font: { family: 'Inter' } }
                }
            }
        }
    });

    // 2. Reachability Distribution (Direct vs Transitive)
    if (AppState.chartInstances['reachability']) AppState.chartInstances['reachability'].destroy();
    
    const reachCtx = document.getElementById('reachabilityChart').getContext('2d');
    AppState.chartInstances['reachability'] = new Chart(reachCtx, {
        type: 'pie',
        data: {
            labels: Object.keys(data.direct_vs_transitive),
            datasets: [{
                data: Object.values(data.direct_vs_transitive),
                backgroundColor: ['#00f2fe', '#9d4edd'],
                borderWidth: 1,
                borderColor: '#121426'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#94a3b8', font: { family: 'Inter' } }
                }
            }
        }
    });

    // 3. Risk Score by Repository Horizontal Bar
    if (AppState.chartInstances['riskByRepo']) AppState.chartInstances['riskByRepo'].destroy();
    
    const repoCtx = document.getElementById('repoRiskChart').getContext('2d');
    AppState.chartInstances['riskByRepo'] = new Chart(repoCtx, {
        type: 'bar',
        data: {
            labels: Object.keys(data.risk_by_repository),
            datasets: [{
                label: 'Risk Score',
                data: Object.values(data.risk_by_repository),
                backgroundColor: '#00f2fe',
                borderRadius: 6,
                borderWidth: 0
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    max: 100,
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    ticks: { color: '#94a3b8' }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8' }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function renderRecentFindings(findings) {
    const tbody = document.getElementById('recent-findings-tbody');
    tbody.innerHTML = '';
    
    if (!findings || findings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center">No active vulnerabilities found!</td></tr>';
        return;
    }

    findings.forEach(f => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${f.cve_id}</strong></td>
            <td>${f.package_name} <span class="text-secondary">v${f.package_version}</span></td>
            <td><span class="badge ${f.package_version.includes('.') ? 'badge-low' : 'badge-safe'}">${f.depth === 1 ? 'pip' : 'npm'}</span></td>
            <td><span class="badge badge-critical">${f.cvss}</span></td>
            <td>${f.epss ? (f.epss * 100).toFixed(1) + '%' : '0%'}</td>
            <td>${f.depth === 1 ? 'Direct' : 'Transitive (Depth ' + f.depth + ')'}</td>
            <td><strong style="color: ${getRiskColor(f.calculated_risk)}">${f.calculated_risk}</strong></td>
            <td>
                <button class="btn btn-secondary btn-sm" onclick="openRemediationModal(${f.id})">
                    <i class="fa-solid fa-wrench"></i> Remediate
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// Helper to get score color
function getRiskColor(score) {
    if (score >= 90) return '#ff3366';
    if (score >= 70) return '#ff9f1c';
    if (score >= 40) return '#ffd166';
    return '#06d6a0';
}

// --- Graph View Handler ---
async function loadGraphRepoList() {
    try {
        const repos = await API.fetchRepositories();
        AppState.repositories = repos;
        
        const select = document.getElementById('repo-select');
        // Clear previous options
        select.innerHTML = '<option value="">Select a Repository...</option>';
        
        repos.forEach(r => {
            const opt = document.createElement('option');
            opt.value = r.id;
            opt.textContent = `${r.name} (${r.build_status} - Risk ${r.risk_score})`;
            select.appendChild(opt);
        });

        // Event listener
        select.removeEventListener('change', onRepoGraphSelect);
        select.addEventListener('change', onRepoGraphSelect);
        
        if (AppState.activeRepoId) {
            select.value = AppState.activeRepoId;
            onRepoGraphSelect();
        }
    } catch (err) {
        showToast('Error loading repositories: ' + err.message, false);
    }
}

async function onRepoGraphSelect() {
    const repoId = document.getElementById('repo-select').value;
    if (!repoId) {
        // Destroy graph if select is cleared
        if (AppState.cyInstance) {
            AppState.cyInstance.destroy();
            AppState.cyInstance = null;
        }
        document.getElementById('details-content').classList.add('hidden');
        document.getElementById('details-empty-state').classList.remove('hidden');
        return;
    }
    
    AppState.activeRepoId = repoId;
    
    try {
        const graphData = await API.fetchGraph(repoId);
        renderCytoscapeGraph(graphData);
    } catch (err) {
        showToast('Error loading dependency graph: ' + err.message, false);
    }
}

function renderCytoscapeGraph(data) {
    const elements = [];
    
    // Process Nodes
    data.nodes.forEach(node => {
        // Set size based on dependents count
        const size = Math.max(22, Math.min(60, 22 + (node.dependents_count * 1.5)));
        
        // Color mapping by severity
        let color = '#06d6a0'; // SAFE default
        if (node.is_vulnerable) {
            if (node.risk_category === 'CRITICAL') color = '#ff3366';
            else if (node.risk_category === 'HIGH') color = '#ff9f1c';
            else if (node.risk_category === 'MEDIUM') color = '#ffd166';
            else color = '#4ea8de'; // LOW
        }

        elements.push({
            data: {
                id: node.id,
                label: node.label,
                version: node.version,
                type: node.type,
                depth: node.depth,
                is_direct: node.is_direct,
                dependents_count: node.dependents_count,
                is_vulnerable: node.is_vulnerable,
                max_risk_score: node.max_risk_score,
                risk_category: node.risk_category,
                vulnerabilities: node.vulnerabilities,
                size: size,
                color: color
            }
        });
    });

    // Process Edges
    data.edges.forEach(edge => {
        elements.push({
            data: {
                id: `edge-${edge.source}-${edge.target}`,
                source: edge.source,
                target: edge.target
            }
        });
    });

    // Initialize Cytoscape
    if (AppState.cyInstance) {
        AppState.cyInstance.destroy();
    }

    AppState.cyInstance = cytoscape({
        container: document.getElementById('cy'),
        elements: elements,
        style: [
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'width': 'data(size)',
                    'height': 'data(size)',
                    'background-color': 'data(color)',
                    'color': '#94a3b8',
                    'font-size': '10px',
                    'font-family': 'Inter, sans-serif',
                    'text-valign': 'bottom',
                    'text-margin-y': 6,
                    'overlay-opacity': 0,
                    'border-width': '2px',
                    'border-color': 'rgba(255,255,255,0.08)'
                }
            },
            {
                selector: 'node[?is_vulnerable]',
                style: {
                    'border-width': '3px',
                    'border-color': 'rgba(255,255,255,0.6)',
                    'shadow-blur': 12,
                    'shadow-color': 'data(color)',
                    'shadow-opacity': 0.8
                }
            },
            {
                selector: 'node[depth = 0]', // Root node
                style: {
                    'background-color': '#9d4edd',
                    'shape': 'hexagon',
                    'width': '52px',
                    'height': '52px',
                    'color': '#e2e8f0',
                    'font-weight': 'bold',
                    'font-size': '12px'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 1.5,
                    'line-color': 'rgba(255, 255, 255, 0.1)',
                    'target-arrow-shape': 'triangle',
                    'target-arrow-color': 'rgba(255, 255, 255, 0.15)',
                    'curve-style': 'bezier'
                }
            }
        ],
        layout: {
            name: 'cose',
            idealEdgeLength: 100,
            nodeOverlap: 20,
            refresh: 20,
            fit: true,
            padding: 40,
            randomize: false,
            componentSpacing: 100,
            nodeRepulsion: 400000,
            edgeElasticity: 100,
            nestingFactor: 5,
            gravity: 80,
            numIter: 1000,
            initialTemp: 200,
            coolingFactor: 0.95,
            minTemp: 1.0
        }
    });

    // Node click event
    AppState.cyInstance.on('tap', 'node', function(evt) {
        const node = evt.target;
        showNodeDetails(node.data());
    });
}

function showNodeDetails(data) {
    document.getElementById('details-empty-state').classList.add('hidden');
    const content = document.getElementById('details-content');
    content.classList.remove('hidden');

    document.getElementById('node-name').textContent = data.label;
    
    const typeBadge = document.getElementById('node-type');
    typeBadge.textContent = data.type.toUpperCase();
    typeBadge.className = data.type === 'pip' ? 'badge badge-low' : 'badge badge-safe';

    document.getElementById('node-version').textContent = data.version;
    document.getElementById('node-depth').textContent = data.is_direct ? 'Direct (Depth 1)' : `Transitive (Depth ${data.depth})`;
    document.getElementById('node-dependents').textContent = data.dependents_count;

    const riskBadge = document.getElementById('node-risk-badge');
    riskBadge.textContent = data.risk_category;
    
    // Set style of risk category
    let badgeClass = 'badge ';
    if (data.risk_category === 'CRITICAL') badgeClass += 'badge-critical';
    else if (data.risk_category === 'HIGH') badgeClass += 'badge-high';
    else if (data.risk_category === 'MEDIUM') badgeClass += 'badge-medium';
    else if (data.risk_category === 'LOW') badgeClass += 'badge-low';
    else badgeClass += 'badge-safe';
    
    riskBadge.className = badgeClass;

    // Vulnerabilities list
    const list = document.getElementById('node-vulns-list');
    list.innerHTML = '';
    
    const section = document.getElementById('node-vulns-section');
    if (!data.is_vulnerable || data.vulnerabilities.length === 0) {
        section.style.display = 'none';
        return;
    }
    
    section.style.display = 'block';
    
    data.vulnerabilities.forEach(v => {
        const div = document.createElement('div');
        const priorityClass = v.priority.toLowerCase();
        div.className = `node-vuln-item ${priorityClass}`;
        div.innerHTML = `
            <div class="node-vuln-item-header">
                <span class="node-vuln-cve">${v.cve_id}</span>
                <span class="node-vuln-score">CVSS: ${v.cvss}</span>
            </div>
            <div class="node-vuln-actions">
                <span class="node-vuln-priority text-${priorityClass}">${v.priority}</span>
                <button class="btn-text btn-sm" onclick="openRemediationModalByName('${v.cve_id}')" style="font-size: 11px; padding: 2px;">
                    Remediate <i class="fa-solid fa-arrow-right"></i>
                </button>
            </div>
        `;
        list.appendChild(div);
    });
}

// Helper to open modal by CVE name
async function openRemediationModalByName(cveId) {
    try {
        const vulns = await API.fetchVulnerabilities('', '');
        const match = vulns.find(v => v.cve_id === cveId);
        if (match) {
            openRemediationModal(match.id);
        } else {
            showToast('Could not find vulnerability details for ' + cveId, false);
        }
    } catch (err) {
        showToast('Error finding vulnerability details: ' + err.message, false);
    }
}

// --- Vulnerabilities View Handler ---
async function loadVulnerabilitiesList() {
    try {
        // Fetch all repositories to populate filter
        const repos = await API.fetchRepositories();
        const select = document.getElementById('filter-repo');
        
        // Preserve standard option
        select.innerHTML = '<option value="">All Repositories</option>';
        repos.forEach(r => {
            const opt = document.createElement('option');
            opt.value = r.id;
            opt.textContent = r.name;
            select.appendChild(opt);
        });

        // Trigger loading
        await filterVulnerabilities();
        
        // Add event listeners for filters
        select.removeEventListener('change', filterVulnerabilities);
        select.addEventListener('change', filterVulnerabilities);
        
        const prioritySelect = document.getElementById('filter-priority');
        prioritySelect.removeEventListener('change', filterVulnerabilities);
        prioritySelect.addEventListener('change', filterVulnerabilities);
        
        const searchInput = document.getElementById('filter-search');
        searchInput.removeEventListener('input', filterVulnerabilities);
        searchInput.addEventListener('input', filterVulnerabilities);
    } catch (err) {
        showToast('Error initializing vulnerability filters: ' + err.message, false);
    }
}

async function filterVulnerabilities() {
    const repoId = document.getElementById('filter-repo').value;
    const priority = document.getElementById('filter-priority').value;
    const searchVal = document.getElementById('filter-search').value.toLowerCase().trim();
    
    try {
        let list = await API.fetchVulnerabilities(repoId, priority);
        AppState.allVulnerabilities = list;
        
        // Client-side text search filter
        if (searchVal) {
            list = list.filter(v => 
                v.package_name.toLowerCase().includes(searchVal) ||
                v.cve_id.toLowerCase().includes(searchVal)
            );
        }
        
        renderVulnerabilitiesTable(list);
    } catch (err) {
        showToast('Error filtering vulnerabilities list: ' + err.message, false);
    }
}

function renderVulnerabilitiesTable(list) {
    const tbody = document.getElementById('vulns-list-tbody');
    tbody.innerHTML = '';
    
    if (!list || list.length === 0) {
        tbody.innerHTML = '<tr><td colspan="10" class="text-center">No vulnerabilities found matching criteria.</td></tr>';
        return;
    }

    list.forEach(v => {
        const tr = document.createElement('tr');
        
        // Severity Class
        let badgeClass = 'badge ';
        if (v.ml_priority === 'CRITICAL') badgeClass += 'badge-critical';
        else if (v.ml_priority === 'HIGH') badgeClass += 'badge-high';
        else if (v.ml_priority === 'MEDIUM') badgeClass += 'badge-medium';
        else badgeClass += 'badge-low';
        
        const statusText = v.status === 'remediated' 
            ? `<span class="badge badge-safe"><i class="fa-solid fa-circle-check"></i> Fix Simmed</span>`
            : `<span class="badge badge-critical"><i class="fa-solid fa-circle-exclamation"></i> Active</span>`;

        // Get repo name
        let repoName = 'unknown';
        if (AppState.repositories.length) {
            const match = AppState.repositories.find(r => r.id === v.repository_id);
            if (match) repoName = match.name;
        } else {
            repoName = `repo-${v.repository_id}`;
        }
        
        const isRemediated = v.status === 'remediated';

        tr.innerHTML = `
            <td><strong>${v.cve_id}</strong></td>
            <td>${v.package_name} <span class="text-secondary">v${v.package_version}</span></td>
            <td>${repoName}</td>
            <td><span class="${badgeClass}">${v.ml_priority}</span></td>
            <td><span class="badge badge-critical">${v.cvss}</span></td>
            <td>${v.epss ? (v.epss * 100).toFixed(1) + '%' : '0%'}</td>
            <td>${v.depth === 1 ? 'Direct' : 'Transitive (Depth ' + v.depth + ')'}</td>
            <td><strong style="color: ${getRiskColor(v.calculated_risk)}">${v.calculated_risk}</strong></td>
            <td>${statusText}</td>
            <td>
                <button class="btn btn-secondary btn-sm" onclick="openRemediationModal(${v.id})" ${isRemediated ? 'disabled' : ''}>
                    <i class="fa-solid fa-wrench"></i> ${isRemediated ? 'Remediated' : 'Remediate'}
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// --- Risk Scoring Configuration Handler ---
async function loadRiskConfig() {
    try {
        const config = await API.fetchRiskConfig();
        
        // Update form values
        document.getElementById('input-cvss-weight').value = config.cvss_weight;
        document.getElementById('val-cvss-weight').textContent = config.cvss_weight.toFixed(1);
        
        document.getElementById('input-epss-weight').value = config.epss_weight;
        document.getElementById('val-epss-weight').textContent = config.epss_weight.toFixed(1);
        
        document.getElementById('input-patch-lag-weight').value = config.patch_lag_weight;
        document.getElementById('val-patch-lag-weight').textContent = config.patch_lag_weight.toFixed(1);
        
        document.getElementById('input-depth-weight').value = config.depth_weight;
        document.getElementById('val-depth-weight').textContent = config.depth_weight.toFixed(1);
        
        setupConfigSliders();
    } catch (err) {
        showToast('Error loading weights configuration: ' + err.message, false);
    }
}

function setupConfigSliders() {
    const sliders = document.querySelectorAll('.weight-slider');
    sliders.forEach(slider => {
        slider.addEventListener('input', (e) => {
            const valSpanId = slider.id.replace('input-', 'val-');
            const valSpan = document.getElementById(valSpanId);
            if (valSpan) {
                valSpan.textContent = parseFloat(e.target.value).toFixed(1);
            }
        });
    });
}

function initRiskConfigForm() {
    const form = document.getElementById('risk-config-form');
    if (!form) return;
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const config = {
            cvss_weight: parseFloat(document.getElementById('input-cvss-weight').value),
            epss_weight: parseFloat(document.getElementById('input-epss-weight').value),
            patch_lag_weight: parseFloat(document.getElementById('input-patch-lag-weight').value),
            depth_weight: parseFloat(document.getElementById('input-depth-weight').value)
        };
        
        try {
            await API.updateRiskConfig(config);
            showToast('Scoring weights saved and database re-calculated!', true);
        } catch (err) {
            showToast('Failed to save configuration: ' + err.message, false);
        }
    });

    document.getElementById('btn-reset-weights').addEventListener('click', () => {
        document.getElementById('input-cvss-weight').value = 10.0;
        document.getElementById('val-cvss-weight').textContent = '10.0';
        
        document.getElementById('input-epss-weight').value = 1.0;
        document.getElementById('val-epss-weight').textContent = '1.0';
        
        document.getElementById('input-patch-lag-weight').value = 1.0;
        document.getElementById('val-patch-lag-weight').textContent = '1.0';
        
        document.getElementById('input-depth-weight').value = 1.0;
        document.getElementById('val-depth-weight').textContent = '1.0';
    });
}

// --- SBOM File Ingestion Handler ---
function initSbomUpload() {
    const dropzone = document.getElementById('upload-dropzone');
    const fileInput = document.getElementById('input-sbom-file');
    const fileNameDiv = document.getElementById('selected-file-name');
    const submitBtn = document.getElementById('btn-submit-sbom');
    const form = document.getElementById('sbom-upload-form');
    
    if (!dropzone || !form) return;

    // Dropzone trigger click
    dropzone.addEventListener('click', () => fileInput.click());
    
    // File input change
    fileInput.addEventListener('change', (e) => {
        handleFiles(e.target.files);
    });

    // Drag-and-drop mechanics
    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropzone.classList.add('dragover');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropzone.classList.remove('dragover');
        }, false);
    });

    dropzone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        handleFiles(files);
    });

    function handleFiles(files) {
        if (!files.length) return;
        const file = files[0];
        if (!file.name.endsWith('.json')) {
            showToast('Invalid file format. Only JSON CycloneDX or SPDX files are allowed.', false);
            fileInput.value = '';
            fileNameDiv.textContent = 'No file selected';
            submitBtn.disabled = true;
            return;
        }
        
        fileNameDiv.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        submitBtn.disabled = false;
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const files = fileInput.files;
        if (!files.length) return;
        
        const file = files[0];
        const repoName = document.getElementById('input-repo-name').value.trim();
        
        const formData = new FormData();
        formData.append('file', file);
        if (repoName) {
            formData.append('repo_name', repoName);
        }
        
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Processing SBOM...';
        
        try {
            const result = await API.uploadSbom(formData);
            showToast(`Scan completed successfully! Found ${result.findings_count} vulnerabilities.`, true);
            
            // Redirect to dashboard
            document.getElementById('nav-dashboard').click();
            
            // Reset form
            form.reset();
            fileNameDiv.textContent = 'No file selected';
            submitBtn.disabled = true;
        } catch (err) {
            showToast('Scan failed: ' + err.message, false);
        } finally {
            submitBtn.innerHTML = '<i class="fa-solid fa-circle-play"></i> Run Security Scan';
        }
    });
}

// --- Actionable Remediation Modal Handler ---
async function openRemediationModal(findingId) {
    AppState.activeFindingId = findingId;
    
    try {
        const data = await API.fetchRemediationDetails(findingId);
        
        document.getElementById('modal-cve-title').textContent = data.cve_id;
        document.getElementById('modal-pkg-info').innerHTML = `Vulnerable Package: <strong>${data.package_name}</strong> v${data.current_version} &rarr; Upgrade to <strong>${data.recommended_version}</strong>`;
        document.getElementById('modal-explanation').textContent = data.explanation;
        document.getElementById('modal-command').textContent = data.remediation_cmd;
        document.getElementById('modal-config-file').textContent = data.config_file;
        document.getElementById('modal-diff-content').textContent = data.patch_diff;
        
        // Show Modal
        const modal = document.getElementById('remediation-modal');
        modal.classList.remove('hidden');
        
        // Configure copy button
        const copyBtn = document.getElementById('btn-copy-cmd');
        copyBtn.innerHTML = '<i class="fa-regular fa-copy"></i>';
        copyBtn.onclick = () => {
            navigator.clipboard.writeText(data.remediation_cmd);
            copyBtn.innerHTML = '<i class="fa-solid fa-check" style="color: #06d6a0;"></i>';
            setTimeout(() => {
                copyBtn.innerHTML = '<i class="fa-regular fa-copy"></i>';
            }, 2000);
        };
    } catch (err) {
        showToast('Error loading remediation suggestions: ' + err.message, false);
    }
}

function initRemediationModal() {
    const modal = document.getElementById('remediation-modal');
    const closeBtn = document.getElementById('btn-close-modal');
    const cancelBtn = document.getElementById('btn-cancel-remediation');
    const applyBtn = document.getElementById('btn-apply-remediation');
    
    const closeModal = () => modal.classList.add('hidden');
    
    closeBtn.addEventListener('click', closeModal);
    cancelBtn.addEventListener('click', closeModal);
    
    // Close modal clicking backdrop
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal();
    });

    applyBtn.addEventListener('click', async () => {
        if (!AppState.activeFindingId) return;
        
        try {
            await API.applyRemediation(AppState.activeFindingId);
            showToast('Remediation successfully simulated! Vulnerability fixed.', true);
            closeModal();
            
            // Reload currently active view datasets
            const activeNav = document.querySelector('.nav-item.active');
            if (activeNav) {
                const target = activeNav.getAttribute('data-target');
                onViewChange(target);
            }
        } catch (err) {
            showToast('Failed to apply remediation: ' + err.message, false);
        }
    });
}

// --- Sync / Rescan Button ---
function initSyncScan() {
    const btn = document.getElementById('btn-quick-scan');
    btn.addEventListener('click', async () => {
        // If we have an active repository in the selector, re-scan it, otherwise re-scan the first repository
        let repoId = AppState.activeRepoId;
        if (!repoId && AppState.repositories.length) {
            repoId = AppState.repositories[0].id;
        }
        
        if (!repoId) {
            showToast('No repositories loaded to trigger a sync re-scan.', false);
            return;
        }
        
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-arrows-rotate fa-spin"></i> Scanning...';
        
        try {
            const repo = AppState.repositories.find(r => r.id === parseInt(repoId));
            const name = repo ? repo.name : `ID: ${repoId}`;
            await API.triggerScan(repoId);
            showToast(`Re-scan completed for ${name}!`, true);
            
            // Reload active view
            const activeNav = document.querySelector('.nav-item.active');
            if (activeNav) {
                onViewChange(activeNav.getAttribute('data-target'));
            }
        } catch (err) {
            showToast('Sync scan failed: ' + err.message, false);
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Sync Scan';
        }
    });
}

// --- Application Entry Point ---
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initRemediationModal();
    initRiskConfigForm();
    initSbomUpload();
    initSyncScan();
    
    // Load initial View
    loadDashboardData();
});
