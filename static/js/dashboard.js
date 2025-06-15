// CyberSec Dashboard JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Auto-hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Add loading state to forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Processing...';
            }
        });
    });

    // File upload validation
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                const maxSize = 16 * 1024 * 1024; // 16MB
                if (file.size > maxSize) {
                    alert('File size exceeds 16MB limit. Please select a smaller file.');
                    this.value = '';
                    return;
                }

                const allowedTypes = ['.log', '.txt', '.json'];
                const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
                if (!allowedTypes.includes(fileExtension)) {
                    alert('Invalid file type. Please select a .log, .txt, or .json file.');
                    this.value = '';
                    return;
                }

                // Show file info
                const fileInfo = document.querySelector('.file-info');
                if (fileInfo) {
                    fileInfo.innerHTML = `
                        <small class="text-muted">
                            Selected: ${file.name} (${formatFileSize(file.size)})
                        </small>
                    `;
                }
            }
        });
    });

    // Vulnerability scan form validation
    const scanForm = document.querySelector('form[action*="scan"]');
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            const targetUrl = this.querySelector('input[name="target_url"]').value;
            const scanTypes = this.querySelectorAll('input[name="scan_types"]:checked');

            if (!targetUrl.trim()) {
                e.preventDefault();
                alert('Please enter a target URL');
                return;
            }

            if (scanTypes.length === 0) {
                e.preventDefault();
                alert('Please select at least one scan type');
                return;
            }

            // URL validation
            try {
                new URL(targetUrl);
            } catch (error) {
                e.preventDefault();
                alert('Please enter a valid URL (including http:// or https://)');
                return;
            }
        });
    }

    // Auto-refresh functionality for real-time data
    if (window.location.pathname.includes('/results/')) {
        // Add refresh button to results pages
        addRefreshButton();
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + R for refresh
        if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
            if (window.location.pathname.includes('/results/')) {
                e.preventDefault();
                window.location.reload();
            }
        }

        // Escape key to go back
        if (e.key === 'Escape') {
            const backBtn = document.querySelector('.btn[href*="index"]');
            if (backBtn) {
                window.location.href = backBtn.href;
            }
        }
    });
});

// Utility Functions
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function addRefreshButton() {
    const actionsDiv = document.querySelector('.d-flex.gap-3');
    if (actionsDiv) {
        const refreshBtn = document.createElement('button');
        refreshBtn.className = 'btn btn-outline-secondary';
        refreshBtn.innerHTML = '<i data-feather="refresh-cw" class="me-2"></i>Refresh';
        refreshBtn.onclick = () => window.location.reload();
        actionsDiv.appendChild(refreshBtn);
        
        // Update feather icons
        feather.replace();
    }
}

// Chart.js default configuration
if (typeof Chart !== 'undefined') {
    Chart.defaults.color = '#e2e8f0';
    Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.1)';
    Chart.defaults.backgroundColor = 'rgba(13, 110, 253, 0.8)';
}

// Real-time updates for dashboard
function updateDashboardStats() {
    // This would typically make AJAX calls to get updated statistics
    // For now, it's a placeholder for future real-time functionality
    console.log('Dashboard stats update placeholder');
}

// Export functionality
function exportToCSV(data, filename) {
    const csvContent = "data:text/csv;charset=utf-8," + data;
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Theme management
function toggleTheme() {
    // Future implementation for light/dark theme toggle
    console.log('Theme toggle placeholder');
}

// Notification system
function showNotification(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    const container = document.querySelector('.container').first() || document.body;
    container.insertBefore(alertDiv, container.firstChild);
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        const bsAlert = new bootstrap.Alert(alertDiv);
        bsAlert.close();
    }, 5000);
}

// Copy to clipboard functionality
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        showNotification('Copied to clipboard!', 'success');
    }, function(err) {
        console.error('Could not copy text: ', err);
        showNotification('Failed to copy to clipboard', 'danger');
    });
}

// Search and filter functionality
function filterTable(input, tableId) {
    const filter = input.value.toUpperCase();
    const table = document.getElementById(tableId);
    const rows = table.getElementsByTagName('tr');
    
    for (let i = 1; i < rows.length; i++) {
        const row = rows[i];
        const cells = row.getElementsByTagName('td');
        let found = false;
        
        for (let j = 0; j < cells.length; j++) {
            if (cells[j].textContent.toUpperCase().indexOf(filter) > -1) {
                found = true;
                break;
            }
        }
        
        row.style.display = found ? '' : 'none';
    }
}

// Severity color mapping
const severityColors = {
    'Critical': 'danger',
    'High': 'danger',
    'Medium': 'warning',
    'Low': 'info',
    'Clean': 'success'
};

function getSeverityBadgeClass(severity) {
    return `badge bg-${severityColors[severity] || 'secondary'}`;
}

// Initialize page-specific functionality
function initPage() {
    const path = window.location.pathname;
    
    if (path.includes('/scanner/')) {
        initScannerPage();
    } else if (path.includes('/analyzer/')) {
        initAnalyzerPage();
    } else if (path === '/') {
        initDashboardPage();
    }
}

function initScannerPage() {
    console.log('Scanner page initialized');
    // Scanner-specific initialization
}

function initAnalyzerPage() {
    console.log('Analyzer page initialized');
    // Analyzer-specific initialization
}

function initDashboardPage() {
    console.log('Dashboard page initialized');
    // Dashboard-specific initialization
}

// Call page initialization
initPage();
