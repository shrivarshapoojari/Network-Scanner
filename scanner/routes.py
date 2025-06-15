import logging
from flask import render_template, request, flash, redirect, url_for, jsonify
from scanner import scanner_bp
from scanner.scanner_engine import VulnerabilityScanner
from models import ScanResult
from app import db

@scanner_bp.route('/')
def index():
    """Main scanner interface"""
    recent_scans = ScanResult.query.order_by(ScanResult.timestamp.desc()).limit(10).all()
    return render_template('scanner/index.html', recent_scans=recent_scans)

@scanner_bp.route('/scan', methods=['POST'])
def scan():
    """Initiate vulnerability scan"""
    target_url = request.form.get('target_url', '').strip()
    scan_types = request.form.getlist('scan_types')
    
    if not target_url:
        flash('Please provide a target URL', 'error')
        return redirect(url_for('scanner.index'))
    
    if not scan_types:
        flash('Please select at least one scan type', 'error')
        return redirect(url_for('scanner.index'))
    
    try:
        scanner = VulnerabilityScanner(target_url)
        results = []
        
        for scan_type in scan_types:
            if scan_type == 'sql_injection':
                result = scanner.test_sql_injection()
            elif scan_type == 'xss':
                result = scanner.test_xss()
            elif scan_type == 'csrf':
                result = scanner.test_csrf()
            elif scan_type == 'command_injection':
                result = scanner.test_command_injection()
            elif scan_type == 'insecure_headers':
                result = scanner.test_insecure_headers()
            elif scan_type == 'directory_traversal':
                result = scanner.test_directory_traversal()
            elif scan_type == 'file_upload':
                result = scanner.test_file_upload()
            elif scan_type == 'information_disclosure':
                result = scanner.test_information_disclosure()
            elif scan_type == 'ssl_tls_security':
                result = scanner.test_ssl_tls_security()
            elif scan_type == 'session_management':
                result = scanner.test_session_management()
            else:
                continue
            
            if result:
                # Save to database
                scan_result = ScanResult(
                    target_url=target_url,
                    scan_type=scan_type,
                    vulnerability=result.get('vulnerability'),
                    severity=result.get('severity'),
                    description=result.get('description'),
                    affected_parameter=result.get('affected_parameter'),
                    recommendation=result.get('recommendation')
                )
                db.session.add(scan_result)
                results.append(scan_result)
        
        db.session.commit()
        
        if results:
            flash(f'Scan completed. Found {len(results)} vulnerabilities.', 'success')
        else:
            flash('Scan completed. No vulnerabilities detected.', 'info')
            
        # Convert results to dictionaries for JSON serialization
        results_dict = [result.to_dict() for result in results]
        return render_template('scanner/results.html', results=results_dict, target_url=target_url)
        
    except Exception as e:
        logging.error(f"Scan error: {str(e)}")
        flash(f'Scan failed: {str(e)}', 'error')
        return redirect(url_for('scanner.index'))

@scanner_bp.route('/results/<int:scan_id>')
def view_result(scan_id):
    """View specific scan result"""
    result = ScanResult.query.get_or_404(scan_id)
    return render_template('scanner/results.html', results=[result.to_dict()], target_url=result.target_url)

@scanner_bp.route('/history')
def history():
    """View scan history"""
    page = request.args.get('page', 1, type=int)
    results = ScanResult.query.order_by(ScanResult.timestamp.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    return render_template('scanner/history.html', results=results)
