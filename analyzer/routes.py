import os
import json
import logging
from flask import render_template, request, flash, redirect, url_for, current_app
from werkzeug.utils import secure_filename
from analyzer import analyzer_bp
from analyzer.log_parser import LogAnalyzer
from models import LogAnalysis
from app import db

ALLOWED_EXTENSIONS = {'log', 'txt', 'json'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@analyzer_bp.route('/')
def index():
    """Main analyzer interface"""
    recent_analyses = LogAnalysis.query.order_by(LogAnalysis.timestamp.desc()).limit(10).all()
    return render_template('analyzer/index.html', recent_analyses=recent_analyses)

@analyzer_bp.route('/upload', methods=['POST'])
def upload_log():
    """Upload and analyze log file"""
    if 'log_file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('analyzer.index'))
    
    file = request.files['log_file']
    log_type = request.form.get('log_type', 'auto')
    
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('analyzer.index'))
    
    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)
            filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Analyze the log file
            analyzer = LogAnalyzer(filepath, log_type)
            analysis_result = analyzer.analyze()
            
            if analysis_result:
                # Save analysis to database
                log_analysis = LogAnalysis(
                    filename=filename,
                    log_type=analysis_result['log_type'],
                    total_entries=analysis_result['total_entries'],
                    suspicious_ips=json.dumps(analysis_result['suspicious_ips']),
                    failed_logins=analysis_result['failed_logins'],
                    port_scans=analysis_result['port_scans'],
                    dos_attempts=analysis_result['dos_attempts'],
                    top_ips=json.dumps(analysis_result['top_ips'])
                )
                db.session.add(log_analysis)
                db.session.commit()
                
                flash('Log file analyzed successfully', 'success')
                return render_template('analyzer/results.html', 
                                     analysis=analysis_result, 
                                     analysis_id=log_analysis.id)
            else:
                flash('Failed to analyze log file', 'error')
                return redirect(url_for('analyzer.index'))
                
        except Exception as e:
            logging.error(f"Log analysis error: {str(e)}")
            flash(f'Analysis failed: {str(e)}', 'error')
            return redirect(url_for('analyzer.index'))
    else:
        flash('Invalid file type. Please upload .log, .txt, or .json files', 'error')
        return redirect(url_for('analyzer.index'))

@analyzer_bp.route('/results/<int:analysis_id>')
def view_result(analysis_id):
    """View specific analysis result"""
    analysis = LogAnalysis.query.get_or_404(analysis_id)
    
    # Reconstruct analysis result
    analysis_result = {
        'log_type': analysis.log_type,
        'total_entries': analysis.total_entries,
        'suspicious_ips': json.loads(analysis.suspicious_ips) if analysis.suspicious_ips else [],
        'failed_logins': analysis.failed_logins,
        'port_scans': analysis.port_scans,
        'dos_attempts': analysis.dos_attempts,
        'top_ips': json.loads(analysis.top_ips) if analysis.top_ips else [],
        'filename': analysis.filename,
        'timestamp': analysis.timestamp
    }
    
    return render_template('analyzer/results.html', 
                         analysis=analysis_result, 
                         analysis_id=analysis_id)

@analyzer_bp.route('/history')
def history():
    """View analysis history"""
    page = request.args.get('page', 1, type=int)
    analyses = LogAnalysis.query.order_by(LogAnalysis.timestamp.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    return render_template('analyzer/history.html', analyses=analyses)
