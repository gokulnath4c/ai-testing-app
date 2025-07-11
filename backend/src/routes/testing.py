from flask import Blueprint, request, jsonify, send_file
import asyncio
import os
from datetime import datetime
from src.services.web_testing_service import WebTestingService
from src.services.security_testing_service import SecurityTestingService
from src.services.aws_audit_service import AWSAuditService
from src.services.ai_service import AIService
from src.services.report_service import ReportService

testing_bp = Blueprint('testing', __name__)

# Store test results temporarily (in production, use a database)
test_results_store = {}

@testing_bp.route('/test/start', methods=['POST'])
def start_test():
    """Start a comprehensive test"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url']
        test_types = data.get('test_types', ['web', 'security'])
        aws_config = data.get('aws_config', {})
        
        # Generate test ID
        test_id = f"test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Initialize services
        web_service = WebTestingService()
        security_service = SecurityTestingService()
        aws_service = AWSAuditService()
        ai_service = AIService()
        
        # Run tests
        results = {
            'test_id': test_id,
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'status': 'running',
            'results': {}
        }
        
        # Store initial result
        test_results_store[test_id] = results
        
        # Run tests asynchronously (simplified for demo)
        try:
            if 'web' in test_types:
                web_results = web_service.run_comprehensive_test(url)
                results['results']['web_testing'] = web_results
            
            if 'security' in test_types:
                security_results = security_service.run_security_test(url)
                results['results']['security_testing'] = security_results
            
            if 'aws' in test_types and aws_config:
                aws_results = aws_service.run_audit(aws_config)
                results['results']['aws_audit'] = aws_results
            
            # Calculate overall score
            scores = []
            if 'web_testing' in results['results']:
                scores.append(results['results']['web_testing'].get('overall_score', 0))
            if 'security_testing' in results['results']:
                scores.append(results['results']['security_testing'].get('security_score', 0))
            if 'aws_audit' in results['results']:
                scores.append(results['results']['aws_audit'].get('compliance_score', 0))
            
            results['overall_score'] = sum(scores) // len(scores) if scores else 0
            
            # Generate AI insights
            ai_insights = ai_service.analyze_test_results(results['results'])
            results['ai_insights'] = ai_insights
            
            results['status'] = 'completed'
            
        except Exception as e:
            results['status'] = 'failed'
            results['error'] = str(e)
        
        # Update stored results
        test_results_store[test_id] = results
        
        return jsonify({
            'test_id': test_id,
            'status': results['status'],
            'message': 'Test completed successfully' if results['status'] == 'completed' else 'Test failed'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@testing_bp.route('/test/results/<test_id>', methods=['GET'])
def get_test_results(test_id):
    """Get test results by ID"""
    try:
        if test_id not in test_results_store:
            return jsonify({'error': 'Test not found'}), 404
        
        results = test_results_store[test_id]
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@testing_bp.route('/test/report/<test_id>', methods=['GET'])
def generate_report(test_id):
    """Generate and download test report"""
    try:
        if test_id not in test_results_store:
            return jsonify({'error': 'Test not found'}), 404
        
        format_type = request.args.get('format', 'html')
        test_results = test_results_store[test_id]
        
        report_service = ReportService()
        report_result = report_service.generate_report(test_results, format_type)
        
        if 'error' in report_result:
            return jsonify(report_result), 500
        
        return jsonify(report_result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@testing_bp.route('/test/download/<filename>', methods=['GET'])
def download_report(filename):
    """Download generated report file"""
    try:
        filepath = os.path.join('/tmp', filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404
        
        return send_file(filepath, as_attachment=True, download_name=filename)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@testing_bp.route('/test/status/<test_id>', methods=['GET'])
def get_test_status(test_id):
    """Get test status"""
    try:
        if test_id not in test_results_store:
            return jsonify({'error': 'Test not found'}), 404
        
        results = test_results_store[test_id]
        return jsonify({
            'test_id': test_id,
            'status': results.get('status', 'unknown'),
            'progress': 100 if results.get('status') == 'completed' else 50
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

