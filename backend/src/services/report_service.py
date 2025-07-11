import json
import os
from datetime import datetime
from jinja2 import Template
import weasyprint
from fpdf import FPDF

class ReportService:
    def __init__(self):
        self.report_templates = {
            'html': self._get_html_template(),
            'pdf': self._get_pdf_template()
        }
    
    def generate_report(self, test_results, format='html'):
        """Generate comprehensive test report in specified format"""
        try:
            if format == 'html':
                return self._generate_html_report(test_results)
            elif format == 'pdf':
                return self._generate_pdf_report(test_results)
            elif format == 'json':
                return self._generate_json_report(test_results)
            else:
                raise ValueError(f"Unsupported format: {format}")
        except Exception as e:
            return {'error': f'Report generation failed: {str(e)}'}
    
    def _generate_html_report(self, test_results):
        """Generate HTML report"""
        template = Template(self.report_templates['html'])
        
        # Prepare data for template
        report_data = {
            'test_id': test_results.get('test_id', 'Unknown'),
            'url': test_results.get('url', 'Unknown'),
            'timestamp': test_results.get('timestamp', datetime.now().isoformat()),
            'overall_score': test_results.get('overall_score', 0),
            'results': test_results.get('results', {}),
            'ai_insights': test_results.get('ai_insights', {}),
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        html_content = template.render(**report_data)
        
        # Save to file
        filename = f"report_{test_results.get('test_id', 'unknown')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join('/tmp', filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return {
            'format': 'html',
            'filename': filename,
            'filepath': filepath,
            'download_url': f'/api/test/download/{filename}'
        }
    
    def _generate_pdf_report(self, test_results):
        """Generate PDF report"""
        # First generate HTML
        html_result = self._generate_html_report(test_results)
        
        if 'error' in html_result:
            return html_result
        
        try:
            # Convert HTML to PDF using weasyprint
            html_filepath = html_result['filepath']
            pdf_filename = html_result['filename'].replace('.html', '.pdf')
            pdf_filepath = os.path.join('/tmp', pdf_filename)
            
            # Read HTML content
            with open(html_filepath, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            # Generate PDF
            weasyprint.HTML(string=html_content).write_pdf(pdf_filepath)
            
            return {
                'format': 'pdf',
                'filename': pdf_filename,
                'filepath': pdf_filepath,
                'download_url': f'/api/test/download/{pdf_filename}'
            }
            
        except Exception as e:
            # Fallback to simple PDF generation
            return self._generate_simple_pdf_report(test_results)
    
    def _generate_simple_pdf_report(self, test_results):
        """Generate simple PDF report using FPDF"""
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font('Arial', 'B', 16)
            
            # Title
            pdf.cell(0, 10, 'AI Testing Platform - Security & Performance Report', 0, 1, 'C')
            pdf.ln(10)
            
            # Basic info
            pdf.set_font('Arial', '', 12)
            pdf.cell(0, 8, f"Test ID: {test_results.get('test_id', 'Unknown')}", 0, 1)
            pdf.cell(0, 8, f"URL: {test_results.get('url', 'Unknown')}", 0, 1)
            pdf.cell(0, 8, f"Date: {test_results.get('timestamp', 'Unknown')}", 0, 1)
            pdf.cell(0, 8, f"Overall Score: {test_results.get('overall_score', 0)}%", 0, 1)
            pdf.ln(10)
            
            # Results summary
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'Test Results Summary', 0, 1)
            pdf.set_font('Arial', '', 12)
            
            results = test_results.get('results', {})
            
            if 'web_testing' in results:
                web_results = results['web_testing']
                pdf.cell(0, 8, f"Web Testing Score: {web_results.get('overall_score', 0)}%", 0, 1)
            
            if 'security_testing' in results:
                security_results = results['security_testing']
                pdf.cell(0, 8, f"Security Score: {security_results.get('security_score', 0)}%", 0, 1)
                pdf.cell(0, 8, f"Risk Level: {security_results.get('risk_level', 'Unknown')}", 0, 1)
            
            if 'aws_audit' in results:
                aws_results = results['aws_audit']
                pdf.cell(0, 8, f"AWS Compliance Score: {aws_results.get('compliance_score', 0)}%", 0, 1)
            
            # AI Insights
            ai_insights = test_results.get('ai_insights', {})
            if ai_insights:
                pdf.ln(10)
                pdf.set_font('Arial', 'B', 14)
                pdf.cell(0, 10, 'AI-Powered Insights', 0, 1)
                pdf.set_font('Arial', '', 12)
                
                overall_assessment = ai_insights.get('overall_assessment', {})
                if overall_assessment:
                    pdf.cell(0, 8, f"Overall Grade: {overall_assessment.get('overall_grade', 'Unknown')}", 0, 1)
                    pdf.cell(0, 8, f"Security Maturity: {overall_assessment.get('security_maturity', 'Unknown')}", 0, 1)
                
                # Recommendations
                recommendations = ai_insights.get('recommendations', [])
                if recommendations:
                    pdf.ln(5)
                    pdf.set_font('Arial', 'B', 12)
                    pdf.cell(0, 8, 'Top Recommendations:', 0, 1)
                    pdf.set_font('Arial', '', 10)
                    
                    for i, rec in enumerate(recommendations[:5], 1):
                        pdf.cell(0, 6, f"{i}. {rec.get('title', 'Unknown')}", 0, 1)
                        if rec.get('description'):
                            pdf.cell(10, 6, '', 0, 0)  # Indent
                            pdf.cell(0, 6, rec['description'][:80] + '...', 0, 1)
            
            # Save PDF
            filename = f"report_{test_results.get('test_id', 'unknown')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            filepath = os.path.join('/tmp', filename)
            pdf.output(filepath)
            
            return {
                'format': 'pdf',
                'filename': filename,
                'filepath': filepath,
                'download_url': f'/api/test/download/{filename}'
            }
            
        except Exception as e:
            return {'error': f'PDF generation failed: {str(e)}'}
    
    def _generate_json_report(self, test_results):
        """Generate JSON report"""
        try:
            # Add metadata
            report_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'format': 'json',
                    'version': '1.0'
                },
                'test_results': test_results
            }
            
            filename = f"report_{test_results.get('test_id', 'unknown')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join('/tmp', filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            return {
                'format': 'json',
                'filename': filename,
                'filepath': filepath,
                'download_url': f'/api/test/download/{filename}'
            }
            
        except Exception as e:
            return {'error': f'JSON report generation failed: {str(e)}'}
    
    def _get_html_template(self):
        """Get HTML report template"""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Testing Platform Report - {{ test_id }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }
        .card h3 {
            margin: 0 0 15px 0;
            color: #667eea;
            font-size: 1.2em;
        }
        .score {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        .score.excellent { color: #28a745; }
        .score.good { color: #17a2b8; }
        .score.warning { color: #ffc107; }
        .score.danger { color: #dc3545; }
        .section {
            background: white;
            margin-bottom: 30px;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .section-header {
            background: #667eea;
            color: white;
            padding: 20px;
            font-size: 1.3em;
            font-weight: bold;
        }
        .section-content {
            padding: 25px;
        }
        .test-result {
            border-left: 4px solid #e9ecef;
            padding: 15px;
            margin: 15px 0;
            background: #f8f9fa;
            border-radius: 0 5px 5px 0;
        }
        .test-result.passed { border-left-color: #28a745; }
        .test-result.warning { border-left-color: #ffc107; }
        .test-result.failed { border-left-color: #dc3545; }
        .recommendation {
            background: #e3f2fd;
            border: 1px solid #bbdefb;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
        }
        .recommendation h4 {
            margin: 0 0 10px 0;
            color: #1976d2;
        }
        .priority-high { border-left: 4px solid #dc3545; }
        .priority-medium { border-left: 4px solid #ffc107; }
        .priority-low { border-left: 4px solid #28a745; }
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            border-top: 1px solid #e9ecef;
            margin-top: 30px;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-warning { background: #fff3cd; color: #856404; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        .badge-info { background: #d1ecf1; color: #0c5460; }
    </style>
</head>
<body>
    <div class="header">
        <h1>AI Testing Platform Report</h1>
        <p>Comprehensive Security & Performance Analysis</p>
        <p><strong>{{ url }}</strong> | Test ID: {{ test_id }}</p>
        <p>Generated on {{ generated_at }}</p>
    </div>

    <div class="summary-cards">
        <div class="card">
            <h3>Overall Score</h3>
            <div class="score {% if overall_score >= 80 %}excellent{% elif overall_score >= 60 %}good{% elif overall_score >= 40 %}warning{% else %}danger{% endif %}">
                {{ overall_score }}%
            </div>
        </div>
        
        {% if results.web_testing %}
        <div class="card">
            <h3>Web Testing</h3>
            <div class="score {% if results.web_testing.overall_score >= 80 %}excellent{% elif results.web_testing.overall_score >= 60 %}good{% elif results.web_testing.overall_score >= 40 %}warning{% else %}danger{% endif %}">
                {{ results.web_testing.overall_score }}%
            </div>
            <p>Performance, SEO & Accessibility</p>
        </div>
        {% endif %}
        
        {% if results.security_testing %}
        <div class="card">
            <h3>Security Testing</h3>
            <div class="score {% if results.security_testing.security_score >= 80 %}excellent{% elif results.security_testing.security_score >= 60 %}good{% elif results.security_testing.security_score >= 40 %}warning{% else %}danger{% endif %}">
                {{ results.security_testing.security_score }}%
            </div>
            <p>Risk Level: {{ results.security_testing.risk_level }}</p>
        </div>
        {% endif %}
        
        {% if results.aws_audit %}
        <div class="card">
            <h3>AWS Compliance</h3>
            <div class="score {% if results.aws_audit.compliance_score >= 80 %}excellent{% elif results.aws_audit.compliance_score >= 60 %}good{% elif results.aws_audit.compliance_score >= 40 %}warning{% else %}danger{% endif %}">
                {{ results.aws_audit.compliance_score }}%
            </div>
            <p>Cloud Security Audit</p>
        </div>
        {% endif %}
    </div>

    {% if results.web_testing %}
    <div class="section">
        <div class="section-header">Web Application Testing Results</div>
        <div class="section-content">
            {% if results.web_testing.tests.performance %}
            <div class="test-result {% if results.web_testing.tests.performance.status == 'passed' %}passed{% elif results.web_testing.tests.performance.status == 'warning' %}warning{% else %}failed{% endif %}">
                <h4>Performance Analysis</h4>
                <p><strong>Load Time:</strong> {{ results.web_testing.tests.performance.load_time }}s</p>
                <p><strong>Performance Score:</strong> {{ results.web_testing.tests.performance.performance_score }}%</p>
                <p><strong>Resources:</strong> {{ results.web_testing.tests.performance.resource_count.images }} images, {{ results.web_testing.tests.performance.resource_count.scripts }} scripts</p>
            </div>
            {% endif %}
            
            {% if results.web_testing.tests.seo %}
            <div class="test-result {% if results.web_testing.tests.seo.status == 'passed' %}passed{% elif results.web_testing.tests.seo.status == 'warning' %}warning{% else %}failed{% endif %}">
                <h4>SEO Analysis</h4>
                <p><strong>SEO Score:</strong> {{ results.web_testing.tests.seo.seo_score }}%</p>
                <p><strong>Title:</strong> {{ results.web_testing.tests.seo.title }}</p>
                <p><strong>Meta Description:</strong> {{ results.web_testing.tests.seo.meta_description }}</p>
            </div>
            {% endif %}
            
            {% if results.web_testing.tests.accessibility %}
            <div class="test-result {% if results.web_testing.tests.accessibility.status == 'passed' %}passed{% elif results.web_testing.tests.accessibility.status == 'warning' %}warning{% else %}failed{% endif %}">
                <h4>Accessibility Analysis</h4>
                <p><strong>Accessibility Score:</strong> {{ results.web_testing.tests.accessibility.accessibility_score }}%</p>
                {% if results.web_testing.tests.accessibility.issues %}
                <p><strong>Issues Found:</strong></p>
                <ul>
                {% for issue in results.web_testing.tests.accessibility.issues %}
                    <li>{{ issue }}</li>
                {% endfor %}
                </ul>
                {% endif %}
            </div>
            {% endif %}
        </div>
    </div>
    {% endif %}

    {% if results.security_testing %}
    <div class="section">
        <div class="section-header">Security Testing Results</div>
        <div class="section-content">
            {% if results.security_testing.security_tests.ssl_tls %}
            <div class="test-result {% if results.security_testing.security_tests.ssl_tls.status == 'passed' %}passed{% elif results.security_testing.security_tests.ssl_tls.status == 'warning' %}warning{% else %}failed{% endif %}">
                <h4>SSL/TLS Configuration</h4>
                <p><strong>Certificate Valid:</strong> {% if results.security_testing.security_tests.ssl_tls.certificate_valid %}Yes{% else %}No{% endif %}</p>
                <p><strong>Days Until Expiry:</strong> {{ results.security_testing.security_tests.ssl_tls.days_until_expiry }}</p>
            </div>
            {% endif %}
            
            {% if results.security_testing.security_tests.security_headers %}
            <div class="test-result {% if results.security_testing.security_tests.security_headers.status == 'passed' %}passed{% elif results.security_testing.security_tests.security_headers.status == 'warning' %}warning{% else %}failed{% endif %}">
                <h4>Security Headers</h4>
                <p><strong>Security Score:</strong> {{ results.security_testing.security_tests.security_headers.security_score }}%</p>
                {% if results.security_testing.security_tests.security_headers.missing_headers %}
                <p><strong>Missing Headers:</strong></p>
                <ul>
                {% for header in results.security_testing.security_tests.security_headers.missing_headers %}
                    <li>{{ header }}</li>
                {% endfor %}
                </ul>
                {% endif %}
            </div>
            {% endif %}
            
            {% if results.security_testing.security_tests.vulnerabilities %}
            <div class="test-result {% if results.security_testing.security_tests.vulnerabilities.status == 'passed' %}passed{% elif results.security_testing.security_tests.vulnerabilities.status == 'warning' %}warning{% else %}failed{% endif %}">
                <h4>Vulnerability Assessment</h4>
                {% if results.security_testing.security_tests.vulnerabilities.vulnerabilities %}
                {% for vuln in results.security_testing.security_tests.vulnerabilities.vulnerabilities %}
                <div style="margin: 10px 0; padding: 10px; background: #fff3cd; border-radius: 5px;">
                    <strong>{{ vuln.type }}</strong> 
                    <span class="badge badge-{% if vuln.severity == 'Critical' %}danger{% elif vuln.severity == 'High' %}warning{% else %}info{% endif %}">{{ vuln.severity }}</span>
                    <p>{{ vuln.description }}</p>
                </div>
                {% endfor %}
                {% endif %}
            </div>
            {% endif %}
        </div>
    </div>
    {% endif %}

    {% if ai_insights %}
    <div class="section">
        <div class="section-header">AI-Powered Insights & Recommendations</div>
        <div class="section-content">
            {% if ai_insights.overall_assessment %}
            <div class="test-result">
                <h4>Overall Assessment</h4>
                <p><strong>Overall Grade:</strong> {{ ai_insights.overall_assessment.overall_grade }}</p>
                <p><strong>Security Maturity:</strong> {{ ai_insights.overall_assessment.security_maturity }}</p>
                
                {% if ai_insights.overall_assessment.key_strengths %}
                <h5>Key Strengths:</h5>
                <ul>
                {% for strength in ai_insights.overall_assessment.key_strengths %}
                    <li>{{ strength }}</li>
                {% endfor %}
                </ul>
                {% endif %}
                
                {% if ai_insights.overall_assessment.critical_weaknesses %}
                <h5>Areas for Improvement:</h5>
                <ul>
                {% for weakness in ai_insights.overall_assessment.critical_weaknesses %}
                    <li>{{ weakness }}</li>
                {% endfor %}
                </ul>
                {% endif %}
            </div>
            {% endif %}
            
            {% if ai_insights.recommendations %}
            <h4>Detailed Recommendations</h4>
            {% for rec in ai_insights.recommendations %}
            <div class="recommendation priority-{% if rec.priority == 1 %}high{% elif rec.priority == 2 %}medium{% else %}low{% endif %}">
                <h4>{{ rec.title }}</h4>
                <p>{{ rec.description }}</p>
                <p><strong>Category:</strong> {{ rec.category }} | 
                   <strong>Priority:</strong> {{ rec.priority }} | 
                   <strong>Effort:</strong> {{ rec.effort }} | 
                   <strong>Impact:</strong> {{ rec.impact }}</p>
            </div>
            {% endfor %}
            {% endif %}
            
            {% if ai_insights.priority_actions %}
            <h4>Priority Actions</h4>
            {% for action in ai_insights.priority_actions %}
            <div class="recommendation priority-high">
                <h4>{{ action.action }}</h4>
                <p><strong>Timeline:</strong> {{ action.timeline }} | 
                   <strong>Impact:</strong> {{ action.impact }}</p>
            </div>
            {% endfor %}
            {% endif %}
        </div>
    </div>
    {% endif %}

    <div class="footer">
        <p>Report generated by AI Testing Platform on {{ generated_at }}</p>
        <p>For questions or support, please contact your security team.</p>
    </div>
</body>
</html>
        '''
    
    def _get_pdf_template(self):
        """Get PDF-specific template (simplified HTML)"""
        return self._get_html_template()  # Use same template for now

