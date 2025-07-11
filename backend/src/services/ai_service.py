import json
import re
from datetime import datetime
from typing import Dict, List, Any
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

class AIService:
    def __init__(self):
        self.vulnerability_patterns = {
            'sql_injection': [
                'sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db',
                'sqlite_', 'postgresql', 'warning: mysql'
            ],
            'xss': [
                '<script>', 'javascript:', 'onerror=', 'onload=',
                'alert(', 'document.cookie'
            ],
            'directory_traversal': [
                '../', '..\\', '%2e%2e%2f', 'etc/passwd', 'windows/system32'
            ],
            'information_disclosure': [
                'phpinfo()', 'server version', 'debug mode', 'stack trace',
                'database error', 'exception'
            ]
        }
        
        self.security_recommendations = {
            'ssl_tls': [
                'Implement HTTPS with strong TLS configuration',
                'Use TLS 1.2 or higher',
                'Disable weak cipher suites',
                'Implement HSTS headers'
            ],
            'security_headers': [
                'Implement Content Security Policy (CSP)',
                'Add X-Frame-Options header',
                'Set X-Content-Type-Options to nosniff',
                'Configure Referrer-Policy header'
            ],
            'authentication': [
                'Implement multi-factor authentication',
                'Use strong password policies',
                'Implement account lockout mechanisms',
                'Regular password rotation'
            ],
            'access_control': [
                'Implement principle of least privilege',
                'Regular access reviews',
                'Role-based access control',
                'Segregation of duties'
            ]
        }
    
    def analyze_test_results(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze test results using AI to provide insights and recommendations"""
        try:
            analysis = {
                'timestamp': datetime.now().isoformat(),
                'overall_assessment': {},
                'risk_analysis': {},
                'recommendations': [],
                'priority_actions': [],
                'compliance_insights': {},
                'trend_analysis': {}
            }
            
            # Analyze web testing results
            if 'web_testing' in test_results:
                web_analysis = self._analyze_web_testing(test_results['web_testing'])
                analysis['web_testing_insights'] = web_analysis
            
            # Analyze security testing results
            if 'security_testing' in test_results:
                security_analysis = self._analyze_security_testing(test_results['security_testing'])
                analysis['security_insights'] = security_analysis
            
            # Analyze AWS audit results
            if 'aws_audit' in test_results:
                aws_analysis = self._analyze_aws_audit(test_results['aws_audit'])
                analysis['aws_insights'] = aws_analysis
            
            # Generate overall assessment
            analysis['overall_assessment'] = self._generate_overall_assessment(test_results)
            
            # Generate risk analysis
            analysis['risk_analysis'] = self._generate_risk_analysis(test_results)
            
            # Generate prioritized recommendations
            analysis['recommendations'] = self._generate_recommendations(test_results)
            
            # Generate priority actions
            analysis['priority_actions'] = self._generate_priority_actions(test_results)
            
            return analysis
            
        except Exception as e:
            return {'error': f'AI analysis failed: {str(e)}'}
    
    def _analyze_web_testing(self, web_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze web testing results"""
        if 'error' in web_results:
            return {'status': 'error', 'message': web_results['error']}
        
        insights = {
            'performance_insights': [],
            'seo_insights': [],
            'accessibility_insights': [],
            'overall_score': web_results.get('overall_score', 0)
        }
        
        tests = web_results.get('tests', {})
        
        # Performance analysis
        if 'performance' in tests:
            perf = tests['performance']
            load_time = perf.get('load_time', 0)
            
            if load_time > 3:
                insights['performance_insights'].append({
                    'type': 'critical',
                    'message': f'Page load time ({load_time}s) exceeds recommended 3 seconds',
                    'impact': 'High user abandonment rate, poor SEO ranking'
                })
            elif load_time > 2:
                insights['performance_insights'].append({
                    'type': 'warning',
                    'message': f'Page load time ({load_time}s) could be improved',
                    'impact': 'Moderate impact on user experience'
                })
            
            resource_count = perf.get('resource_count', {})
            if resource_count.get('images', 0) > 50:
                insights['performance_insights'].append({
                    'type': 'warning',
                    'message': f'High number of images ({resource_count["images"]}) detected',
                    'recommendation': 'Consider image optimization and lazy loading'
                })
        
        # SEO analysis
        if 'seo' in tests:
            seo = tests['seo']
            seo_score = seo.get('seo_score', 0)
            
            if seo_score < 70:
                insights['seo_insights'].append({
                    'type': 'critical',
                    'message': f'SEO score ({seo_score}) is below recommended threshold',
                    'impact': 'Poor search engine visibility'
                })
            
            issues = seo.get('issues', [])
            for issue in issues:
                insights['seo_insights'].append({
                    'type': 'warning',
                    'message': issue,
                    'category': 'SEO'
                })
        
        # Accessibility analysis
        if 'accessibility' in tests:
            acc = tests['accessibility']
            acc_score = acc.get('accessibility_score', 0)
            
            if acc_score < 80:
                insights['accessibility_insights'].append({
                    'type': 'critical',
                    'message': f'Accessibility score ({acc_score}) indicates compliance issues',
                    'impact': 'Legal compliance risk, poor user experience for disabled users'
                })
        
        return insights
    
    def _analyze_security_testing(self, security_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security testing results"""
        if 'error' in security_results:
            return {'status': 'error', 'message': security_results['error']}
        
        insights = {
            'vulnerability_analysis': [],
            'threat_assessment': {},
            'security_posture': {},
            'risk_score': security_results.get('security_score', 0)
        }
        
        security_tests = security_results.get('security_tests', {})
        
        # Analyze vulnerabilities
        critical_vulns = []
        high_vulns = []
        medium_vulns = []
        
        for test_name, test_result in security_tests.items():
            if isinstance(test_result, dict):
                vulns = test_result.get('vulnerabilities', [])
                for vuln in vulns:
                    severity = vuln.get('severity', 'Unknown')
                    if severity == 'Critical':
                        critical_vulns.append(vuln)
                    elif severity == 'High':
                        high_vulns.append(vuln)
                    elif severity == 'Medium':
                        medium_vulns.append(vuln)
        
        # Generate threat assessment
        insights['threat_assessment'] = {
            'critical_threats': len(critical_vulns),
            'high_threats': len(high_vulns),
            'medium_threats': len(medium_vulns),
            'overall_risk': self._calculate_threat_level(critical_vulns, high_vulns, medium_vulns)
        }
        
        # Analyze specific vulnerabilities
        if critical_vulns:
            insights['vulnerability_analysis'].append({
                'type': 'critical',
                'message': f'Found {len(critical_vulns)} critical vulnerabilities requiring immediate attention',
                'vulnerabilities': critical_vulns[:3]  # Show top 3
            })
        
        if high_vulns:
            insights['vulnerability_analysis'].append({
                'type': 'high',
                'message': f'Found {len(high_vulns)} high-severity vulnerabilities',
                'vulnerabilities': high_vulns[:3]  # Show top 3
            })
        
        # Security posture analysis
        ssl_status = security_tests.get('ssl_tls', {}).get('status', 'unknown')
        headers_status = security_tests.get('security_headers', {}).get('status', 'unknown')
        
        insights['security_posture'] = {
            'ssl_tls_grade': self._grade_ssl_status(ssl_status),
            'headers_grade': self._grade_headers_status(headers_status),
            'overall_grade': self._calculate_security_grade(security_results.get('security_score', 0))
        }
        
        return insights
    
    def _analyze_aws_audit(self, aws_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze AWS audit results"""
        if 'error' in aws_results:
            return {'status': 'error', 'message': aws_results['error']}
        
        insights = {
            'compliance_analysis': [],
            'security_gaps': [],
            'cost_optimization': [],
            'governance_insights': []
        }
        
        audit_results = aws_results.get('audit_results', {})
        compliance_score = aws_results.get('compliance_score', 0)
        
        # Analyze compliance
        if compliance_score < 80:
            insights['compliance_analysis'].append({
                'type': 'critical',
                'message': f'AWS compliance score ({compliance_score}%) below recommended 80%',
                'impact': 'Regulatory compliance risk'
            })
        
        # Analyze specific service findings
        for service, results in audit_results.items():
            if isinstance(results, dict) and 'findings' in results:
                findings = results['findings']
                critical_findings = [f for f in findings if f.get('status') == 'failed']
                
                if critical_findings:
                    insights['security_gaps'].append({
                        'service': service.upper(),
                        'critical_issues': len(critical_findings),
                        'top_issues': critical_findings[:3]
                    })
        
        # Generate governance insights
        insights['governance_insights'] = self._generate_governance_insights(audit_results)
        
        return insights
    
    def _generate_overall_assessment(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall assessment of all test results"""
        assessment = {
            'security_maturity': 'Unknown',
            'compliance_readiness': 'Unknown',
            'operational_excellence': 'Unknown',
            'overall_grade': 'Unknown',
            'key_strengths': [],
            'critical_weaknesses': []
        }
        
        scores = []
        
        # Collect scores from different tests
        if 'web_testing' in test_results and isinstance(test_results['web_testing'], dict):
            web_score = test_results['web_testing'].get('overall_score', 0)
            scores.append(web_score)
            
            if web_score > 80:
                assessment['key_strengths'].append('Strong web application performance and functionality')
            elif web_score < 60:
                assessment['critical_weaknesses'].append('Web application performance and functionality issues')
        
        if 'security_testing' in test_results and isinstance(test_results['security_testing'], dict):
            security_score = test_results['security_testing'].get('security_score', 0)
            scores.append(security_score)
            
            if security_score > 80:
                assessment['key_strengths'].append('Good security posture')
            elif security_score < 60:
                assessment['critical_weaknesses'].append('Significant security vulnerabilities')
        
        if 'aws_audit' in test_results and isinstance(test_results['aws_audit'], dict):
            aws_score = test_results['aws_audit'].get('compliance_score', 0)
            scores.append(aws_score)
            
            if aws_score > 80:
                assessment['key_strengths'].append('Strong AWS security and compliance')
            elif aws_score < 60:
                assessment['critical_weaknesses'].append('AWS security and compliance gaps')
        
        # Calculate overall grade
        if scores:
            avg_score = sum(scores) / len(scores)
            assessment['overall_grade'] = self._score_to_grade(avg_score)
            
            # Determine maturity levels
            assessment['security_maturity'] = self._determine_security_maturity(avg_score)
            assessment['compliance_readiness'] = self._determine_compliance_readiness(avg_score)
            assessment['operational_excellence'] = self._determine_operational_excellence(avg_score)
        
        return assessment
    
    def _generate_risk_analysis(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive risk analysis"""
        risk_analysis = {
            'risk_score': 0,
            'risk_level': 'Unknown',
            'business_impact': [],
            'technical_risks': [],
            'compliance_risks': [],
            'mitigation_priority': []
        }
        
        total_risk = 0
        risk_factors = 0
        
        # Analyze security risks
        if 'security_testing' in test_results and isinstance(test_results['security_testing'], dict):
            security_score = test_results['security_testing'].get('security_score', 100)
            security_risk = 100 - security_score
            total_risk += security_risk
            risk_factors += 1
            
            if security_risk > 40:
                risk_analysis['business_impact'].append({
                    'type': 'Data Breach Risk',
                    'probability': 'High',
                    'impact': 'Critical',
                    'description': 'Significant security vulnerabilities increase data breach risk'
                })
                
                risk_analysis['technical_risks'].append({
                    'type': 'System Compromise',
                    'severity': 'High',
                    'description': 'Multiple security vulnerabilities could lead to system compromise'
                })
        
        # Analyze compliance risks
        if 'aws_audit' in test_results and isinstance(test_results['aws_audit'], dict):
            compliance_score = test_results['aws_audit'].get('compliance_score', 100)
            compliance_risk = 100 - compliance_score
            total_risk += compliance_risk
            risk_factors += 1
            
            if compliance_risk > 30:
                risk_analysis['compliance_risks'].append({
                    'type': 'Regulatory Non-Compliance',
                    'severity': 'High',
                    'description': 'AWS configuration gaps may violate regulatory requirements'
                })
        
        # Calculate overall risk
        if risk_factors > 0:
            risk_analysis['risk_score'] = total_risk / risk_factors
            risk_analysis['risk_level'] = self._determine_risk_level(risk_analysis['risk_score'])
        
        # Generate mitigation priorities
        risk_analysis['mitigation_priority'] = self._generate_mitigation_priorities(test_results)
        
        return risk_analysis
    
    def _generate_recommendations(self, test_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate AI-powered recommendations"""
        recommendations = []
        
        # Security recommendations
        if 'security_testing' in test_results:
            security_recs = self._generate_security_recommendations(test_results['security_testing'])
            recommendations.extend(security_recs)
        
        # Performance recommendations
        if 'web_testing' in test_results:
            performance_recs = self._generate_performance_recommendations(test_results['web_testing'])
            recommendations.extend(performance_recs)
        
        # AWS recommendations
        if 'aws_audit' in test_results:
            aws_recs = self._generate_aws_recommendations(test_results['aws_audit'])
            recommendations.extend(aws_recs)
        
        # Sort by priority
        recommendations.sort(key=lambda x: x.get('priority', 5))
        
        return recommendations[:10]  # Return top 10 recommendations
    
    def _generate_priority_actions(self, test_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate priority actions based on test results"""
        actions = []
        
        # Critical security actions
        if 'security_testing' in test_results and isinstance(test_results['security_testing'], dict):
            security_tests = test_results['security_testing'].get('security_tests', {})
            
            for test_name, test_result in security_tests.items():
                if isinstance(test_result, dict):
                    vulns = test_result.get('vulnerabilities', [])
                    critical_vulns = [v for v in vulns if v.get('severity') == 'Critical']
                    
                    if critical_vulns:
                        actions.append({
                            'priority': 1,
                            'action': f'Address critical {test_name} vulnerabilities',
                            'timeline': 'Immediate (24-48 hours)',
                            'impact': 'Critical',
                            'effort': 'Medium'
                        })
        
        # High-impact performance actions
        if 'web_testing' in test_results and isinstance(test_results['web_testing'], dict):
            overall_score = test_results['web_testing'].get('overall_score', 100)
            
            if overall_score < 60:
                actions.append({
                    'priority': 2,
                    'action': 'Optimize website performance and functionality',
                    'timeline': '1-2 weeks',
                    'impact': 'High',
                    'effort': 'High'
                })
        
        # AWS compliance actions
        if 'aws_audit' in test_results and isinstance(test_results['aws_audit'], dict):
            compliance_score = test_results['aws_audit'].get('compliance_score', 100)
            
            if compliance_score < 70:
                actions.append({
                    'priority': 2,
                    'action': 'Remediate AWS security and compliance gaps',
                    'timeline': '2-4 weeks',
                    'impact': 'High',
                    'effort': 'Medium'
                })
        
        return sorted(actions, key=lambda x: x.get('priority', 5))[:5]
    
    # Helper methods
    def _calculate_threat_level(self, critical, high, medium):
        """Calculate overall threat level"""
        if critical:
            return 'Critical'
        elif len(high) > 2:
            return 'High'
        elif len(high) > 0 or len(medium) > 3:
            return 'Medium'
        else:
            return 'Low'
    
    def _grade_ssl_status(self, status):
        """Grade SSL status"""
        if status == 'passed':
            return 'A'
        elif status == 'warning':
            return 'B'
        else:
            return 'F'
    
    def _grade_headers_status(self, status):
        """Grade security headers status"""
        if status == 'passed':
            return 'A'
        elif status == 'warning':
            return 'C'
        else:
            return 'F'
    
    def _calculate_security_grade(self, score):
        """Calculate security grade from score"""
        if score >= 90:
            return 'A+'
        elif score >= 80:
            return 'A'
        elif score >= 70:
            return 'B'
        elif score >= 60:
            return 'C'
        else:
            return 'F'
    
    def _score_to_grade(self, score):
        """Convert numeric score to letter grade"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def _determine_security_maturity(self, score):
        """Determine security maturity level"""
        if score >= 85:
            return 'Advanced'
        elif score >= 70:
            return 'Intermediate'
        elif score >= 50:
            return 'Basic'
        else:
            return 'Initial'
    
    def _determine_compliance_readiness(self, score):
        """Determine compliance readiness"""
        if score >= 80:
            return 'Ready'
        elif score >= 60:
            return 'Partially Ready'
        else:
            return 'Not Ready'
    
    def _determine_operational_excellence(self, score):
        """Determine operational excellence level"""
        if score >= 85:
            return 'Excellent'
        elif score >= 70:
            return 'Good'
        elif score >= 50:
            return 'Fair'
        else:
            return 'Poor'
    
    def _determine_risk_level(self, risk_score):
        """Determine risk level from score"""
        if risk_score >= 70:
            return 'Critical'
        elif risk_score >= 50:
            return 'High'
        elif risk_score >= 30:
            return 'Medium'
        else:
            return 'Low'
    
    def _generate_security_recommendations(self, security_results):
        """Generate security-specific recommendations"""
        recommendations = []
        
        if isinstance(security_results, dict):
            security_score = security_results.get('security_score', 100)
            
            if security_score < 70:
                recommendations.append({
                    'category': 'Security',
                    'title': 'Implement comprehensive security controls',
                    'description': 'Address identified vulnerabilities and implement security best practices',
                    'priority': 1,
                    'effort': 'High',
                    'impact': 'Critical'
                })
        
        return recommendations
    
    def _generate_performance_recommendations(self, web_results):
        """Generate performance-specific recommendations"""
        recommendations = []
        
        if isinstance(web_results, dict):
            overall_score = web_results.get('overall_score', 100)
            
            if overall_score < 70:
                recommendations.append({
                    'category': 'Performance',
                    'title': 'Optimize website performance',
                    'description': 'Improve page load times and user experience',
                    'priority': 2,
                    'effort': 'Medium',
                    'impact': 'High'
                })
        
        return recommendations
    
    def _generate_aws_recommendations(self, aws_results):
        """Generate AWS-specific recommendations"""
        recommendations = []
        
        if isinstance(aws_results, dict):
            compliance_score = aws_results.get('compliance_score', 100)
            
            if compliance_score < 80:
                recommendations.append({
                    'category': 'AWS Security',
                    'title': 'Improve AWS security posture',
                    'description': 'Address AWS security and compliance findings',
                    'priority': 2,
                    'effort': 'Medium',
                    'impact': 'High'
                })
        
        return recommendations
    
    def _generate_mitigation_priorities(self, test_results):
        """Generate mitigation priorities"""
        priorities = []
        
        # Add critical security issues first
        if 'security_testing' in test_results:
            priorities.append({
                'priority': 1,
                'category': 'Security',
                'action': 'Address critical security vulnerabilities',
                'justification': 'Immediate threat to system security'
            })
        
        return priorities
    
    def _generate_governance_insights(self, audit_results):
        """Generate governance insights from AWS audit"""
        insights = []
        
        for service, results in audit_results.items():
            if isinstance(results, dict) and 'findings' in results:
                findings = results['findings']
                if findings:
                    insights.append({
                        'service': service,
                        'governance_gap': f'Found {len(findings)} governance issues in {service.upper()}',
                        'recommendation': f'Implement proper {service.upper()} governance controls'
                    })
        
        return insights

