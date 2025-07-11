import asyncio
import time
from datetime import datetime
from playwright.async_api import async_playwright
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import requests
from bs4 import BeautifulSoup
import json

class WebTestingService:
    def __init__(self):
        self.results = {}
        
    def run_comprehensive_test(self, url):
        """Run comprehensive web testing including performance, accessibility, and functionality"""
        try:
            results = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'tests': {}
            }
            
            # Basic connectivity test
            results['tests']['connectivity'] = self._test_connectivity(url)
            
            # Performance testing
            results['tests']['performance'] = self._test_performance(url)
            
            # SEO and metadata testing
            results['tests']['seo'] = self._test_seo(url)
            
            # Accessibility testing
            results['tests']['accessibility'] = self._test_accessibility(url)
            
            # Responsive design testing
            results['tests']['responsive'] = self._test_responsive_design(url)
            
            # Form testing (if forms are present)
            results['tests']['forms'] = self._test_forms(url)
            
            # Link testing
            results['tests']['links'] = self._test_links(url)
            
            # JavaScript errors testing
            results['tests']['javascript'] = self._test_javascript_errors(url)
            
            # Overall score calculation
            results['overall_score'] = self._calculate_overall_score(results['tests'])
            
            return results
            
        except Exception as e:
            return {'error': f'Web testing failed: {str(e)}'}
    
    def _test_connectivity(self, url):
        """Test basic connectivity and response"""
        try:
            start_time = time.time()
            response = requests.get(url, timeout=30)
            response_time = time.time() - start_time
            
            return {
                'status': 'passed' if response.status_code == 200 else 'failed',
                'status_code': response.status_code,
                'response_time': round(response_time, 2),
                'headers': dict(response.headers),
                'content_length': len(response.content)
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _test_performance(self, url):
        """Test website performance metrics"""
        try:
            # Use requests for basic timing
            start_time = time.time()
            response = requests.get(url, timeout=30)
            load_time = time.time() - start_time
            
            # Analyze page size and resources
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Count resources
            images = len(soup.find_all('img'))
            scripts = len(soup.find_all('script'))
            stylesheets = len(soup.find_all('link', rel='stylesheet'))
            
            # Performance score based on load time and resource count
            performance_score = 100
            if load_time > 3:
                performance_score -= 30
            elif load_time > 2:
                performance_score -= 15
            elif load_time > 1:
                performance_score -= 5
                
            if images > 50:
                performance_score -= 10
            if scripts > 20:
                performance_score -= 10
            if stylesheets > 10:
                performance_score -= 5
            
            return {
                'status': 'passed' if performance_score > 70 else 'warning' if performance_score > 50 else 'failed',
                'load_time': round(load_time, 2),
                'page_size': len(response.content),
                'resource_count': {
                    'images': images,
                    'scripts': scripts,
                    'stylesheets': stylesheets
                },
                'performance_score': max(0, performance_score),
                'recommendations': self._get_performance_recommendations(load_time, images, scripts)
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _test_seo(self, url):
        """Test SEO elements and metadata"""
        try:
            response = requests.get(url, timeout=30)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            seo_score = 100
            issues = []
            
            # Check title tag
            title = soup.find('title')
            if not title or not title.text.strip():
                seo_score -= 20
                issues.append('Missing or empty title tag')
            elif len(title.text) > 60:
                seo_score -= 10
                issues.append('Title tag too long (>60 characters)')
            
            # Check meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if not meta_desc or not meta_desc.get('content'):
                seo_score -= 15
                issues.append('Missing meta description')
            elif len(meta_desc.get('content', '')) > 160:
                seo_score -= 5
                issues.append('Meta description too long (>160 characters)')
            
            # Check heading structure
            h1_tags = soup.find_all('h1')
            if len(h1_tags) == 0:
                seo_score -= 15
                issues.append('Missing H1 tag')
            elif len(h1_tags) > 1:
                seo_score -= 10
                issues.append('Multiple H1 tags found')
            
            # Check alt attributes on images
            images = soup.find_all('img')
            images_without_alt = [img for img in images if not img.get('alt')]
            if images_without_alt:
                seo_score -= min(20, len(images_without_alt) * 2)
                issues.append(f'{len(images_without_alt)} images missing alt attributes')
            
            return {
                'status': 'passed' if seo_score > 80 else 'warning' if seo_score > 60 else 'failed',
                'seo_score': max(0, seo_score),
                'title': title.text.strip() if title else None,
                'meta_description': meta_desc.get('content') if meta_desc else None,
                'h1_count': len(h1_tags),
                'images_without_alt': len(images_without_alt),
                'issues': issues
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _test_accessibility(self, url):
        """Test basic accessibility features"""
        try:
            response = requests.get(url, timeout=30)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            accessibility_score = 100
            issues = []
            
            # Check for alt attributes on images
            images = soup.find_all('img')
            images_without_alt = [img for img in images if not img.get('alt')]
            if images_without_alt:
                accessibility_score -= min(30, len(images_without_alt) * 3)
                issues.append(f'{len(images_without_alt)} images missing alt text')
            
            # Check for form labels
            inputs = soup.find_all('input', type=['text', 'email', 'password', 'tel'])
            inputs_without_labels = []
            for input_elem in inputs:
                input_id = input_elem.get('id')
                if not input_id or not soup.find('label', attrs={'for': input_id}):
                    inputs_without_labels.append(input_elem)
            
            if inputs_without_labels:
                accessibility_score -= min(20, len(inputs_without_labels) * 5)
                issues.append(f'{len(inputs_without_labels)} form inputs missing labels')
            
            # Check for heading hierarchy
            headings = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
            if headings:
                heading_levels = [int(h.name[1]) for h in headings]
                if heading_levels and heading_levels[0] != 1:
                    accessibility_score -= 10
                    issues.append('Page does not start with H1')
            
            # Check for lang attribute
            html_tag = soup.find('html')
            if not html_tag or not html_tag.get('lang'):
                accessibility_score -= 10
                issues.append('Missing lang attribute on html element')
            
            return {
                'status': 'passed' if accessibility_score > 80 else 'warning' if accessibility_score > 60 else 'failed',
                'accessibility_score': max(0, accessibility_score),
                'issues': issues,
                'recommendations': ['Add alt text to images', 'Ensure proper form labeling', 'Maintain heading hierarchy']
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _test_responsive_design(self, url):
        """Test responsive design using different viewport sizes"""
        try:
            # This would ideally use Playwright for better testing
            # For now, check for viewport meta tag and CSS media queries
            response = requests.get(url, timeout=30)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            responsive_score = 100
            issues = []
            
            # Check for viewport meta tag
            viewport_meta = soup.find('meta', attrs={'name': 'viewport'})
            if not viewport_meta:
                responsive_score -= 30
                issues.append('Missing viewport meta tag')
            
            # Check for CSS media queries (basic check)
            style_tags = soup.find_all('style')
            link_tags = soup.find_all('link', rel='stylesheet')
            
            has_media_queries = False
            for style in style_tags:
                if '@media' in style.text:
                    has_media_queries = True
                    break
            
            if not has_media_queries:
                responsive_score -= 20
                issues.append('No CSS media queries detected')
            
            return {
                'status': 'passed' if responsive_score > 70 else 'warning' if responsive_score > 50 else 'failed',
                'responsive_score': max(0, responsive_score),
                'has_viewport_meta': bool(viewport_meta),
                'has_media_queries': has_media_queries,
                'issues': issues
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _test_forms(self, url):
        """Test form functionality and validation"""
        try:
            response = requests.get(url, timeout=30)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            forms = soup.find_all('form')
            if not forms:
                return {'status': 'skipped', 'message': 'No forms found on the page'}
            
            form_issues = []
            for i, form in enumerate(forms):
                form_analysis = {
                    'form_index': i,
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': len(form.find_all('input')),
                    'has_submit': bool(form.find('input', type='submit') or form.find('button', type='submit')),
                    'issues': []
                }
                
                # Check for CSRF protection (basic check)
                csrf_input = form.find('input', attrs={'name': lambda x: x and 'csrf' in x.lower()})
                if not csrf_input:
                    form_analysis['issues'].append('No CSRF token detected')
                
                # Check for required fields
                required_inputs = form.find_all('input', required=True)
                form_analysis['required_fields'] = len(required_inputs)
                
                form_issues.append(form_analysis)
            
            return {
                'status': 'passed' if all(not form['issues'] for form in form_issues) else 'warning',
                'forms_count': len(forms),
                'forms_analysis': form_issues
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _test_links(self, url):
        """Test internal and external links"""
        try:
            response = requests.get(url, timeout=30)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            links = soup.find_all('a', href=True)
            if not links:
                return {'status': 'skipped', 'message': 'No links found on the page'}
            
            internal_links = []
            external_links = []
            broken_links = []
            
            base_domain = requests.utils.urlparse(url).netloc
            
            for link in links[:20]:  # Limit to first 20 links to avoid long execution
                href = link['href']
                
                # Skip javascript and mailto links
                if href.startswith(('javascript:', 'mailto:', 'tel:')):
                    continue
                
                # Convert relative URLs to absolute
                if href.startswith('/'):
                    full_url = f"{requests.utils.urlparse(url).scheme}://{base_domain}{href}"
                elif not href.startswith('http'):
                    full_url = f"{url.rstrip('/')}/{href}"
                else:
                    full_url = href
                
                # Categorize as internal or external
                link_domain = requests.utils.urlparse(full_url).netloc
                if link_domain == base_domain:
                    internal_links.append(full_url)
                else:
                    external_links.append(full_url)
                
                # Test if link is accessible (quick check)
                try:
                    link_response = requests.head(full_url, timeout=5)
                    if link_response.status_code >= 400:
                        broken_links.append({'url': full_url, 'status_code': link_response.status_code})
                except:
                    broken_links.append({'url': full_url, 'status_code': 'timeout/error'})
            
            return {
                'status': 'passed' if not broken_links else 'warning',
                'total_links': len(links),
                'internal_links': len(internal_links),
                'external_links': len(external_links),
                'broken_links': broken_links,
                'tested_links': len(internal_links) + len(external_links)
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _test_javascript_errors(self, url):
        """Test for JavaScript errors using Selenium"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            
            driver = webdriver.Chrome(options=chrome_options)
            driver.get(url)
            
            # Wait for page to load
            WebDriverWait(driver, 10).until(
                lambda d: d.execute_script('return document.readyState') == 'complete'
            )
            
            # Get console logs
            logs = driver.get_log('browser')
            js_errors = [log for log in logs if log['level'] == 'SEVERE']
            
            driver.quit()
            
            return {
                'status': 'passed' if not js_errors else 'warning',
                'js_errors_count': len(js_errors),
                'js_errors': js_errors[:5],  # Limit to first 5 errors
                'console_logs_count': len(logs)
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _get_performance_recommendations(self, load_time, images, scripts):
        """Generate performance recommendations"""
        recommendations = []
        
        if load_time > 3:
            recommendations.append('Optimize server response time')
            recommendations.append('Enable compression (gzip/brotli)')
        
        if images > 30:
            recommendations.append('Optimize and compress images')
            recommendations.append('Consider lazy loading for images')
        
        if scripts > 15:
            recommendations.append('Minimize and combine JavaScript files')
            recommendations.append('Consider async/defer loading for scripts')
        
        return recommendations
    
    def _calculate_overall_score(self, tests):
        """Calculate overall score based on all test results"""
        scores = []
        
        for test_name, test_result in tests.items():
            if isinstance(test_result, dict) and 'status' in test_result:
                if test_result['status'] == 'passed':
                    scores.append(100)
                elif test_result['status'] == 'warning':
                    scores.append(70)
                elif test_result['status'] == 'failed':
                    scores.append(30)
                # Skip 'skipped' tests
        
        return round(sum(scores) / len(scores)) if scores else 0

