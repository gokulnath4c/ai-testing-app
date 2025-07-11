# AI Testing Platform - Technical Documentation

## Architecture Overview

The AI Testing Platform is built as a modern web application with a clear separation between frontend and backend components, designed for scalability, maintainability, and extensibility.

### System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Frontend │    │  Flask Backend  │    │  External APIs  │
│                 │    │                 │    │                 │
│  - User Interface│◄──►│  - REST API     │◄──►│  - Target URLs  │
│  - Test Config  │    │  - Test Engine  │    │  - AWS Services │
│  - Results View │    │  - AI Analysis  │    │  - Security DBs │
│  - Report Gen   │    │  - Report Gen   │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Browser   │    │  File System    │    │  Network Layer  │
│                 │    │                 │    │                 │
│  - HTML/CSS/JS  │    │  - Reports      │    │  - HTTP/HTTPS   │
│  - Local Storage│    │  - Temp Files   │    │  - SSL/TLS      │
│  - Session Mgmt │    │  - Logs         │    │  - DNS          │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Technology Stack

**Frontend**
- **React 18**: Modern UI framework with hooks and functional components
- **React Router**: Client-side routing and navigation
- **Tailwind CSS**: Utility-first CSS framework for styling
- **Vite**: Fast build tool and development server
- **JavaScript ES6+**: Modern JavaScript features and syntax

**Backend**
- **Flask 2.3**: Lightweight Python web framework
- **Flask-CORS**: Cross-origin resource sharing support
- **Python 3.11**: Modern Python runtime with type hints
- **Asyncio**: Asynchronous programming for concurrent operations
- **Requests**: HTTP library for external API calls

**Testing Libraries**
- **Playwright**: Browser automation and testing
- **BeautifulSoup4**: HTML parsing and analysis
- **python-nmap**: Network scanning capabilities
- **Boto3**: AWS SDK for cloud security auditing
- **OpenAI**: AI-powered analysis and insights

**Report Generation**
- **Jinja2**: Template engine for HTML reports
- **WeasyPrint**: HTML to PDF conversion
- **FPDF2**: Direct PDF generation
- **JSON**: Structured data export

## Project Structure

```
ai-testing-app/
├── backend/                    # Flask backend application
│   ├── src/                   # Source code
│   │   ├── main.py           # Application entry point
│   │   ├── routes/           # API route definitions
│   │   │   └── testing.py    # Testing endpoints
│   │   ├── services/         # Business logic services
│   │   │   ├── web_testing_service.py      # Web testing logic
│   │   │   ├── security_testing_service.py # Security testing
│   │   │   ├── aws_audit_service.py        # AWS auditing
│   │   │   ├── ai_service.py              # AI analysis
│   │   │   └── report_service.py          # Report generation
│   │   ├── static/           # Static files (built frontend)
│   │   └── templates/        # Jinja2 templates
│   ├── venv/                 # Python virtual environment
│   ├── requirements.txt      # Python dependencies
│   └── README.md            # Backend documentation
├── frontend/                 # React frontend application
│   ├── src/                 # Source code
│   │   ├── App.jsx          # Main application component
│   │   ├── components/      # React components
│   │   │   ├── Header.jsx           # Navigation header
│   │   │   ├── Dashboard.jsx        # Main dashboard
│   │   │   ├── TestConfiguration.jsx # Test setup
│   │   │   ├── TestResults.jsx      # Results display
│   │   │   └── Reports.jsx          # Report management
│   │   ├── hooks/           # Custom React hooks
│   │   │   └── use-toast.js # Toast notifications
│   │   └── components/ui/   # UI components
│   │       └── toaster.jsx  # Toast component
│   ├── public/              # Public assets
│   ├── dist/                # Built frontend files
│   ├── package.json         # Node.js dependencies
│   └── vite.config.js       # Vite configuration
├── docs/                    # Documentation
│   └── architecture_design.md # System architecture
├── tests/                   # Test files
├── scripts/                 # Utility scripts
├── DEPLOYMENT_GUIDE.md      # Deployment instructions
├── USER_MANUAL.md          # User documentation
├── TECHNICAL_DOCUMENTATION.md # This file
└── README.md               # Project overview
```

## Backend API Reference

### Base URL
```
http://localhost:5000/api
```

### Authentication
Currently, the API does not require authentication. For production deployment, implement appropriate authentication mechanisms.

### Endpoints

#### Start Test
```http
POST /test/start
Content-Type: application/json

{
    "url": "https://example.com",
    "test_types": ["web", "security", "aws"],
    "aws_config": {
        "accessKey": "AKIA...",
        "secretKey": "...",
        "region": "us-east-1"
    }
}
```

**Response:**
```json
{
    "test_id": "test_20250708_104906",
    "status": "completed",
    "message": "Test completed successfully"
}
```

#### Get Test Results
```http
GET /test/results/{test_id}
```

**Response:**
```json
{
    "test_id": "test_20250708_104906",
    "url": "https://example.com",
    "timestamp": "2025-07-08T10:49:06.123456",
    "status": "completed",
    "overall_score": 74,
    "results": {
        "web_testing": { ... },
        "security_testing": { ... },
        "aws_audit": { ... }
    },
    "ai_insights": { ... }
}
```

#### Generate Report
```http
GET /test/report/{test_id}?format=html|pdf|json
```

**Response:**
```json
{
    "format": "html",
    "filename": "report_test_20250708_104906_20250708_104919.html",
    "filepath": "/tmp/report_test_20250708_104906_20250708_104919.html",
    "download_url": "/api/test/download/report_test_20250708_104906_20250708_104919.html"
}
```

#### Download Report
```http
GET /test/download/{filename}
```

Returns the file for download with appropriate headers.

#### Get Test Status
```http
GET /test/status/{test_id}
```

**Response:**
```json
{
    "test_id": "test_20250708_104906",
    "status": "completed",
    "progress": 100
}
```

### Error Responses

All endpoints return appropriate HTTP status codes and error messages:

```json
{
    "error": "Description of the error"
}
```

Common status codes:
- `200`: Success
- `400`: Bad Request (invalid parameters)
- `404`: Not Found (test ID not found)
- `500`: Internal Server Error

## Service Architecture

### Web Testing Service

**Purpose**: Analyzes web application performance, SEO, accessibility, and functionality.

**Key Methods**:
- `run_comprehensive_test(url)`: Main entry point for web testing
- `_test_performance(page)`: Measures load times and resource usage
- `_test_seo(page)`: Evaluates SEO metadata and structure
- `_test_accessibility(page)`: Checks accessibility compliance
- `_test_responsive_design(page)`: Validates mobile responsiveness

**Dependencies**:
- Playwright for browser automation
- BeautifulSoup4 for HTML parsing
- Custom scoring algorithms

**Output Format**:
```json
{
    "overall_score": 85,
    "tests": {
        "performance": {
            "status": "passed",
            "load_time": 2.34,
            "performance_score": 78,
            "resource_count": { ... }
        },
        "seo": { ... },
        "accessibility": { ... }
    }
}
```

### Security Testing Service

**Purpose**: Performs comprehensive security analysis including vulnerability scanning and penetration testing.

**Key Methods**:
- `run_security_test(url)`: Main entry point for security testing
- `_test_ssl_tls(domain)`: SSL/TLS configuration analysis
- `_test_security_headers(url)`: HTTP security header validation
- `_test_common_vulnerabilities(url)`: XSS, SQL injection, etc.
- `_test_open_ports(domain)`: Network port scanning

**Security Tests Performed**:
1. **SSL/TLS Analysis**
   - Certificate validation and expiry
   - Cipher suite strength
   - Protocol version support
   - Certificate chain verification

2. **Security Headers**
   - Strict-Transport-Security
   - Content-Security-Policy
   - X-Frame-Options
   - X-Content-Type-Options
   - X-XSS-Protection
   - Referrer-Policy

3. **Vulnerability Scanning**
   - Cross-Site Scripting (XSS)
   - SQL Injection
   - Directory Traversal
   - Information Disclosure
   - Clickjacking

4. **Network Analysis**
   - Open port detection
   - Service enumeration
   - Banner grabbing

**Output Format**:
```json
{
    "security_score": 65,
    "risk_level": "Medium",
    "security_tests": {
        "ssl_tls": { ... },
        "security_headers": { ... },
        "vulnerabilities": { ... }
    }
}
```

### AWS Audit Service

**Purpose**: Evaluates AWS cloud infrastructure security and compliance.

**Key Methods**:
- `run_audit(aws_config)`: Main entry point for AWS auditing
- `_audit_iam_policies()`: IAM permission analysis
- `_audit_s3_buckets()`: S3 security configuration
- `_audit_ec2_instances()`: EC2 security assessment
- `_check_compliance()`: Compliance framework validation

**AWS Services Audited**:
1. **Identity and Access Management (IAM)**
   - User permissions and policies
   - Role assignments and trust relationships
   - Multi-factor authentication status
   - Password policies and rotation

2. **Simple Storage Service (S3)**
   - Bucket permissions and ACLs
   - Public access configuration
   - Encryption settings
   - Versioning and lifecycle policies

3. **Elastic Compute Cloud (EC2)**
   - Security group configurations
   - Instance metadata access
   - EBS encryption status
   - Network access controls

4. **CloudTrail and Logging**
   - Audit trail configuration
   - Log retention policies
   - Event monitoring setup

**Output Format**:
```json
{
    "compliance_score": 78,
    "findings": {
        "iam": { ... },
        "s3": { ... },
        "ec2": { ... }
    },
    "recommendations": [ ... ]
}
```

### AI Service

**Purpose**: Provides intelligent analysis and actionable recommendations based on test results.

**Key Methods**:
- `analyze_test_results(results)`: Main analysis entry point
- `_generate_overall_assessment()`: Comprehensive evaluation
- `_generate_recommendations()`: Actionable improvement suggestions
- `_prioritize_findings()`: Risk-based prioritization

**AI Analysis Components**:
1. **Pattern Recognition**
   - Common vulnerability patterns
   - Performance bottleneck identification
   - Security misconfigurations

2. **Risk Assessment**
   - CVSS-based scoring
   - Business impact analysis
   - Exploitability assessment

3. **Recommendation Engine**
   - Prioritized action items
   - Implementation guidance
   - Effort and impact estimation

4. **Trend Analysis**
   - Historical comparison
   - Improvement tracking
   - Regression detection

**Output Format**:
```json
{
    "overall_assessment": {
        "overall_grade": "B",
        "security_maturity": "Intermediate",
        "key_strengths": [ ... ],
        "critical_weaknesses": [ ... ]
    },
    "recommendations": [
        {
            "title": "Implement Content Security Policy",
            "description": "...",
            "category": "Security",
            "priority": 1,
            "effort": "Medium",
            "impact": "High"
        }
    ]
}
```

### Report Service

**Purpose**: Generates comprehensive reports in multiple formats.

**Key Methods**:
- `generate_report(test_results, format)`: Main report generation
- `_generate_html_report()`: HTML report with styling
- `_generate_pdf_report()`: PDF document generation
- `_generate_json_report()`: Structured data export

**Report Features**:
1. **Professional Styling**
   - Responsive HTML design
   - Print-optimized PDF layout
   - Corporate branding support

2. **Comprehensive Content**
   - Executive summary
   - Detailed findings
   - AI insights and recommendations
   - Technical appendices

3. **Multiple Formats**
   - Interactive HTML reports
   - Print-ready PDF documents
   - Machine-readable JSON data

## Database Schema

Currently, the application uses in-memory storage for test results. For production deployment, implement a proper database schema:

### Recommended Tables

**tests**
```sql
CREATE TABLE tests (
    id VARCHAR(50) PRIMARY KEY,
    url VARCHAR(500) NOT NULL,
    test_types JSON,
    status VARCHAR(20),
    created_at TIMESTAMP,
    completed_at TIMESTAMP,
    overall_score INTEGER
);
```

**test_results**
```sql
CREATE TABLE test_results (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    test_id VARCHAR(50) REFERENCES tests(id),
    category VARCHAR(50),
    results JSON,
    created_at TIMESTAMP
);
```

**reports**
```sql
CREATE TABLE reports (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    test_id VARCHAR(50) REFERENCES tests(id),
    format VARCHAR(10),
    filename VARCHAR(200),
    filepath VARCHAR(500),
    created_at TIMESTAMP
);
```

## Configuration Management

### Environment Variables

Create a `.env` file in the backend directory:

```env
# Flask Configuration
FLASK_ENV=production
FLASK_DEBUG=False
SECRET_KEY=your-secret-key-here
PORT=5000

# Database Configuration (if using external database)
DATABASE_URL=postgresql://user:password@localhost/ai_testing

# AWS Configuration (optional)
AWS_DEFAULT_REGION=us-east-1

# AI Service Configuration
OPENAI_API_KEY=your-openai-key-here

# Security Configuration
CORS_ORIGINS=http://localhost:3000,http://localhost:5173

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=/var/log/ai-testing-platform.log
```

### Configuration Classes

```python
# config.py
import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False
    
class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    
class TestingConfig(Config):
    DEBUG = True
    TESTING = True

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
```

## Security Considerations

### Input Validation

All user inputs are validated to prevent injection attacks:

```python
def validate_url(url):
    """Validate URL format and security"""
    if not url or not isinstance(url, str):
        raise ValueError("URL is required")
    
    # Check URL format
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid URL format")
    
    # Security checks
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("Only HTTP/HTTPS URLs are allowed")
    
    # Prevent internal network access
    if parsed.netloc in ['localhost', '127.0.0.1', '0.0.0.0']:
        raise ValueError("Internal URLs are not allowed")
    
    return url
```

### Rate Limiting

Implement rate limiting to prevent abuse:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

@app.route('/api/test/start', methods=['POST'])
@limiter.limit("10 per minute")
def start_test():
    # Test logic here
    pass
```

### Data Protection

- Sanitize all outputs to prevent XSS
- Use HTTPS in production
- Implement proper session management
- Secure file upload and download mechanisms

### AWS Credentials Security

- Never log AWS credentials
- Use IAM roles when possible
- Implement credential rotation
- Validate permissions before use

## Performance Optimization

### Backend Optimization

1. **Asynchronous Processing**
```python
import asyncio
from concurrent.futures import ThreadPoolExecutor

async def run_tests_async(url, test_types):
    """Run tests concurrently for better performance"""
    loop = asyncio.get_event_loop()
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        tasks = []
        
        if 'web' in test_types:
            tasks.append(loop.run_in_executor(
                executor, web_service.run_comprehensive_test, url
            ))
        
        if 'security' in test_types:
            tasks.append(loop.run_in_executor(
                executor, security_service.run_security_test, url
            ))
        
        results = await asyncio.gather(*tasks)
        return results
```

2. **Caching Strategy**
```python
from functools import lru_cache
import redis

# In-memory caching for DNS lookups
@lru_cache(maxsize=1000)
def resolve_domain(domain):
    return socket.gethostbyname(domain)

# Redis caching for test results
redis_client = redis.Redis(host='localhost', port=6379, db=0)

def cache_test_result(test_id, results):
    redis_client.setex(
        f"test:{test_id}", 
        timedelta(hours=24), 
        json.dumps(results)
    )
```

3. **Database Optimization**
- Use connection pooling
- Implement proper indexing
- Use prepared statements
- Optimize query patterns

### Frontend Optimization

1. **Code Splitting**
```javascript
// Lazy load components
const TestResults = lazy(() => import('./components/TestResults'));
const Reports = lazy(() => import('./components/Reports'));

// Use Suspense for loading states
<Suspense fallback={<LoadingSpinner />}>
  <TestResults />
</Suspense>
```

2. **State Management**
```javascript
// Use React Context for global state
const AppContext = createContext();

export const AppProvider = ({ children }) => {
  const [tests, setTests] = useState([]);
  const [currentTest, setCurrentTest] = useState(null);
  
  return (
    <AppContext.Provider value={{ tests, setTests, currentTest, setCurrentTest }}>
      {children}
    </AppContext.Provider>
  );
};
```

3. **Performance Monitoring**
```javascript
// Monitor component performance
import { Profiler } from 'react';

function onRenderCallback(id, phase, actualDuration) {
  console.log('Component:', id, 'Phase:', phase, 'Duration:', actualDuration);
}

<Profiler id="TestConfiguration" onRender={onRenderCallback}>
  <TestConfiguration />
</Profiler>
```

## Testing Strategy

### Backend Testing

```python
# test_web_testing_service.py
import unittest
from unittest.mock import patch, MagicMock
from src.services.web_testing_service import WebTestingService

class TestWebTestingService(unittest.TestCase):
    def setUp(self):
        self.service = WebTestingService()
    
    @patch('playwright.sync_api.sync_playwright')
    def test_run_comprehensive_test(self, mock_playwright):
        # Mock Playwright browser
        mock_page = MagicMock()
        mock_page.goto.return_value = None
        mock_page.evaluate.return_value = 1000
        
        # Test the service
        result = self.service.run_comprehensive_test('https://example.com')
        
        # Assertions
        self.assertIn('overall_score', result)
        self.assertIn('tests', result)
        self.assertTrue(0 <= result['overall_score'] <= 100)
```

### Frontend Testing

```javascript
// TestConfiguration.test.jsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import TestConfiguration from '../components/TestConfiguration';

const renderWithRouter = (component) => {
  return render(
    <BrowserRouter>
      {component}
    </BrowserRouter>
  );
};

describe('TestConfiguration', () => {
  test('validates URL input', async () => {
    renderWithRouter(<TestConfiguration />);
    
    const urlInput = screen.getByPlaceholderText('https://example.com');
    const startButton = screen.getByText('Start Test');
    
    // Test invalid URL
    fireEvent.change(urlInput, { target: { value: 'invalid-url' } });
    fireEvent.click(startButton);
    
    await waitFor(() => {
      expect(screen.getByText('Please enter a valid URL')).toBeInTheDocument();
    });
  });
});
```

### Integration Testing

```python
# test_api_integration.py
import unittest
import json
from src.main import app

class TestAPIIntegration(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
    
    def test_start_test_endpoint(self):
        # Test data
        test_data = {
            'url': 'https://example.com',
            'test_types': ['web', 'security']
        }
        
        # Make request
        response = self.app.post(
            '/api/test/start',
            data=json.dumps(test_data),
            content_type='application/json'
        )
        
        # Assertions
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('test_id', data)
        self.assertIn('status', data)
```

## Monitoring and Logging

### Application Logging

```python
import logging
from logging.handlers import RotatingFileHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)

# File handler with rotation
file_handler = RotatingFileHandler(
    'logs/ai-testing-platform.log',
    maxBytes=10485760,  # 10MB
    backupCount=5
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s %(name)s %(message)s'
))

app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# Usage in services
logger = logging.getLogger(__name__)

def run_security_test(self, url):
    logger.info(f"Starting security test for {url}")
    try:
        # Test logic
        logger.info(f"Security test completed for {url}")
    except Exception as e:
        logger.error(f"Security test failed for {url}: {str(e)}")
        raise
```

### Performance Monitoring

```python
import time
from functools import wraps

def monitor_performance(func):
    """Decorator to monitor function performance"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            logger.info(f"{func.__name__} completed in {duration:.2f}s")
            return result
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"{func.__name__} failed after {duration:.2f}s: {str(e)}")
            raise
    return wrapper

@monitor_performance
def run_comprehensive_test(self, url):
    # Test implementation
    pass
```

### Health Checks

```python
@app.route('/health')
def health_check():
    """Application health check endpoint"""
    try:
        # Check database connectivity
        # Check external service availability
        # Check disk space
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 503
```

## Deployment Considerations

### Production Deployment

1. **Web Server Configuration**
```nginx
# nginx.conf
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /static {
        alias /path/to/ai-testing-app/backend/src/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

2. **Process Management**
```ini
# supervisord.conf
[program:ai-testing-platform]
command=/path/to/ai-testing-app/backend/venv/bin/python src/main.py
directory=/path/to/ai-testing-app/backend
user=www-data
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/ai-testing-platform.log
```

3. **Environment Setup**
```bash
#!/bin/bash
# deploy.sh

# Update system packages
sudo apt update && sudo apt upgrade -y

# Install system dependencies
sudo apt install -y python3 python3-pip python3-venv nodejs npm nginx

# Create application user
sudo useradd -m -s /bin/bash ai-testing

# Set up application directory
sudo mkdir -p /opt/ai-testing-platform
sudo chown ai-testing:ai-testing /opt/ai-testing-platform

# Copy application files
sudo cp -r ai-testing-app/* /opt/ai-testing-platform/
sudo chown -R ai-testing:ai-testing /opt/ai-testing-platform

# Set up Python environment
cd /opt/ai-testing-platform/backend
sudo -u ai-testing python3 -m venv venv
sudo -u ai-testing venv/bin/pip install -r requirements.txt

# Build frontend
cd ../frontend
sudo -u ai-testing npm install --legacy-peer-deps
sudo -u ai-testing npm run build
sudo -u ai-testing cp -r dist/* ../backend/src/static/

# Configure services
sudo cp deployment/nginx.conf /etc/nginx/sites-available/ai-testing-platform
sudo ln -s /etc/nginx/sites-available/ai-testing-platform /etc/nginx/sites-enabled/
sudo systemctl restart nginx

# Start application
sudo -u ai-testing /opt/ai-testing-platform/backend/venv/bin/python /opt/ai-testing-platform/backend/src/main.py
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy backend requirements and install
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy frontend and build
COPY frontend/ ./frontend/
WORKDIR /app/frontend
RUN npm install --legacy-peer-deps && npm run build

# Copy backend code
WORKDIR /app
COPY backend/ ./backend/
RUN cp -r frontend/dist/* backend/src/static/

# Install Playwright browsers
RUN playwright install --with-deps

# Expose port
EXPOSE 5000

# Start application
CMD ["python", "backend/src/main.py"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  ai-testing-platform:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
      - FLASK_DEBUG=False
    volumes:
      - ./logs:/app/logs
      - ./reports:/tmp
    restart: unless-stopped
    
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - ai-testing-platform
    restart: unless-stopped
```

### Scaling Considerations

1. **Horizontal Scaling**
   - Use load balancers (nginx, HAProxy)
   - Implement session affinity or stateless design
   - Use external storage for reports and temporary files

2. **Vertical Scaling**
   - Monitor CPU and memory usage
   - Optimize test execution concurrency
   - Implement resource limits and quotas

3. **Database Scaling**
   - Implement read replicas for reporting
   - Use connection pooling
   - Consider sharding for large datasets

This technical documentation provides comprehensive information for developers and system administrators working with the AI Testing Platform. Regular updates to this documentation should accompany any significant changes to the system architecture or implementation.

