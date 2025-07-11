# AI Testing Platform - Local Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the AI Testing Platform on your local laptop or development environment. The application consists of a Flask backend API and a React frontend interface, designed to work together as a comprehensive web security and performance testing solution.

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 10/11, macOS 10.15+, or Linux (Ubuntu 18.04+)
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 2GB free space
- **Network**: Internet connection for testing external websites

### Software Dependencies
- **Python**: 3.8 or higher
- **Node.js**: 16.0 or higher
- **npm**: 7.0 or higher (comes with Node.js)
- **Git**: For cloning the repository

## Pre-Installation Setup

### 1. Install Python
**Windows:**
1. Download Python from https://python.org/downloads/
2. Run the installer and check "Add Python to PATH"
3. Verify installation: `python --version`

**macOS:**
```bash
# Using Homebrew (recommended)
brew install python

# Or download from python.org
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

### 2. Install Node.js and npm
**Windows/macOS:**
1. Download from https://nodejs.org/
2. Run the installer
3. Verify installation: `node --version` and `npm --version`

**Linux (Ubuntu/Debian):**
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### 3. Install Git
**Windows:**
Download from https://git-scm.com/download/win

**macOS:**
```bash
brew install git
```

**Linux:**
```bash
sudo apt install git
```

## Installation Steps

### Step 1: Download the Application
Copy the entire `ai-testing-app` folder to your laptop. You can do this by:
1. Copying the folder from the provided source
2. Or cloning from a repository if available

### Step 2: Backend Setup

1. **Navigate to the backend directory:**
```bash
cd ai-testing-app/backend
```

2. **Create a Python virtual environment:**
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

4. **Install additional system dependencies (Linux only):**
```bash
# For PDF generation and browser automation
sudo apt-get install -y wkhtmltopdf
sudo apt-get install -y chromium-browser

# Install Playwright browsers
playwright install
playwright install-deps
```

5. **Install system dependencies (macOS):**
```bash
# Using Homebrew
brew install wkhtmltopdf
brew install chromium

# Install Playwright browsers
playwright install
```

6. **Install system dependencies (Windows):**
- Download wkhtmltopdf from https://wkhtmltopdf.org/downloads.html
- Install Playwright browsers: `playwright install`

### Step 3: Frontend Setup

1. **Navigate to the frontend directory:**
```bash
cd ../frontend
```

2. **Install Node.js dependencies:**
```bash
npm install --legacy-peer-deps
```

3. **Build the frontend for production:**
```bash
npm run build
```

4. **Copy built files to backend static directory:**
```bash
# Windows
xcopy /E /I dist\* ..\backend\src\static\

# macOS/Linux
cp -r dist/* ../backend/src/static/
```

## Configuration

### Backend Configuration

1. **Environment Variables (Optional):**
Create a `.env` file in the backend directory:
```env
FLASK_ENV=production
FLASK_DEBUG=False
SECRET_KEY=your-secret-key-here
PORT=5000
```

2. **AWS Configuration (Optional):**
If you plan to use AWS auditing features, configure AWS credentials:
```bash
# Install AWS CLI
pip install awscli

# Configure credentials
aws configure
```

### Frontend Configuration

The frontend is pre-configured to work with the backend API. If you need to change the API endpoint, modify the fetch URLs in the React components.

## Running the Application

### Method 1: Integrated Deployment (Recommended)

1. **Navigate to the backend directory:**
```bash
cd ai-testing-app/backend
```

2. **Activate the virtual environment:**
```bash
# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

3. **Start the application:**
```bash
python src/main.py
```

4. **Access the application:**
Open your web browser and go to: `http://localhost:5000`

### Method 2: Separate Frontend and Backend

**Terminal 1 - Backend:**
```bash
cd ai-testing-app/backend
source venv/bin/activate  # or venv\Scripts\activate on Windows
python src/main.py
```

**Terminal 2 - Frontend (Development Mode):**
```bash
cd ai-testing-app/frontend
npm run dev
```

Access the application at: `http://localhost:5173` (frontend) with API at `http://localhost:5000`

## Verification

### 1. Check Backend API
Open your browser and visit: `http://localhost:5000/api/users`
You should see a simple API test interface.

### 2. Test the Application
1. Go to `http://localhost:5000` (or `http://localhost:5173` if running separately)
2. Click "New Test"
3. Enter a test URL (e.g., `https://example.com`)
4. Select test types (Web Testing and Security Testing)
5. Click "Start Test"
6. Wait for results and verify report generation

## Troubleshooting

### Common Issues

**1. Port Already in Use:**
```bash
# Find process using port 5000
# Windows
netstat -ano | findstr :5000

# macOS/Linux
lsof -i :5000

# Kill the process or change port in main.py
```

**2. Python Module Not Found:**
```bash
# Ensure virtual environment is activated
# Reinstall requirements
pip install -r requirements.txt
```

**3. Node.js Build Errors:**
```bash
# Clear npm cache
npm cache clean --force

# Delete node_modules and reinstall
rm -rf node_modules package-lock.json
npm install --legacy-peer-deps
```

**4. Permission Errors (Linux/macOS):**
```bash
# Fix permissions
chmod +x venv/bin/activate
sudo chown -R $USER:$USER ai-testing-app/
```

**5. Playwright Browser Issues:**
```bash
# Reinstall browsers
playwright install --force
```

### Performance Optimization

**1. Increase Memory for Large Tests:**
```bash
# Set environment variable
export NODE_OPTIONS="--max-old-space-size=4096"
```

**2. Configure Timeout Settings:**
Edit `backend/src/services/web_testing_service.py` and adjust timeout values if needed.

## Security Considerations

### Local Network Access
- The application runs on `0.0.0.0:5000` by default, making it accessible from other devices on your network
- To restrict to localhost only, modify `main.py`: `app.run(host='127.0.0.1', port=5000)`

### Firewall Configuration
- Ensure your firewall allows connections on port 5000
- Windows: Add exception in Windows Defender Firewall
- macOS: System Preferences > Security & Privacy > Firewall
- Linux: Configure ufw or iptables as needed

## Maintenance

### Regular Updates
1. **Update Python packages:**
```bash
pip install --upgrade -r requirements.txt
```

2. **Update Node.js packages:**
```bash
npm update
```

### Backup Configuration
- Backup the entire `ai-testing-app` directory
- Export any custom configurations or test results

### Log Management
- Application logs are stored in the console output
- For production use, consider implementing file-based logging

## Support

### Log Files
- Backend logs: Console output when running `python src/main.py`
- Frontend logs: Browser developer console (F12)

### Debug Mode
To enable debug mode for troubleshooting:
```bash
# Set environment variable
export FLASK_DEBUG=True

# Or modify main.py
app.run(host='0.0.0.0', port=5000, debug=True)
```

### Getting Help
1. Check the console output for error messages
2. Verify all dependencies are installed correctly
3. Ensure ports 5000 and 5173 are available
4. Check network connectivity for external website testing

## Next Steps

After successful deployment:
1. Test the application with various websites
2. Explore the AI-powered insights and recommendations
3. Generate and download reports in different formats
4. Configure AWS credentials for cloud security auditing (optional)
5. Customize the application for your specific testing needs

The AI Testing Platform is now ready for use on your local environment!

