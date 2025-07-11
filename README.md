# AI-Powered Web Testing Application

A comprehensive website-based AI testing application that performs automated audits and tests for websites and software, including pentesting tools, AWS audit capabilities, and automated report generation.

## Features

- **URL-based Testing**: Simply enter a URL to initiate comprehensive testing
- **AI-Powered Analysis**: Leverages artificial intelligence for intelligent test generation and vulnerability detection
- **End-to-End Testing**: Complete functional testing of web applications
- **Security Testing**: Automated penetration testing and vulnerability scanning
- **AWS Auditing**: Comprehensive AWS security and compliance auditing
- **Automated Reporting**: Generate detailed reports in multiple formats (PDF, HTML)

## Project Structure

```
ai-testing-app/
├── backend/          # Flask backend API
├── frontend/         # React frontend interface
├── docs/            # Documentation
├── tests/           # Test files
├── scripts/         # Utility scripts
└── README.md        # This file
```

## Quick Start

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Activate the virtual environment:
   ```bash
   source venv/bin/activate
   ```

3. Start the Flask development server:
   ```bash
   python src/main.py
   ```

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Start the React development server:
   ```bash
   pnpm run dev
   ```

## Development

The application follows a microservices architecture with:
- **Frontend**: React.js with Tailwind CSS and shadcn/ui components
- **Backend**: Flask API with SQLite database
- **AI/ML**: Integrated AI services for intelligent testing
- **Testing Tools**: Integration with popular security testing tools
- **AWS Integration**: Boto3 for AWS auditing capabilities

## Documentation

Detailed documentation can be found in the `docs/` directory:
- [Architecture Design](docs/architecture_design.md)
- API Documentation (coming soon)
- User Guide (coming soon)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License.

