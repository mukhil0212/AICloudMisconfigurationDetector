# 🔐 AI-Powered Cloud Misconfiguration Detector

A full-stack application that identifies cloud security misconfigurations and provides AI-powered remediation suggestions. Perfect for learning cloud security and demonstrating full-stack development skills.

![Dashboard Preview](./dashboard-preview.png)

![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)
![Tech Stack](https://img.shields.io/badge/Stack-Next.js%20%7C%20FastAPI%20%7C%20AI-blue)
![Security](https://img.shields.io/badge/Security-AWS%20Cloud-orange)

## 🚀 Project Overview

This application demonstrates cloud security automation with AI-powered remediation suggestions. It's designed to help developers learn about cloud security while showcasing modern full-stack development practices.

### 🎯 Key Features
- **Security Detection**: Automatically identifies common cloud misconfigurations
- **AI-Powered Remediation**: Provides step-by-step fix instructions using AI
- **Demo & Real Scanning**: Supports both mock data for demos and real AWS scanning
- **Modern Dashboard**: Clean, responsive UI built with Next.js and Tailwind

## ✨ Features

### 🛡️ Security Detection
- **S3 Bucket Analysis**: Detects publicly accessible buckets and policies
- **IAM Role Scanning**: Identifies overly permissive roles and policies
- **Security Group Audit**: Finds unrestricted network access rules
- **Real-time Scanning**: Supports live AWS account scanning

### 🤖 AI-Powered Remediation
- **Groq AI Integration**: Uses `llama-3.1-8b-instant` model for intelligent suggestions
- **Structured Guidance**: Provides security risk analysis, immediate fixes, CLI commands, and prevention tips
- **Confidence Scoring**: AI suggestions include confidence levels (High/Medium/Low)
- **Markdown Formatting**: Professional formatting with syntax highlighting

### 🎨 Modern Dashboard
- **Next.js Frontend**: React-based with TypeScript for type safety
- **Tailwind CSS**: Professional, responsive design
- **Real-time Updates**: Loading states, error handling, and live feedback
- **Credential Management**: Secure AWS credential input with encryption notice

### 🔧 Technical Architecture
- **FastAPI Backend**: Python API with JWT authentication and analytics
- **CORS Configuration**: Proper cross-origin setup for frontend-backend communication  
- **Authentication**: Role-based access control (admin/viewer)
- **Error Handling**: Comprehensive error handling with fallback mock data

## 🏗️ Tech Stack

### Frontend
- **Next.js 14** - React framework with App Router
- **TypeScript** - Type safety and better developer experience
- **Tailwind CSS** - Utility-first styling framework
- **React Markdown** - Markdown rendering for AI suggestions

### Backend
- **FastAPI** - Modern Python web framework
- **Boto3** - AWS SDK for Python
- **Groq AI** - AI model integration for remediation suggestions
- **Uvicorn** - ASGI server for production deployment

### Infrastructure
- **AWS Services** - S3, IAM, EC2 Security Groups
- **Docker** - Containerization ready
- **Environment Variables** - Secure configuration management

## 🚀 Quick Start Guide

### Prerequisites
- **Node.js** (v18+)
- **Python** (3.8+)
- **Groq API Key** (for AI suggestions)
- **AWS Credentials** (optional - uses mock data otherwise)

### 1. Clone and Setup
```bash
git clone <repository-url>
cd Aicloudmisconfigurationdetector
```

### 2. Backend Setup
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your GROQ_API_KEY
```

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

### 4. Start the Application
```bash
# Terminal 1 - Backend
cd backend
source venv/bin/activate
uvicorn app.main:app --reload --port 8000

# Terminal 2 - Frontend
cd frontend
npm run dev
```

### 5. Access the Application
- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

### 6. Demo Login Credentials
- **Admin**: username `admin`, password `admin123` (Full access)
- **Viewer**: username `viewer`, password `viewer123` (Read-only)

## 💡 Usage Examples

### Demo Mode (No AWS Credentials)
1. Open the dashboard at http://localhost:3000
2. Enable "AI-Powered Remediation" toggle
3. Click "Start AI-Powered Scan"
4. View mock security issues with AI-generated remediation suggestions

### Production Mode (With AWS Credentials)
1. Click "Configure" under Custom AWS Credentials
2. Enter your AWS Access Key ID, Secret Access Key, and Region
3. Enable AI suggestions and run scan
4. Review real security issues from your AWS account

### AI Remediation Features
- Click "View AI Fix" on any detected issue
- See structured remediation guidance:
  - 🔍 **Security Risk Analysis**
  - 🛠️ **Immediate Fix Steps**
  - ⚡ **CLI Commands**
  - 🔒 **Prevention Best Practices**

## 📊 API Endpoints

### Core Endpoints
- `GET /` - Health check
- `POST /auth/login` - User authentication
- `GET /auth/me` - Get current user info
- `GET /scan` - Basic scan with mock/environment credentials
- `POST /scan` - Scan with custom AWS credentials (requires auth)
- `POST /scan-with-suggestions` - AI-powered scan with remediation suggestions (requires auth)
- `GET /analytics/dashboard` - Get analytics dashboard data (requires auth)
- `POST /analytics/remediation` - Record remediation action (admin only)

### Request/Response Examples
```bash
# Basic scan
curl http://localhost:8000/scan

# AI-powered scan with credentials
curl -X POST http://localhost:8000/scan-with-suggestions \
  -H "Content-Type: application/json" \
  -d '{
    "credentials": {
      "access_key_id": "AKIA...",
      "secret_access_key": "...",
      "region": "us-east-1"
    }
  }'
```

## 🔒 Security Features

### Authentication & Authorization
- **JWT Authentication**: Secure token-based authentication
- **Role-Based Access**: Admin and viewer roles with different permissions
- **Session Management**: Token expiration and refresh handling

### Data Protection
- **No Credential Storage**: AWS credentials are used only for scanning, never stored
- **Environment Variables**: Secure configuration management
- **Input Validation**: Comprehensive request validation with Pydantic

### AWS Permissions Required
For real scanning, the provided AWS credentials need:
- `s3:ListBuckets`, `s3:GetBucketAcl`, `s3:GetBucketPolicy`
- `iam:ListRoles`, `iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`
- `ec2:DescribeSecurityGroups`

## 🐳 Deployment

### Docker Deployment (Coming Soon)
```bash
# Backend
docker build -t cloud-security-backend ./backend
docker run -p 8000:8000 cloud-security-backend

# Frontend
docker build -t cloud-security-frontend ./frontend
docker run -p 3000:3000 cloud-security-frontend
```

### Environment Variables
```bash
# Backend (.env)
GROQ_API_KEY=your_groq_api_key_here

# Frontend (.env.local)
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## 🎯 Learning Objectives

### Full-Stack Development
- **Frontend**: Modern React with Next.js 14, TypeScript, and Tailwind CSS
- **Backend**: FastAPI with Python, async programming, and REST APIs
- **Authentication**: JWT implementation with role-based access control
- **State Management**: React hooks and context for complex UI state

### Cloud & Security
- **AWS Integration**: Boto3 SDK for cloud resource scanning
- **Security Analysis**: Understanding common cloud misconfigurations
- **AI Integration**: Working with language models for automated assistance
- **Real-world Skills**: Practical cloud security and DevOps knowledge

## 🛣️ Roadmap

### Phase 1 (Current)
- ✅ AWS S3, IAM, Security Group scanning
- ✅ AI-powered remediation suggestions
- ✅ Professional dashboard interface
- ✅ Mock data for demonstrations

### Phase 2 (Future)
- 🔄 Additional AWS services (RDS, Lambda, CloudTrail)
- 🔄 Multi-cloud support (Azure, GCP)
- 🔄 Automated remediation execution
- 🔄 Enhanced analytics and reporting

### Phase 3 (Advanced)
- 🔄 Real-time monitoring and alerting
- 🔄 Custom policy engine
- 🔄 Integration with external security tools
- 🔄 Advanced AI model fine-tuning

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Contact & Support

For questions or collaboration opportunities:
- **Issues**: Open an issue in this repository
- **Discussions**: Use GitHub Discussions for general questions

---

**Built with ❤️ for learning and demonstration**

*This project showcases modern full-stack development, AI integration, cloud security knowledge, and practical DevOps skills.* 