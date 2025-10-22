# 🎓 CredApp - Decentralized Credential Verification Platform

> A blockchain-powered credential management system enabling secure, verifiable, and tamper-proof digital credentials for educational institutions, employers, and learners.

[![Frontend](https://img.shields.io/badge/Frontend-Vercel-black?logo=vercel)](https://cred-app-pearl.vercel.app/landing)
[![Backend](https://img.shields.io/badge/Backend-AWS_EC2-FF9900?logo=amazon-aws)](https://credhub.twilightparadox.com/)
[![Blockchain](https://img.shields.io/badge/Blockchain-Polygon_Amoy-8247E5?logo=polygon)](https://polygon.technology)

---

## 🌟 Overview

**CredApp** is an enterprise-grade decentralized credential management platform that revolutionizes how educational credentials are issued, verified, and shared. Built on blockchain technology and Decentralized Identity (DID) principles, it provides an immutable, secure, and privacy-preserving solution for credential verification.

### 🔗 Platform Access

- **Frontend**: Hosted on **Vercel** - [Frontend Repository](https://credhub.twilightparadox.com/)
- **Backend API**: Deployed on **AWS EC2** - [Backend Repository](https://github.com/ishaanxgupta/CredApp/)
- **Blockchain Network**: **Polygon Amoy Testnet** - [Blockchain Repository](https://github.com/Vivekgupta008/CredApp-blockchain)
- **API Documentation**: Available at https://credhub.twilightparadox.com/docs
- **Issuer API Docs**: Available at https://cred-app-pearl.vercel.app/dashboard/issuer/api-docs

---

## 🚀 Key Features

### 🔐 Decentralized Identity (DID) Management
- **W3C DID Compliance**: Fully compliant with W3C DID specifications
- **Self-Sovereign Identity**: Users have complete control over their digital identities
- **DID Document Management**: Create, resolve, update, and deactivate DIDs
- **Multi-Method Support**: Flexible DID method implementation
- **Cryptographic Key Management**: Secure public/private key pair generation and storage

### ⛓️ Blockchain-Based Credentials
- **Immutable Storage**: Credentials stored on Polygon blockchain for tamper-proof verification
- **Smart Contract Integration**: Automated credential issuance and verification
- **Transaction Tracking**: Complete audit trail of all credential operations
- **Gas Optimization**: Efficient smart contract design for minimal transaction costs
- **IPFS Integration**: Decentralized storage for credential metadata
- **Verifiable Credentials (VC)**: JSON-LD formatted credentials following W3C VC standards

### 👥 Role-Based Access Control (RBAC)
- **Multi-Tenant Architecture**: Support for multiple organizations
- **Five Core Roles**:
  - **Admin**: Platform administration and system configuration
  - **Issuer**: Credential issuance and institution management
  - **Learner**: Credential wallet and sharing capabilities
  - **Employer**: Credential verification and talent discovery
  - **Institution**: Course management and credential templates
- **Granular Permissions**: Fine-grained access control for each role
- **Dynamic Role Assignment**: Runtime role switching and management

### 📄 Document Verification & KYC
- **Real-time KYC Integration**: 
  - **PAN Card Verification**: Live verification via Sandbox API
  - **Aadhaar Verification**: OTP-based identity verification
  - **DigiLocker Integration**: Government document fetching (ready)
- **3-Step Verification Process**:
  - Document Verification (PAN/Aadhaar)
  - Identity Verification (Face & Address)
  - Contact Verification (Email & Mobile)
- **OCR Technology**: Automatic data extraction from documents
- **Face Verification**: Biometric identity confirmation
- **Address Verification**: Location and residency validation

### 📊 Advanced Credential Features
- **QR Code Generation**: Instant credential sharing via QR codes
- **QR Code Verification**: Real-time credential validation
- **Batch Credential Issuance**: Issue credentials to multiple recipients
- **Credential Templates**: Predefined templates for common credential types
- **Credential Revocation**: Secure credential invalidation mechanism
- **Credential Expiry**: Time-bound credential validity
- **Credential Workflows**: Automated multi-step issuance processes
- **NSQF Compliance**: National Skills Qualifications Framework integration

### 🤖 AI-Powered Capabilities
- **AI Chatbot**: Intelligent assistant for platform navigation and support
- **Natural Language Processing**: Context-aware responses
- **Multi-lingual Support**: AI responses in 5 languages
- **Document Intelligence**: OCR and automated data extraction
- **Recommendation Engine**: Personalized credential and course suggestions

### 🌍 Internationalization & Accessibility
- **Multi-Language Support**: 
  - English
  - Spanish (Español)
  - French (Français)
  - German (Deutsch)
  - Hindi (हिंदी)
- **Accessibility Features**:
  - WCAG 2.1 AA Compliance
  - Screen reader compatibility
  - Keyboard navigation
  - Text-to-speech integration
  - High contrast mode
  - Font size adjustment
  - Focus indicators

### 📱 User Experience
- **Responsive Design**: Optimized for desktop, tablet, and mobile
- **Real-time Notifications**: Instant updates on credential status
- **Interactive Dashboards**: Role-specific analytics and insights
- **Profile Management**: Comprehensive user profile customization
- **Credential Wallet**: Digital wallet for storing and managing credentials
- **Sharing Capabilities**: Secure credential sharing with employers
- **Interactive API Tester**: Built-in API testing interface for developers

### 🔒 Security Features
- **JWT Authentication**: Secure token-based authentication
- **Password Hashing**: Bcrypt encryption for password storage
- **Rate Limiting**: Protection against brute force attacks
- **CORS Configuration**: Secure cross-origin resource sharing
- **Data Encryption**: End-to-end encryption for sensitive data
- **Secure File Upload**: Validated and sanitized document uploads
- **Session Management**: Secure session handling and timeout
- **Audit Logging**: Comprehensive activity tracking

### 📈 Analytics & Reporting
- **Credential Analytics**: Track issuance, verification, and usage metrics
- **User Analytics**: Monitor user engagement and platform adoption
- **Employer Insights**: Candidate discovery and verification statistics
- **Institution Dashboard**: Course enrollment and completion tracking
- **Custom Reports**: Generate detailed reports for stakeholders
- **Data Visualization**: Interactive charts and graphs

---

## 🛠️ Technology Stack

### Frontend
- **Framework**: Next.js 15.5.4 (React 19.1.0)
- **Language**: TypeScript 5
- **UI Library**: Material-UI (MUI) v7
- **Styling**: Tailwind CSS v4, Emotion
- **Charts**: Chart.js, MUI X-Charts
- **Data Grid**: MUI X-Data-Grid
- **Forms**: React Hook Form + Zod validation
- **Animations**: Framer Motion, Lottie
- **HTTP Client**: Axios
- **Authentication**: NextAuth.js
- **Internationalization**: next-intl
- **Build Tool**: Turbopack

### Backend
- **Framework**: FastAPI 0.104.1
- **Language**: Python 3.12
- **Web Server**: Uvicorn + Gunicorn
- **Database**: MongoDB (Motor async driver)
- **Authentication**: Python-JOSE (JWT), Bcrypt
- **Blockchain**: Web3.py, Ethereum libraries
- **File Processing**:
  - PyMuPDF (PDF processing)
  - Pillow (Image processing)
  - OpenCV (Computer vision)
- **Document Generation**: ReportLab
- **QR Codes**: qrcode library
- **Data Validation**: Pydantic 2.10.3
- **HTTP Client**: HTTPX, aiohttp
- **Email Validation**: email-validator

### Blockchain
- **Network**: Polygon Amoy Testnet
- **Smart Contracts**: Solidity
- **Web3 Library**: Web3.py 7.13.0
- **Ethereum Utilities**: 
  - eth-account 0.13.7
  - eth-keys 0.7.0
  - eth-utils 5.3.1
- **Key Management**: eth-keyfile 0.8.1
- **Transaction Signing**: eth-account

### Infrastructure
- **Frontend Hosting**: Vercel (Serverless)
- **Backend Hosting**: AWS EC2
- **Database**: MongoDB Atlas
- **Blockchain Network**: Polygon Amoy (Layer 2)
- **File Storage**: Azure Blob Storage (ready)
- **CDN**: Vercel Edge Network

### DevOps & Tools
- **Version Control**: Git
- **Package Management**: npm (frontend), pip (backend)
- **Code Quality**: ESLint, Python type hints
- **Environment Management**: python-dotenv
- **API Documentation**: FastAPI auto-generated Swagger/OpenAPI

---

## 🏗️ Architecture

### System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Frontend (Next.js)                      │
│                    Hosted on Vercel                         │
│  ┌────────────┬────────────┬────────────┬────────────┐      │
│  │  Learner   │  Employer  │  Issuer    │   Admin    │      │
│  │  Dashboard │  Dashboard │  Dashboard │  Dashboard │      │
│  └────────────┴────────────┴────────────┴────────────┘      │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTPS/REST API
┌────────────────────────▼────────────────────────────────────┐
│                  Backend API (FastAPI)                      │
│                   Hosted on AWS EC2                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Authentication │ RBAC │ DID Service │ Blockchain    │   │
│  │  OCR Service    │ QR   │ PDF Gen     │ Verification  │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────┬──────────────────────────┬─────────────────────┘
             │                          │
    ┌────────▼────────┐        ┌────────▼────────────┐
    │   MongoDB       │        │  Polygon Blockchain │
    │   Database      │        │   (Amoy Testnet)    │
    │                 │        │                     │
    │  - Users        │        │  - Smart Contracts  │
    │  - Credentials  │        │  - Transactions     │
    │  - DIDs         │        │  - Immutable Ledger │
    │  - KYC Data     │        │                     │
    └─────────────────┘        └─────────────────────┘
```

### Data Flow

1. **User Registration**: 
   - Frontend → Backend → KYC Verification → MongoDB
   - DID Creation → Blockchain registration

2. **Credential Issuance**:
   - Issuer Dashboard → Backend → Smart Contract → Blockchain
   - Credential metadata → IPFS → Hash stored on-chain
   - Notification → Learner

3. **Credential Verification**:
   - QR Scan → Backend → Blockchain query → Verification result
   - Immutable proof retrieved from blockchain

4. **Credential Sharing**:
   - Learner shares → Employer access → Backend verification
   - Real-time validation against blockchain

---

## 💼 Business Value

### For Educational Institutions
- ✅ Automated credential issuance
- ✅ Reduced administrative overhead
- ✅ Enhanced brand credibility
- ✅ Fraud prevention
- ✅ Compliance with standards (NSQF)

### For Learners
- ✅ Portable digital credentials
- ✅ Instant verification
- ✅ Secure credential wallet
- ✅ Easy sharing with employers
- ✅ Lifetime access to credentials

### For Employers
- ✅ Instant credential verification
- ✅ Reduced hiring fraud
- ✅ Streamlined background checks
- ✅ Access to verified talent pool
- ✅ Cost and time savings

### For the Ecosystem
- ✅ Standardized credential format
- ✅ Interoperability across institutions
- ✅ Reduced verification costs
- ✅ Increased trust in credentials
- ✅ Blockchain-backed immutability

---

## 📦 Repository Structure

### Frontend Repository
```
frontend/
├── src/
│   ├── app/              # Next.js app router
│   │   ├── auth/         # Authentication pages
│   │   ├── dashboard/    # Role-based dashboards
│   │   └── landing/      # Landing page
│   ├── components/       # React components
│   │   ├── auth/         # Authentication components
│   │   ├── dashboard/    # Dashboard components
│   │   ├── chatbot/      # AI chatbot
│   │   └── accessibility/# Accessibility features
│   ├── services/         # API integration
│   ├── hooks/            # Custom React hooks
│   ├── contexts/         # React contexts
│   └── utils/            # Utility functions
└── messages/             # i18n translations
```

### Backend Repository
```
backend/
├── app/
│   ├── api/v1/           # API endpoints
│   │   ├── auth.py       # Authentication
│   │   ├── did_management.py
│   │   ├── blockchain_credentials.py
│   │   ├── kyc.py
│   │   ├── issuer.py
│   │   ├── learner.py
│   │   ├── employer.py
│   │   └── verification.py
│   ├── services/         # Business logic
│   │   ├── did_service.py
│   │   ├── blockchain_service.py
│   │   ├── credential_issuance_service.py
│   │   ├── ocr_service.py
│   │   ├── qr_service.py
│   │   └── verification_service.py
│   ├── models/           # Data models
│   ├── core/             # Core configurations
│   └── db/               # Database connections
└── requirements.txt      # Python dependencies
```

### Blockchain Repository
```
blockchain/
├── contracts/            # Smart contracts
│   ├── CredentialRegistry.sol
│   ├── DIDRegistry.sol
│   └── VerificationContract.sol
├── scripts/              # Deployment scripts
├── test/                 # Contract tests
└── migrations/           # Contract migrations
```

---

## 🎯 Use Cases

### 1. Academic Credential Issuance
University issues degree certificates → Stored on blockchain → Student receives verifiable credential → Employer verifies instantly

### 2. Skill Certification
Training institute issues skill certificate → Blockchain record created → Learner shares with potential employers → Instant verification

### 3. Background Verification
Employer requests credentials → Learner shares via QR → System verifies against blockchain → Employer receives proof

### 4. Credential Portfolio
Learner collects credentials from multiple institutions → All stored in wallet → Single shareable profile for job applications

### 5. Compliance Tracking
Institution tracks NSQF compliance → Automated reporting → Credential mapping to qualification framework

---

## 🔄 Workflow Examples

### Credential Issuance Workflow
```
1. Issuer logs in → Dashboard
2. Selects "Issue Credential"
3. Chooses credential template (e.g., Degree)
4. Enters learner details
5. Uploads supporting documents
6. Reviews and confirms
7. System generates credential
8. Creates blockchain transaction
9. Stores credential hash on Polygon
10. Sends notification to learner
11. Learner receives verifiable credential in wallet
```

### Verification Workflow
```
1. Employer receives credential (QR/PDF)
2. Scans QR code or enters credential ID
3. System queries blockchain
4. Retrieves credential hash
5. Validates credential data
6. Checks revocation status
7. Displays verification result
8. Shows credential details
9. Provides blockchain proof
```

---

## 🌐 Deployment Details

### Frontend (Vercel)
- **Auto-deployment**: Git push triggers automatic deployment
- **Edge Functions**: Global CDN for low latency
- **Environment Variables**: Secure configuration management
- **SSL/TLS**: Automatic HTTPS certificates
- **Preview Deployments**: Branch-based preview URLs

### Backend (AWS EC2)
- **Instance Type**: [Specify your EC2 instance type]
- **Operating System**: Ubuntu 22.04 LTS
- **Web Server**: Nginx reverse proxy
- **Process Manager**: Gunicorn with Uvicorn workers
- **Security Groups**: Configured for HTTPS traffic
- **Elastic IP**: Static IP assignment

### Blockchain (Polygon Amoy)
- **Network**: Layer 2 scaling solution
- **Consensus**: Proof of Stake
- **Transaction Speed**: ~2 seconds
- **Gas Fees**: Minimal (testnet)
- **Block Explorer**: Polygonscan Amoy

---

## 📊 Technical Highlights

### Performance Optimizations
- Server-side rendering (SSR) for fast initial page loads
- Code splitting and lazy loading
- Image optimization with Next.js Image component
- API response caching
- Database query optimization with indexes
- Async/await for non-blocking operations

### Scalability
- Microservices-ready architecture
- Horizontal scaling capability
- Database sharding support (MongoDB)
- Load balancing ready
- Stateless API design

### Reliability
- Error handling and graceful degradation
- Retry mechanisms for blockchain transactions
- Transaction monitoring and logging
- Automated backup strategies
- Health check endpoints

---

## 🔐 Security & Compliance

### Data Protection
- GDPR-ready architecture
- Data encryption at rest and in transit
- Privacy-preserving credential sharing
- Minimal data collection principle
- User consent management

### Blockchain Security
- Immutable credential records
- Cryptographic proof of authenticity
- Decentralized verification (no single point of failure)
- Smart contract auditing
- Private key management

---

## 📞 Support & Documentation

### Documentation Resources
- **API Documentation**: `/docs` (Swagger UI)
- **Issuer API Guide**: `/dashboard/issuer/api-docs`
- **User Guides**: Available in platform
- **Video Tutorials**: [https://youtu.be/MovdTUVLVlg]

### Getting Started
1. **For Issuers**: Register institution → Complete KYC → Create credential templates → Start issuing
2. **For Learners**: Sign up → Verify identity → Receive credentials → Build portfolio
3. **For Employers**: Create account → Verify credentials → Discover talent
4. **For Developers**: Access API docs → Generate API keys → Integrate with your system

---


## 🤝 Contributing

We welcome contributions from the community. Please see our contributing guidelines for more information. []

---

## 🏆 Recognition

Built with cutting-edge technology and designed for the future of credential verification.

**Powered by:**
- Blockchain technology for immutability
- Decentralized Identity for privacy
- AI for intelligence
- Cloud infrastructure for reliability

---

<p align="center">
  <strong>Making Credentials Trustworthy, Portable, and Verifiable</strong>
</p>

<p align="center">
  <sub>© 2025 CredApp. Revolutionizing Digital Credentials.</sub>
</p>

