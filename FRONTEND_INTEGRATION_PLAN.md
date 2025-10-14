# Frontend Integration Plan - Comprehensive QR Code System

## 🎯 Overview
This document provides a complete integration plan for frontend applications to use the comprehensive QR code system for credential display and verification.

## 📋 Table of Contents
1. [API Endpoints](#api-endpoints)
2. [Authentication](#authentication)
3. [Request/Response Formats](#requestresponse-formats)
4. [Frontend Integration Steps](#frontend-integration-steps)
5. [QR Code Usage](#qr-code-usage)
6. [Error Handling](#error-handling)
7. [Sample Code](#sample-code)

---

## 🔗 API Endpoints

### 1. Get Complete Credential Information with QR Code
**Endpoint:** `GET /api/v1/issuer/credentials/{credential_id}/complete-info`

**Authentication:** API Key (X-API-Key header)

**Purpose:** Retrieve complete credential information including comprehensive QR code data

---

## 🔐 Authentication

### API Key Authentication
```javascript
const headers = {
  'X-API-Key': 'your_api_key_here',
  'Content-Type': 'application/json'
};
```

### Getting API Key
1. Issuer logs in with JWT
2. Submits verification documents
3. Gets automatically verified after 10 seconds
4. Generates API key via: `POST /api/v1/issuer/api-keys/generate`

---

## 📊 Request/Response Formats

### Request Format
```javascript
// GET Request
const response = await fetch(`/api/v1/issuer/credentials/${credentialId}/complete-info`, {
  method: 'GET',
  headers: {
    'X-API-Key': apiKey,
    'Content-Type': 'application/json'
  }
});
```

### Response Format
```json
{
  "message": "Complete credential information retrieved successfully",
  "credential": {
    "id": "68ed82464200dfcf24e90833",
    "status": "verified",
    "title": "Python Programming Certificate",
    "description": "Certificate for completing Python programming course",
    "created_at": "2025-10-13T22:50:46.506000",
    "verified_at": "2025-10-13T22:55:30.123000",
    "updated_at": "2025-10-13T22:55:30.123000"
  },
  "learner": {
    "id": "68ec04e8f9a2d4d5bf6e7f2b",
    "name": "Ishaan Gupta",
    "email": "ishu@gmail.com",
    "phone": "+918766381885",
    "date_of_birth": "2004-06-15T00:00:00.000Z",
    "is_active": true,
    "kyc_verified": true
  },
  "issuer": {
    "id": "68ed1be2de695bb667db2e4b",
    "name": "John Doe",
    "email": "john@testorg.com",
    "organization_name": "Test Organization",
    "organization_type": "Educational Institution",
    "registration_number": "REG123456",
    "website": "https://testorg.com",
    "verified_at": "2025-10-13T22:45:00.000Z"
  },
  "blockchain": {
    "transaction_hash": "bc16524d92ab57600db9d6a566c209cf3a4a9923ca1c9d2a879970e933c7ce2d",
    "block_number": 12345,
    "network": "ethereum",
    "deployed_at": "2025-10-13T22:55:30.123000",
    "gas_used": "21000",
    "gas_price": "20000000000",
    "block_explorer_url": "https://etherscan.io/tx/bc16524d92ab57600db9d6a566c209cf3a4a9923ca1c9d2a879970e933c7ce2d"
  },
  "qr_code": {
    "image_base64": "iVBORw0KGgoAAAANSUhEUgAA...",
    "data_url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
    "verification_url": "http://localhost:8000/api/v1/verify/68ed82464200dfcf24e90833",
    "qr_data": {
      "credential_info": {
        "credential_id": "68ed82464200dfcf24e90833",
        "title": "Python Programming Certificate",
        "description": "Certificate for completing Python programming course",
        "status": "verified",
        "type": "Educational Credential",
        "standard": "W3C Verifiable Credential"
      },
      "learner_info": {
        "learner_id": "68ec04e8f9a2d4d5bf6e7f2b",
        "full_name": "Ishaan Gupta",
        "email": "ishu@gmail.com",
        "phone_number": "+918766381885",
        "kyc_verified": true
      },
      "issuer_info": {
        "issuer_id": "68ed1be2de695bb667db2e4b",
        "organization_name": "Test Organization",
        "organization_type": "Educational Institution",
        "registration_number": "REG123456",
        "website": "https://testorg.com"
      },
      "blockchain_info": {
        "transaction_hash": "bc16524d92ab57600db9d6a566c209cf3a4a9923ca1c9d2a879970e933c7ce2d",
        "block_number": 12345,
        "network": "ethereum",
        "credential_hash": "f040380af643dd4ea073769570d20e4719722983a9581955f40a009ce3499efe"
      },
      "educational_info": {
        "nsqf_level": 5,
        "skill_tags": ["Python", "Programming", "Software Development"],
        "grade": "A+",
        "competencies": ["Python Programming", "Software Development", "Problem Solving"]
      },
      "verification_info": {
        "verification_url": "http://localhost:8000/api/v1/verify/68ed82464200dfcf24e90833",
        "qr_generated_at": "2025-10-13T22:55:30.123000",
        "verification_type": "blockchain_verified",
        "verification_method": "QR_Code_Scan",
        "public_verification": true,
        "offline_verification": true
      },
      "security_info": {
        "digital_signature": "eyJhbGciOiJFUzI1Nks...",
        "signature_algorithm": "EcdsaSecp256k1Signature2019",
        "tamper_proof": true,
        "integrity_check": "sha256"
      }
    },
    "qr_json_data": "{\n  \"credential_info\": {\n    \"credential_id\": \"68ed82464200dfcf24e90833\",\n    \"title\": \"Python Programming Certificate\",\n    ...\n  }\n}",
    "generated_at": "2025-10-13T22:55:30.123000"
  },
  "verifiable_credential": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "EducationalCredential"],
    "issuer": "did:ethr:0x1234567890123456789012345678901234567890",
    "issuanceDate": "2025-10-13T22:55:30.123Z",
    "credentialSubject": {
      "id": "did:example:learner123",
      "name": "Ishaan Gupta",
      "credential": {
        "title": "Python Programming Certificate",
        "description": "Certificate for completing Python programming course"
      }
    },
    "proof": {
      "type": "EcdsaSecp256k1Signature2019",
      "created": "2025-10-13T22:55:30.123Z",
      "verificationMethod": "did:ethr:0x1234567890123456789012345678901234567890#key-1",
      "proofPurpose": "assertionMethod",
      "jws": "eyJhbGciOiJFUzI1Nks..."
    }
  },
  "metadata": {
    "nsqf_level": 5,
    "skill_tags": ["Python", "Programming", "Software Development"],
    "file_info": {
      "original_filename": "certificate.pdf",
      "file_size": 1024000,
      "file_type": "application/pdf"
    },
    "ocr_data": {
      "learner_name": "Ishaan Gupta",
      "certificate_title": "Python Programming Certificate",
      "confidence": 0.95
    },
    "upload_timestamp": "2025-10-13T22:50:46.506000"
  }
}
```

---

## 🚀 Frontend Integration Steps

### Step 1: Setup Authentication
```javascript
// Store API key securely
const API_KEY = process.env.REACT_APP_API_KEY || 'your_api_key_here';
const BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

// Create API client
const apiClient = {
  headers: {
    'X-API-Key': API_KEY,
    'Content-Type': 'application/json'
  },
  
  async getCredentialCompleteInfo(credentialId) {
    const response = await fetch(`${BASE_URL}/api/v1/issuer/credentials/${credentialId}/complete-info`, {
      method: 'GET',
      headers: this.headers
    });
    
    if (!response.ok) {
      throw new Error(`API Error: ${response.status} ${response.statusText}`);
    }
    
    return await response.json();
  }
};
```

### Step 2: Create Credential Display Component
```javascript
import React, { useState, useEffect } from 'react';
import QRCode from 'qrcode.react';

const CredentialDisplay = ({ credentialId }) => {
  const [credentialData, setCredentialData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchCredential = async () => {
      try {
        setLoading(true);
        const data = await apiClient.getCredentialCompleteInfo(credentialId);
        setCredentialData(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchCredential();
  }, [credentialId]);

  if (loading) return <div className="loading">Loading credential...</div>;
  if (error) return <div className="error">Error: {error}</div>;
  if (!credentialData) return <div className="error">No credential data found</div>;

  return (
    <div className="credential-display">
      <CredentialHeader data={credentialData} />
      <CredentialDetails data={credentialData} />
      <QRCodeSection data={credentialData.qr_code} />
      <BlockchainInfo data={credentialData.blockchain} />
    </div>
  );
};
```

### Step 3: Create QR Code Display Component
```javascript
const QRCodeSection = ({ data }) => {
  const handleDownloadQR = () => {
    const link = document.createElement('a');
    link.href = data.data_url;
    link.download = `credential-qr-${data.qr_data.credential_info.credential_id}.png`;
    link.click();
  };

  const handleDownloadData = () => {
    const blob = new Blob([data.qr_json_data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `credential-data-${data.qr_data.credential_info.credential_id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="qr-section">
      <h3>📱 QR Code Verification</h3>
      
      {/* Display QR Code */}
      <div className="qr-display">
        <img 
          src={data.data_url} 
          alt="Credential QR Code" 
          className="qr-image"
          style={{ maxWidth: '300px', height: 'auto' }}
        />
      </div>

      {/* QR Code Info */}
      <div className="qr-info">
        <p><strong>Data Size:</strong> {data.qr_json_data.length} characters</p>
        <p><strong>Offline Verification:</strong> {data.qr_data.verification_info.offline_verification ? 'Yes' : 'No'}</p>
        <p><strong>Tamper Proof:</strong> {data.qr_data.security_info.tamper_proof ? 'Yes' : 'No'}</p>
        <p><strong>Generated:</strong> {new Date(data.generated_at).toLocaleString()}</p>
      </div>

      {/* Action Buttons */}
      <div className="qr-actions">
        <button onClick={handleDownloadQR} className="btn-primary">
          📥 Download QR Code
        </button>
        <button onClick={handleDownloadData} className="btn-secondary">
          📄 Download Data
        </button>
        <a 
          href={data.verification_url} 
          target="_blank" 
          rel="noopener noreferrer"
          className="btn-link"
        >
          🔗 Verify Online
        </a>
      </div>

      {/* QR Code Preview */}
      <details className="qr-preview">
        <summary>View QR Code Data</summary>
        <pre className="json-preview">
          {JSON.stringify(data.qr_data, null, 2)}
        </pre>
      </details>
    </div>
  );
};
```

### Step 4: Create Certificate Overlay Component
```javascript
const CertificateOverlay = ({ credentialData, onDownload }) => {
  const [qrPosition, setQrPosition] = useState({ x: 'right', y: 'bottom' });
  
  const generateCertificateWithQR = async () => {
    // This would integrate with your PDF generation service
    const certificateData = {
      credential: credentialData.credential,
      learner: credentialData.learner,
      issuer: credentialData.issuer,
      qr_code: credentialData.qr_code,
      position: qrPosition
    };

    try {
      const response = await fetch('/api/v1/certificates/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(certificateData)
      });

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `certificate-${credentialData.credential.id}.pdf`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Error generating certificate:', error);
    }
  };

  return (
    <div className="certificate-overlay">
      <h3>📜 Certificate Generation</h3>
      
      <div className="qr-position-selector">
        <label>QR Code Position:</label>
        <select 
          value={`${qrPosition.x}-${qrPosition.y}`}
          onChange={(e) => {
            const [x, y] = e.target.value.split('-');
            setQrPosition({ x, y });
          }}
        >
          <option value="right-bottom">Bottom Right</option>
          <option value="left-bottom">Bottom Left</option>
          <option value="right-top">Top Right</option>
          <option value="left-top">Top Left</option>
        </select>
      </div>

      <button onClick={generateCertificateWithQR} className="btn-primary">
        🎓 Generate Certificate with QR
      </button>
    </div>
  );
};
```

---

## 📱 QR Code Usage

### Scanning the QR Code
When someone scans the QR code, they will receive the complete JSON data containing:

1. **Credential Information** - Title, description, status
2. **Learner Details** - Name, email, phone, KYC status
3. **Issuer Information** - Organization details, verification status
4. **Blockchain Data** - Transaction hash, block number, network
5. **Educational Info** - NSQF level, skills, grade
6. **Security Data** - Digital signature, tamper-proof status

### Offline Verification
The QR code works completely offline - no internet connection required for basic verification.

### Online Verification
For additional verification, the QR code also includes a verification URL that can be used for online blockchain verification.

---

## ⚠️ Error Handling

### Common Error Responses
```json
{
  "detail": "Invalid or inactive API key",
  "status_code": 401
}

{
  "detail": "Credential not found or access denied",
  "status_code": 404
}

{
  "detail": "Credential must be verified to get complete information",
  "status_code": 400
}
```

### Frontend Error Handling
```javascript
const handleApiError = (error, response) => {
  switch (response?.status) {
    case 401:
      return 'Invalid API key. Please check your authentication.';
    case 403:
      return 'Access denied. You do not have permission to view this credential.';
    case 404:
      return 'Credential not found. Please check the credential ID.';
    case 400:
      return 'Invalid request. The credential may not be verified yet.';
    case 500:
      return 'Server error. Please try again later.';
    default:
      return 'An unexpected error occurred.';
  }
};
```

---

## 🎨 CSS Styling Example

```css
.credential-display {
  max-width: 800px;
  margin: 0 auto;
  padding: 20px;
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

.qr-section {
  background: #f8f9fa;
  border-radius: 8px;
  padding: 20px;
  margin: 20px 0;
  border: 1px solid #e9ecef;
}

.qr-display {
  text-align: center;
  margin: 20px 0;
}

.qr-image {
  border: 2px solid #007bff;
  border-radius: 8px;
  box-shadow: 0 4px 8px rgba(0,0,0,0.1);
}

.qr-info {
  background: white;
  padding: 15px;
  border-radius: 6px;
  margin: 15px 0;
}

.qr-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  justify-content: center;
}

.btn-primary, .btn-secondary, .btn-link {
  padding: 10px 20px;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  text-decoration: none;
  display: inline-block;
  transition: all 0.3s ease;
}

.btn-primary {
  background: #007bff;
  color: white;
}

.btn-secondary {
  background: #6c757d;
  color: white;
}

.btn-link {
  background: #28a745;
  color: white;
}

.json-preview {
  background: #f8f9fa;
  border: 1px solid #e9ecef;
  border-radius: 4px;
  padding: 15px;
  overflow-x: auto;
  font-size: 12px;
  max-height: 400px;
  overflow-y: auto;
}

.loading {
  text-align: center;
  padding: 40px;
  color: #6c757d;
}

.error {
  background: #f8d7da;
  color: #721c24;
  padding: 15px;
  border-radius: 5px;
  border: 1px solid #f5c6cb;
}
```

---

## 🔧 Environment Variables

```env
# Frontend Environment Variables
REACT_APP_API_URL=http://localhost:8000
REACT_APP_API_KEY=your_api_key_here
REACT_APP_QR_CODE_SIZE=300
REACT_APP_DEFAULT_QR_POSITION=right-bottom
```

---

## 📋 Integration Checklist

- [ ] Set up API key authentication
- [ ] Create API client with error handling
- [ ] Implement credential display component
- [ ] Add QR code display and download functionality
- [ ] Create certificate generation with QR overlay
- [ ] Add offline verification capabilities
- [ ] Implement error handling and loading states
- [ ] Add responsive design for mobile devices
- [ ] Test QR code scanning functionality
- [ ] Validate blockchain verification links

---

## 🚀 Next Steps

1. **Implement the components** using the provided code examples
2. **Test the API integration** with your credential data
3. **Customize the UI** to match your application design
4. **Add certificate PDF generation** with QR code overlay
5. **Implement QR code scanning** for verification
6. **Add analytics** to track QR code usage

This comprehensive integration plan provides everything needed to implement the QR code system in your frontend application! 🎉
