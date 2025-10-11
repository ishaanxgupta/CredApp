# Issuer Verification & API Key Management

Complete implementation of issuer verification workflow and API key authentication for credential submission.

## 🎯 Overview

This system implements a multi-step verification process for educational institutions (like PhysicsWallah, BYJU'S, etc.) to become verified issuers and use API keys to submit credentials.

## 📋 Features Implemented

### 1. Frontend - Institution Dashboard (`InstitutionDashboard.tsx`)

#### **Step-by-Step Verification Form**
- **Step 1: Organization Details**
  - Organization Name
  - Organization Type (Educational Institution, University, Training Center, etc.)
  - Registration Number
  - Year Established
  - Official Website

- **Step 2: Government Documents**
  - Government ID Type (PAN, CIN, LLPIN, Trust Registration)
  - Government ID Number
  - Tax ID / GSTIN
  - Registration Certificate URL

- **Step 3: Contact Information**
  - Official Email
  - Official Phone
  - Complete Address (Address Line 1, Line 2, City, State, Postal Code, Country)

- **Step 4: Authorized Representative**
  - Representative Name
  - Designation
  - Representative Email
  - Representative Phone
  - ID Proof URL (Aadhaar/PAN/Passport)

#### **API Key Management Dashboard**
- Generate new API keys with custom names
- View all API keys (masked by default)
- Copy API keys to clipboard
- Revoke API keys
- Track last usage time
- One-time display of generated keys with warning

#### **Status States**
- **Not Submitted**: Shows verification form
- **Pending**: Shows waiting message
- **Rejected**: Shows error with support contact
- **Verified**: Shows API key management dashboard

---

### 2. Backend API Endpoints

#### **Verification Endpoints**

##### POST `/api/v1/issuer/submit-verification`
Submit issuer verification request.

**Request Body:**
```json
{
  "organization_name": "PhysicsWallah",
  "organization_type": "online_platform",
  "registration_number": "REG123456",
  "year_established": "2020",
  "website": "https://www.pw.live",
  "govt_id_type": "cin",
  "govt_id_number": "U12345MH2020PTC123456",
  "tax_id": "29ABCDE1234F1Z5",
  "registration_certificate_url": "https://drive.google.com/...",
  "official_email": "contact@pw.live",
  "official_phone": "+91 9876543210",
  "address_line1": "123 Education Street",
  "address_line2": "Sector 15",
  "city": "Noida",
  "state": "Uttar Pradesh",
  "postal_code": "201301",
  "country": "India",
  "representative_name": "Alakh Pandey",
  "representative_designation": "CEO",
  "representative_email": "alakh@pw.live",
  "representative_phone": "+91 9876543210",
  "representative_id_proof_url": "https://drive.google.com/..."
}
```

**Response:**
```json
{
  "message": "Verification request submitted successfully",
  "status": "pending"
}
```

##### GET `/api/v1/issuer/verification-status`
Get current verification status.

**Headers:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Response:**
```json
{
  "status": "verified",
  "submitted_at": "2025-10-07T10:00:00",
  "verified_at": "2025-10-08T15:30:00",
  "rejected_at": null,
  "rejection_reason": null
}
```

#### **API Key Management Endpoints**

##### POST `/api/v1/issuer/api-keys`
Generate a new API key (requires verified status).

**Request Body:**
```json
{
  "name": "Production API Key"
}
```

**Response:**
```json
{
  "api_key": "ck_abc123xyz789...",
  "key_id": "507f1f77bcf86cd799439011",
  "message": "API key generated successfully. Store it securely as it won't be shown again."
}
```

##### GET `/api/v1/issuer/api-keys`
List all active API keys.

**Response:**
```json
{
  "api_keys": [
    {
      "_id": "507f1f77bcf86cd799439011",
      "key": "ck_abc123xyz789...",
      "name": "Production API Key",
      "created_at": "2025-10-07T10:00:00",
      "last_used": "2025-10-07T15:30:00",
      "is_active": true
    }
  ]
}
```

##### DELETE `/api/v1/issuer/api-keys/{key_id}`
Revoke an API key.

**Response:**
```json
{
  "message": "API key revoked successfully"
}
```

---

### 3. API Key Authentication

#### **Updated Credential Submission Endpoints**

The following endpoints now require API key authentication instead of JWT:

##### POST `/api/v1/issuer/credentials`
Submit a single credential (requires API key).

**Headers:**
```
X-API-Key: ck_abc123xyz789...
Content-Type: application/json
```

**Request Body:**
```json
{
  "learner_id": "507f1f77bcf86cd799439011",
  "credential_type": "certificate",
  "credential_title": "Python Programming Certificate",
  "credential_data": {
    "course_name": "Advanced Python",
    "grade": "A+",
    "completion_date": "2025-10-01"
  }
}
```

##### POST `/api/v1/issuer/credentials/bulk`
Submit multiple credentials in bulk (requires API key).

**Headers:**
```
X-API-Key: ck_abc123xyz789...
Content-Type: application/json
```

---

### 4. API Key Validation Middleware

Created `validate_api_key()` dependency in `dependencies.py`:

**Features:**
- ✅ Validates API key from `X-API-Key` header
- ✅ Checks if API key is active
- ✅ Verifies issuer verification status
- ✅ Updates last used timestamp
- ✅ Returns user ID for the issuer
- ✅ Proper error handling with HTTP 401/403

**Usage in Routes:**
```python
@router.post("/credentials")
async def submit_credential(
    credential_data: CredentialSubmission,
    issuer_id: str = Depends(validate_api_key),  # ← API key validation
    db: AsyncIOMotorDatabase = DatabaseDep
):
    # issuer_id is now populated from validated API key
    pass
```

---

## 🗄️ MongoDB Collections

### 1. `issuer_verifications`
Stores issuer verification requests and status.

```javascript
{
  _id: ObjectId,
  user_id: ObjectId,  // Reference to users collection
  status: "pending" | "verified" | "rejected" | "not_submitted",
  organization_name: String,
  organization_type: String,
  registration_number: String,
  year_established: String,
  website: String,
  govt_id_type: String,
  govt_id_number: String,
  tax_id: String,
  registration_certificate_url: String,
  official_email: String,
  official_phone: String,
  address_line1: String,
  address_line2: String,
  city: String,
  state: String,
  postal_code: String,
  country: String,
  representative_name: String,
  representative_designation: String,
  representative_email: String,
  representative_phone: String,
  representative_id_proof_url: String,
  submitted_at: DateTime,
  verified_at: DateTime,
  rejected_at: DateTime,
  rejection_reason: String
}
```

### 2. `issuer_api_keys`
Stores API keys for verified issuers.

```javascript
{
  _id: ObjectId,
  user_id: ObjectId,  // Reference to users collection
  key: String,  // Format: "ck_<random_token>"
  name: String,
  created_at: DateTime,
  last_used: DateTime,
  is_active: Boolean,
  revoked_at: DateTime
}
```

---

## 🔐 Security Features

### API Key Format
- Prefix: `ck_` (credential key)
- Random token: 32-byte URL-safe base64 encoded
- Example: `ck_8dh3jsk2_9sk3hd8_kd8sk2_js8dks3`

### Security Measures
1. ✅ API keys stored in plain text (for validation) but never re-shown to user
2. ✅ One-time display during generation with warning
3. ✅ Last used timestamp tracking
4. ✅ Active/inactive status flag
5. ✅ Verification status check on every API call
6. ✅ Rate limiting ready (can be added)

---

## 🚀 Usage Flow

### For Issuers (Educational Institutions)

1. **Register/Login** as issuer
2. **Complete 4-step verification** form
3. **Wait for admin approval** (status: pending)
4. **Once verified**, access API key dashboard
5. **Generate API key** with a descriptive name
6. **Copy and store** API key securely
7. **Use API key** to submit credentials via API

### For API Integration

```bash
# Submit a credential
curl -X POST http://localhost:8000/api/v1/issuer/credentials \
  -H "X-API-Key: ck_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "learner_id": "507f1f77bcf86cd799439011",
    "credential_type": "certificate",
    "credential_title": "Python Certification"
  }'
```

---

## 🎨 UI Components

### Stepper Component
- Material-UI Stepper with 4 steps
- Progress tracking
- Back/Next navigation
- Form validation per step

### API Key Display
- Masked by default (shows as password field)
- Toggle visibility with eye icon
- Copy to clipboard button
- Delete/Revoke button
- Last used timestamp

### Status Chips
- ✅ **Verified** - Green chip with checkmark
- ⏳ **Pending** - Orange warning icon
- ❌ **Rejected** - Red error icon

---

## 🔄 Admin Workflow (To be implemented)

Admins can approve/reject verification requests:

```python
# Update verification status
await db.issuer_verifications.update_one(
    {"_id": ObjectId(verification_id)},
    {
        "$set": {
            "status": "verified",
            "verified_at": datetime.utcnow()
        }
    }
)
```

---

## 📝 Next Steps

1. **Admin Panel** to approve/reject verifications
2. **Email notifications** for verification status changes
3. **Rate limiting** for API key usage
4. **Usage analytics** per API key
5. **Webhook notifications** for credential events
6. **API key scopes** (read-only, write-only, etc.)

---

## 🧪 Testing

### Test Verification Submission
```bash
curl -X POST http://localhost:8000/api/v1/issuer/submit-verification \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d @verification_data.json
```

### Test API Key Generation
```bash
curl -X POST http://localhost:8000/api/v1/issuer/api-keys \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test API Key"}'
```

### Test Credential Submission with API Key
```bash
curl -X POST http://localhost:8000/api/v1/issuer/credentials \
  -H "X-API-Key: ck_your_generated_key" \
  -H "Content-Type: application/json" \
  -d @credential_data.json
```

---

## ✅ Implementation Checklist

- [x] Frontend verification form with 4 steps
- [x] Frontend API key management dashboard
- [x] Backend verification submission endpoint
- [x] Backend verification status endpoint
- [x] Backend API key generation endpoint
- [x] Backend API key listing endpoint
- [x] Backend API key revocation endpoint
- [x] API key validation middleware
- [x] Updated credential submission to use API keys
- [x] MongoDB collections schema
- [x] Security measures implemented
- [ ] Admin approval interface
- [ ] Email notifications
- [ ] Rate limiting
- [ ] Usage analytics

---

## 📄 License
MIT







