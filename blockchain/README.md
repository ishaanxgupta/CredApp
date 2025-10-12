# 🏗️ CredHub Blockchain Integration

This folder contains the blockchain integration for CredHub, implementing a **hybrid trust layer** for credential verification.

## 🎯 Architecture Overview

CredHub uses a **hybrid blockchain architecture** where:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Issuer        │    │   CredHub DB     │    │   Blockchain    │
│ (University)    │───▶│  (Full Creds)    │    │ (Trust Layer)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
   Issue Credential      Store PDF/JSON-LD         Store Hash Only
   (PDF/JSON-LD)         + Metadata                + Verification Data
```

### Key Components

1. **Smart Contracts** (`contracts/`)
   - `IssuerRegistry.sol` - Manages verified credential issuers
   - `CredentialRegistry.sol` - Stores credential hashes and verification data

2. **Integration Layer** (`services/`)
   - `blockchain_service.py` - Main blockchain interaction service
   - `contract_interfaces.py` - Smart contract interfaces
   - `verification_service.py` - Credential verification logic

3. **Configuration** (`config/`)
   - `blockchain_config.py` - Network and contract configuration

4. **Deployment** (`scripts/`)
   - `deploy-mumbai.cjs` - Deploy to Mumbai testnet
   - `deploy-production.cjs` - Deploy to Polygon mainnet

## 🚀 Quick Start

### 1. Environment Setup

```bash
# Copy environment template
cp env.example .env

# Edit .env with your credentials
PRIVATE_KEY=your_private_key_here
POLYGONSCAN_API_KEY=your_polygonscan_api_key_here
WALLET_ADDRESS=your_wallet_address_here
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Compile Contracts

```bash
npm run compile
```

### 4. Deploy to Testnet (Mumbai)

```bash
# Get test MATIC from faucet: https://faucet.polygon.technology/
npm run deploy:mumbai
```

### 5. Deploy to Mainnet (Polygon)

```bash
npm run deploy:mainnet
```

## 📋 Usage Examples

### Basic Credential Flow

```python
from config.blockchain_config import get_testnet_config
from services.blockchain_service import BlockchainService
from services.verification_service import CredentialVerificationService

# Setup
config = get_testnet_config()
blockchain_service = BlockchainService(config)
verification_service = CredentialVerificationService(blockchain_service)

# Issue credential
credential_data = {
    "credential_id": "cert_001_2024",
    "learner_id": "learner_123",
    "issuer_id": "did:ethr:0x...",
    "credential_type": "Bachelor's Degree",
    "credential_data": {...}
}

result = blockchain_service.issue_credential(credential_data, learner_address)

# Verify credential
verification_result = verification_service.verify_credential_integrity(credential_data)
print(f"Valid: {verification_result.is_valid}")
```

### Run Complete Example

```bash
python examples/credential_lifecycle.py
```

## 🔧 API Reference

### BlockchainService

- `issue_credential()` - Issue a credential by storing its hash
- `verify_credential()` - Verify a credential against blockchain
- `revoke_credential()` - Revoke a credential
- `register_issuer()` - Register a new issuer (admin only)

### CredentialVerificationService

- `verify_credential_integrity()` - Verify credential hash integrity
- `verify_credential_ownership()` - Verify credential ownership
- `batch_verify_credentials()` - Batch verify multiple credentials
- `get_verification_report()` - Generate comprehensive verification report

## 🌐 Supported Networks

| Network | Chain ID | Currency | Status |
|---------|----------|----------|--------|
| Mumbai Testnet | 80001 | MATIC | ✅ Active |
| Polygon Mainnet | 137 | MATIC | ✅ Active |
| Local Hardhat | 31337 | ETH | ✅ Development |

## 💰 Cost Estimation

### Deployment Costs (Approximate)
- **Mumbai Testnet**: Free (test MATIC)
- **Polygon Mainnet**: ~0.001-0.01 MATIC

### Transaction Costs (Approximate)
- **Issue Credential**: ~0.0001-0.001 MATIC
- **Verify Credential**: ~0.00005-0.0005 MATIC
- **Register Issuer**: ~0.001-0.01 MATIC

## 🔒 Security Features

1. **Issuer Registry** - Only registered issuers can issue credentials
2. **Hash Verification** - Credential integrity verified via SHA-256 hashes
3. **Revocation Support** - Credentials can be revoked with reason
4. **Expiration Support** - Credentials can have expiration dates
5. **Access Control** - Admin-only functions for registry management

## 📊 Verification Process

1. **Hash Calculation** - Calculate SHA-256 hash of credential data
2. **Blockchain Lookup** - Check if hash exists on blockchain
3. **Issuer Verification** - Verify issuer is registered and active
4. **Expiration Check** - Check if credential has expired
5. **Revocation Check** - Check if credential has been revoked
6. **Ownership Verification** - Verify credential ownership

## 🛠️ Development

### Project Structure

```
blockchain/
├── contracts/              # Smart contracts
│   ├── IssuerRegistry.sol
│   └── CredentialRegistry.sol
├── services/              # Python integration layer
│   ├── blockchain_service.py
│   ├── contract_interfaces.py
│   └── verification_service.py
├── config/               # Configuration
│   └── blockchain_config.py
├── scripts/              # Deployment scripts
│   ├── deploy-mumbai.cjs
│   └── deploy-production.cjs
├── examples/             # Usage examples
│   └── credential_lifecycle.py
└── artifacts/            # Compiled contracts
```

### Testing

```bash
# Run credential lifecycle example
python examples/credential_lifecycle.py

# Test blockchain connection
python -c "
from config.blockchain_config import get_testnet_config
from services.blockchain_service import BlockchainService
config = get_testnet_config()
service = BlockchainService(config)
print('✅ Blockchain connection successful')
"
```

## 📚 Documentation

- [Production Deployment Guide](PRODUCTION_DEPLOYMENT_GUIDE.md)
- [Smart Contract Documentation](contracts/)
- [API Reference](services/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

MIT License - see [LICENSE](../LICENSE) for details.

## 🆘 Support

- Check the [troubleshooting guide](PRODUCTION_DEPLOYMENT_GUIDE.md#troubleshooting)
- Review [Polygon documentation](https://docs.polygon.technology/)
- Join [Polygon Discord](https://discord.gg/polygon)

---

**CredHub Blockchain Integration** - Building trust in credentials through blockchain technology 🚀
