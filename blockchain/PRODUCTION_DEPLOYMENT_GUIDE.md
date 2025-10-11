# 🚀 CredHub Blockchain Deployment Guide

## 🏗️ Architecture Overview

CredHub uses a **hybrid blockchain architecture** where:
- **Blockchain**: Stores credential hashes and verification data (trust layer)
- **Database**: Stores full credential data (PDFs, JSON-LD, metadata)
- **Verification**: Compares off-chain credential hash with on-chain hash

### Smart Contracts
1. **IssuerRegistry.sol** - Manages verified credential issuers
2. **CredentialRegistry.sol** - Stores credential hashes and verification data

## Prerequisites

1. **MATIC Tokens**: You need at least 0.1 MATIC for gas fees
2. **Private Key**: Your wallet's private key (without 0x prefix)
3. **PolygonScan API Key**: For contract verification

## Step 1: Environment Setup

### 1.1 Create Environment File
```bash
cp env.example .env
```

### 1.2 Configure Environment Variables
Edit `.env` file:
```env
# Your wallet private key (without 0x prefix)
PRIVATE_KEY=your_private_key_here

# PolygonScan API key (optional, for verification)
POLYGONSCAN_API_KEY=your_polygonscan_api_key_here

# Your wallet address (for reference)
WALLET_ADDRESS=your_wallet_address_here
```

### 1.3 Get Test MATIC (for Mumbai testing)
Visit [Polygon Faucet](https://faucet.polygon.technology/) to get test MATIC

## Step 2: Deployment Options

### Option A: Deploy to Mumbai Testnet (Recommended First)
```bash
# Compile contracts
npm run compile

# Deploy to Mumbai testnet
npm run deploy:mumbai

# Verify contracts (optional)
npm run verify:mumbai
```

### Option B: Deploy to Polygon Mainnet
```bash
# Compile contracts
npm run compile

# Deploy to Polygon mainnet
npm run deploy:mainnet

# Verify contracts (optional)
npm run verify:mainnet
```

## Step 3: Update Backend Configuration

### 3.1 Update Blockchain Settings
After deployment, update your backend configuration with the deployed contract address:

```python
# In your backend .env or config
BLOCKCHAIN_NETWORK=polygon
BLOCKCHAIN_RPC_URL=https://polygon-rpc.com
BLOCKCHAIN_CONTRACT_ADDRESS=0xYourDeployedContractAddress
BLOCKCHAIN_PRIVATE_KEY=your_private_key
BLOCKCHAIN_CHAIN_ID=137
```

### 3.2 Update Verification Service
The backend will automatically use the real blockchain when these environment variables are set.

## Step 4: Testing Production Integration

### 4.1 Test Contract Interaction
```bash
cd ..
python -c "
from blockchain.services.blockchain_service import BlockchainService
from blockchain.config.production import get_production_config

# Test connection
config = get_production_config()
service = BlockchainService(config)
print('✅ Connected to Polygon Mainnet')
print(f'Contract Address: {config.contract_address}')
"
```

### 4.2 Test Credential Anchoring
```bash
# Test with a sample credential
python -c "
from blockchain.services.blockchain_service import BlockchainService
from blockchain.config.production import get_production_config

config = get_production_config()
service = BlockchainService(config)

# Test merkle root anchoring
result = service.anchor_merkle_root(
    merkle_root='0x1234567890abcdef...',
    issuer_did='did:ethr:0x...',
    batch_id='batch_001'
)
print('✅ Credential anchored on Polygon Mainnet')
print(f'Transaction Hash: {result[\"transaction_hash\"]}')
"
```

## Step 5: Monitor and Maintain

### 5.1 Monitor Transactions
- Check transactions on [Polygonscan](https://polygonscan.com/)
- Monitor gas usage and costs
- Set up alerts for failed transactions

### 5.2 Gas Optimization
- Monitor gas prices: [Polygon Gas Tracker](https://polygonscan.com/gastracker)
- Adjust gas prices in configuration based on network conditions
- Consider using gas estimation for dynamic pricing

### 5.3 Security Considerations
- Keep private keys secure and never commit them to version control
- Use hardware wallets for production deployments
- Regularly audit contract interactions
- Monitor for suspicious activity

## Troubleshooting

### Common Issues

1. **Insufficient Gas Error**
   ```
   Error: insufficient funds for gas
   ```
   **Solution**: Add more MATIC to your wallet

2. **Network Connection Error**
   ```
   Error: network connection failed
   ```
   **Solution**: Check RPC URL and network connectivity

3. **Contract Verification Failed**
   ```
   Error: verification failed
   ```
   **Solution**: Ensure contract source code matches deployed bytecode

4. **Private Key Error**
   ```
   Error: invalid private key
   ```
   **Solution**: Check private key format (no 0x prefix)

### Getting Help

1. Check [Polygon Documentation](https://docs.polygon.technology/)
2. Visit [Polygon Discord](https://discord.gg/polygon)
3. Check [Hardhat Documentation](https://hardhat.org/docs)

## Cost Estimation

### Deployment Costs (Approximate)
- **Mumbai Testnet**: Free (test MATIC)
- **Polygon Mainnet**: ~0.001-0.01 MATIC

### Transaction Costs (Approximate)
- **Anchor Merkle Root**: ~0.0001-0.001 MATIC
- **Verify Merkle Root**: ~0.00005-0.0005 MATIC
- **Get Anchor**: ~0.00001-0.0001 MATIC

## Security Best Practices

1. **Environment Variables**
   - Never commit `.env` files
   - Use different keys for testnet and mainnet
   - Rotate keys regularly

2. **Contract Security**
   - Audit contract code before deployment
   - Use established libraries and patterns
   - Test thoroughly on testnet first

3. **Operational Security**
   - Monitor for unusual activity
   - Set up alerts for failed transactions
   - Keep backups of deployment configurations

## Next Steps

1. Deploy to Mumbai testnet first
2. Test all functionality thoroughly
3. Deploy to Polygon mainnet
4. Update backend configuration
5. Monitor and maintain the deployment
