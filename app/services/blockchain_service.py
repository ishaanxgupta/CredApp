"""
Blockchain service integration for CredHub backend
Handles all blockchain interactions with deployed contracts
"""

import hashlib
import json
import os
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from eth_account import Account
import requests

from ..utils.logger import get_logger

logger = get_logger("blockchain_service")


class BlockchainConfig:
    """Configuration for blockchain connections"""
    
    def __init__(self):
        # Load from environment variables or use defaults for Amoy testnet
        self.network = os.getenv("BLOCKCHAIN_NETWORK", "amoy")
        self.rpc_url = os.getenv("BLOCKCHAIN_RPC_URL", "https://rpc-amoy.polygon.technology")
        self.chain_id = int(os.getenv("BLOCKCHAIN_CHAIN_ID", "80002"))
        self.private_key = os.getenv("BLOCKCHAIN_PRIVATE_KEY", "")
        
        # Contract addresses from your deployment
        self.issuer_registry_address = os.getenv(
            "ISSUER_REGISTRY_ADDRESS", 
            "0x5868c5Fa4eeF9db8Ca998F16845CCffA3B85C472"
        )
        self.credential_registry_address = os.getenv(
            "CREDENTIAL_REGISTRY_ADDRESS", 
            "0xE70530BdAe091D597840FD787f5Dafa7c6Ef796A"
        )


class BlockchainService:
    """Service for blockchain interactions with deployed contracts"""
    
    def __init__(self):
        self.config = BlockchainConfig()
        self.w3 = self._setup_web3()
        self.account = self._setup_account()
        
        # Contract ABIs (simplified for your deployed contracts)
        self.issuer_registry_abi = self._get_issuer_registry_abi()
        self.credential_registry_abi = self._get_credential_registry_abi()
        
        # Initialize contracts
        self.issuer_registry = self.w3.eth.contract(
            address=self.config.issuer_registry_address,
            abi=self.issuer_registry_abi
        )
        self.credential_registry = self.w3.eth.contract(
            address=self.config.credential_registry_address,
            abi=self.credential_registry_abi
        )
    
    def _setup_web3(self) -> Web3:
        """Setup Web3 connection"""
        w3 = Web3(Web3.HTTPProvider(self.config.rpc_url))
        
        # Add PoA middleware for Polygon networks
        if self.config.chain_id in [80001, 80002, 137]:  # Mumbai, Amoy, or Polygon
            w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        
        if not w3.is_connected():
            raise ConnectionError(f"Failed to connect to {self.config.network}")
        
        logger.info(f"Connected to {self.config.network} network")
        return w3
    
    def _setup_account(self) -> Account:
        """Setup account from private key"""
        if not self.config.private_key:
            logger.warning("No private key provided - some functions will be read-only")
            return None
        
        return Account.from_key(self.config.private_key)
    
    def _get_issuer_registry_abi(self) -> List[Dict]:
        """Get IssuerRegistry contract ABI"""
        return [
            {
                "inputs": [
                    {"internalType": "address", "name": "issuerAddress", "type": "address"},
                    {"internalType": "string", "name": "issuerDid", "type": "string"},
                    {"internalType": "string", "name": "name", "type": "string"},
                    {"internalType": "string", "name": "domain", "type": "string"},
                    {"internalType": "string", "name": "metadataUri", "type": "string"}
                ],
                "name": "registerIssuer",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "issuerAddress", "type": "address"}],
                "name": "isIssuerActive",
                "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "issuerAddress", "type": "address"}],
                "name": "getIssuer",
                "outputs": [
                    {"internalType": "address", "name": "issuerAddress", "type": "address"},
                    {"internalType": "string", "name": "issuerDid", "type": "string"},
                    {"internalType": "string", "name": "name", "type": "string"},
                    {"internalType": "string", "name": "domain", "type": "string"},
                    {"internalType": "string", "name": "metadataUri", "type": "string"},
                    {"internalType": "bool", "name": "isActive", "type": "bool"},
                    {"internalType": "uint256", "name": "registeredAt", "type": "uint256"}
                ],
                "stateMutability": "view",
                "type": "function"
            }
        ]
    
    def _get_credential_registry_abi(self) -> List[Dict]:
        """Get CredentialRegistry contract ABI"""
        return [
            {
                "inputs": [
                    {"internalType": "bytes32", "name": "credentialHash", "type": "bytes32"},
                    {"internalType": "address", "name": "learnerAddress", "type": "address"},
                    {"internalType": "string", "name": "credentialId", "type": "string"},
                    {"internalType": "string", "name": "issuerDid", "type": "string"},
                    {"internalType": "string", "name": "credentialType", "type": "string"},
                    {"internalType": "uint256", "name": "expiresAt", "type": "uint256"},
                    {"internalType": "string", "name": "metadataUri", "type": "string"}
                ],
                "name": "issueCredential",
                "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "bytes32", "name": "credentialHash", "type": "bytes32"}],
                "name": "verifyCredential",
                "outputs": [
                    {"internalType": "bool", "name": "isValid", "type": "bool"},
                    {"internalType": "address", "name": "issuerAddress", "type": "address"},
                    {"internalType": "address", "name": "learnerAddress", "type": "address"},
                    {"internalType": "uint256", "name": "issuedAt", "type": "uint256"},
                    {"internalType": "uint256", "name": "expiresAt", "type": "uint256"},
                    {"internalType": "bool", "name": "isExpired", "type": "bool"},
                    {"internalType": "bool", "name": "isRevoked", "type": "bool"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "bytes32", "name": "credentialHash", "type": "bytes32"}],
                "name": "getCredential",
                "outputs": [
                    {"internalType": "bytes32", "name": "credentialHash", "type": "bytes32"},
                    {"internalType": "address", "name": "issuerAddress", "type": "address"},
                    {"internalType": "address", "name": "learnerAddress", "type": "address"},
                    {"internalType": "string", "name": "credentialId", "type": "string"},
                    {"internalType": "string", "name": "issuerDid", "type": "string"},
                    {"internalType": "string", "name": "credentialType", "type": "string"},
                    {"internalType": "uint256", "name": "issuedAt", "type": "uint256"},
                    {"internalType": "uint256", "name": "expiresAt", "type": "uint256"},
                    {"internalType": "bool", "name": "isActive", "type": "bool"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "learnerAddress", "type": "address"}],
                "name": "getLearnerCredentials",
                "outputs": [{"internalType": "bytes32[]", "name": "", "type": "bytes32[]"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
    
    def calculate_credential_hash(self, credential_data: Dict[str, Any]) -> str:
        """
        Calculate SHA-256 hash of credential data for blockchain storage
        
        Args:
            credential_data: Dictionary containing credential information
        
        Returns:
            Hex string of the SHA-256 hash
        """
        # Extract data from database structure
        credential_id = str(credential_data.get("_id", ""))
        vc_payload = credential_data.get("vc_payload", {})
        credential_subject = vc_payload.get("credentialSubject", {})
        issuer_info = vc_payload.get("issuer", {})
        
        # Create deterministic string representation
        hash_data = {
            "credential_id": credential_id,
            "learner_name": credential_subject.get("name", ""),
            "learner_address": credential_subject.get("learner_address", ""),
            "issuer_name": issuer_info.get("name", ""),
            "issuer_did": issuer_info.get("did", ""),
            "credential_type": credential_data.get("credential_type", ""),
            "course": credential_subject.get("course", ""),
            "grade": credential_subject.get("grade", ""),
            "completion_date": credential_subject.get("completion_date", ""),
            "issued_at": vc_payload.get("issuanceDate", ""),
            "credential_schema": vc_payload.get("credentialSchema", {}),
            "context": vc_payload.get("@context", []),
            "type": vc_payload.get("type", [])
        }
        
        # Sort keys for deterministic JSON
        sorted_data = json.dumps(hash_data, sort_keys=True, separators=(',', ':'))
        
        # Calculate SHA-256 hash
        hash_bytes = hashlib.sha256(sorted_data.encode('utf-8')).digest()
        return "0x" + hash_bytes.hex()
    
    def check_credential_exists(self, credential_hash: str) -> bool:
        """
        Check if a credential hash already exists on blockchain
        
        Args:
            credential_hash: SHA-256 hash of the credential
        
        Returns:
            True if credential exists, False otherwise
        """
        try:
            # Convert hex string to bytes32
            hash_bytes = bytes.fromhex(credential_hash[2:])  # Remove 0x prefix
            
            # Call verifyCredential to check if it exists
            result = self.credential_registry.functions.verifyCredential(hash_bytes).call()
            
            # If isValid is True, the credential exists
            return result[0]  # isValid is the first return value
            
        except Exception as e:
            logger.error(f"Error checking credential existence: {e}")
            return False
    
    def issue_credential_on_blockchain(
        self,
        credential_data: Dict[str, Any],
        learner_address: str,
        expires_at: Optional[int] = None,
        metadata_uri: str = ""
    ) -> Dict[str, Any]:
        """
        Issue a credential by storing its hash on blockchain
        
        Args:
            credential_data: Dictionary containing credential information
            learner_address: Ethereum address of the learner
            expires_at: Expiration timestamp (None for no expiration)
            metadata_uri: URI pointing to full credential data
        
        Returns:
            Dictionary with transaction details
        """
        if not self.account:
            raise ValueError("Private key required for issuing credentials")
        
        try:
            # Calculate credential hash
            credential_hash = self.calculate_credential_hash(credential_data)
            hash_bytes = bytes.fromhex(credential_hash[2:])
            
            # Check if credential already exists
            if self.check_credential_exists(credential_hash):
                logger.warning(f"Credential with hash {credential_hash} already exists")
                return {
                    "status": "duplicate",
                    "credential_hash": credential_hash,
                    "message": "Credential already exists on blockchain"
                }
            
            # Prepare transaction
            transaction = self.credential_registry.functions.issueCredential(
                hash_bytes,
                learner_address,
                str(credential_data.get("credential_id", "")),
                credential_data.get("issuer_did", ""),
                credential_data.get("credential_type", ""),
                expires_at or 0,
                metadata_uri
            ).build_transaction({
                'from': self.account.address,
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
            })
            
            # Sign and send transaction
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
            
            logger.info(f"Credential issued on blockchain with tx hash: {tx_hash.hex()}")
            
            return {
                "transaction_hash": tx_hash.hex(),
                "credential_hash": credential_hash,
                "credential_id": credential_data.get("credential_id", ""),
                "learner_address": learner_address,
                "block_number": None,  # Will be filled when mined
                "status": "pending"
            }
            
        except Exception as e:
            logger.error(f"Error issuing credential on blockchain: {e}")
            raise
    
    def verify_credential_on_blockchain(self, credential_hash: str) -> Dict[str, Any]:
        """
        Verify a credential by checking its hash on blockchain
        
        Args:
            credential_hash: SHA-256 hash of the credential
        
        Returns:
            Dictionary with verification results
        """
        try:
            # Convert hex string to bytes32
            hash_bytes = bytes.fromhex(credential_hash[2:])
            
            # Call verifyCredential function
            result = self.credential_registry.functions.verifyCredential(hash_bytes).call()
            
            # Unpack the result tuple
            (is_valid, issuer_address, learner_address, issued_at, expires_at, is_expired, is_revoked) = result
            
            return {
                "credential_hash": credential_hash,
                "is_valid": is_valid,
                "issuer_address": issuer_address,
                "learner_address": learner_address,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "is_expired": is_expired,
                "is_revoked": is_revoked,
                "verified_at": int(datetime.utcnow().timestamp())
            }
            
        except Exception as e:
            logger.error(f"Error verifying credential on blockchain: {e}")
            return {
                "credential_hash": credential_hash,
                "is_valid": False,
                "error": str(e),
                "verified_at": int(datetime.utcnow().timestamp())
            }
    
    def get_credential_info(self, credential_hash: str) -> Dict[str, Any]:
        """Get detailed credential information from blockchain"""
        try:
            hash_bytes = bytes.fromhex(credential_hash[2:])
            
            result = self.credential_registry.functions.getCredential(hash_bytes).call()
            
            # Unpack the result tuple
            (cred_hash, issuer_address, learner_address, credential_id, 
             issuer_did, credential_type, issued_at, expires_at, is_active) = result
            
            return {
                "credential_hash": "0x" + cred_hash.hex(),
                "issuer_address": issuer_address,
                "learner_address": learner_address,
                "credential_id": credential_id,
                "issuer_did": issuer_did,
                "credential_type": credential_type,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "is_active": is_active
            }
            
        except Exception as e:
            logger.error(f"Error getting credential info: {e}")
            return {"error": str(e)}
    
    def get_learner_credentials(self, learner_address: str) -> List[str]:
        """Get all credential hashes for a learner"""
        try:
            credential_hashes = self.credential_registry.functions.getLearnerCredentials(learner_address).call()
            return ["0x" + ch.hex() for ch in credential_hashes]
            
        except Exception as e:
            logger.error(f"Error getting learner credentials: {e}")
            return []
    
    def wait_for_transaction(self, tx_hash: str, timeout: int = 300) -> Dict[str, Any]:
        """Wait for transaction to be mined and get receipt"""
        try:
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
            
            return {
                "transaction_hash": tx_hash,
                "status": "success" if receipt.status == 1 else "failed",
                "block_number": receipt.blockNumber,
                "gas_used": receipt.gasUsed,
                "effective_gas_price": receipt.effectiveGasPrice,
                "contract_address": receipt.contractAddress
            }
            
        except Exception as e:
            logger.error(f"Error waiting for transaction: {e}")
            return {
                "transaction_hash": tx_hash,
                "status": "failed",
                "error": str(e)
            }
    
    def get_transaction_status(self, tx_hash: str) -> Dict[str, Any]:
        """Get current transaction status"""
        try:
            tx = self.w3.eth.get_transaction(tx_hash)
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            
            return {
                "transaction_hash": tx_hash,
                "status": "success" if receipt.status == 1 else "failed",
                "block_number": receipt.blockNumber,
                "gas_used": receipt.gasUsed,
                "from": tx['from'],
                "to": tx['to']
            }
            
        except Exception as e:
            return {
                "transaction_hash": tx_hash,
                "status": "pending",
                "error": str(e)
            }
    
    def get_network_info(self) -> Dict[str, Any]:
        """Get network information"""
        try:
            latest_block = self.w3.eth.get_block('latest')
            
            return {
                "network_name": self.config.network,
                "chain_id": self.config.chain_id,
                "latest_block": latest_block.number,
                "gas_price_gwei": self.w3.from_wei(self.w3.eth.gas_price, 'gwei'),
                "account_address": self.account.address if self.account else None,
                "account_balance": self.get_account_balance() if self.account else None
            }
            
        except Exception as e:
            logger.error(f"Error getting network info: {e}")
            return {"error": str(e)}
    
    def get_account_balance(self) -> float:
        """Get account balance in native currency"""
        if not self.account:
            return 0.0
            
        try:
            balance_wei = self.w3.eth.get_balance(self.account.address)
            balance_eth = self.w3.from_wei(balance_wei, 'ether')
            return float(balance_eth)
        except Exception as e:
            logger.error(f"Error getting account balance: {e}")
            return 0.0
    
    def is_issuer_active(self, issuer_address: str) -> bool:
        """Check if an issuer is active on blockchain"""
        try:
            return self.issuer_registry.functions.isIssuerActive(issuer_address).call()
        except Exception as e:
            logger.error(f"Error checking issuer status: {e}")
            return False
    
    def get_issuer_info(self, issuer_address: str) -> Dict[str, Any]:
        """Get issuer information from blockchain"""
        try:
            result = self.issuer_registry.functions.getIssuer(issuer_address).call()
            
            (issuer_addr, issuer_did, name, domain, metadata_uri, is_active, registered_at) = result
            
            return {
                "issuer_address": issuer_addr,
                "issuer_did": issuer_did,
                "name": name,
                "domain": domain,
                "metadata_uri": metadata_uri,
                "is_active": is_active,
                "registered_at": registered_at
            }
            
        except Exception as e:
            logger.error(f"Error getting issuer info: {e}")
            return {"error": str(e)}
    
    def batch_issue_credentials(
        self,
        credentials_data: List[Dict[str, Any]],
        issuer_did: str,
        expires_at: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Issue multiple credentials in a single transaction (if supported by contract)
        
        Args:
            credentials_data: List of credential data
            issuer_did: Issuer's DID
            expires_at: Expiration timestamp for all credentials
        
        Returns:
            Batch issuance result
        """
        if not self.account:
            raise ValueError("Private key required for batch issuing credentials")
        
        try:
            # Calculate hashes for all credentials
            credential_hashes = []
            credential_infos = []
            
            for cred_data in credentials_data:
                credential_hash = self.calculate_credential_hash(cred_data)
                
                # Check if credential already exists
                if self.check_credential_exists(credential_hash):
                    logger.warning(f"Credential with hash {credential_hash} already exists")
                    continue
                
                credential_hashes.append(credential_hash)
                credential_infos.append({
                    "hash": credential_hash,
                    "learner_address": cred_data.get("learner_address", "0x0000000000000000000000000000000000000000"),
                    "credential_id": cred_data.get("credential_id", ""),
                    "credential_type": cred_data.get("credential_type", ""),
                    "credential_data": cred_data
                })
            
            if not credential_hashes:
                return {
                    "status": "no_valid_credentials",
                    "message": "No valid credentials to issue",
                    "total_processed": len(credentials_data),
                    "successful": 0,
                    "failed": len(credentials_data)
                }
            
            # For now, issue credentials individually
            # In production, implement actual batch issuance in smart contract
            successful_transactions = []
            failed_credentials = []
            
            for i, cred_info in enumerate(credential_infos):
                try:
                    hash_bytes = bytes.fromhex(cred_info["hash"][2:])
                    
                    # Build transaction
                    transaction = self.credential_registry.functions.issueCredential(
                        hash_bytes,
                        cred_info["learner_address"],
                        cred_info["credential_id"],
                        issuer_did,
                        cred_info["credential_type"],
                        expires_at or 0,
                        ""
                    ).build_transaction({
                        'from': self.account.address,
                        'gas': 500000,
                        'gasPrice': self.w3.eth.gas_price,
                        'nonce': self.w3.eth.get_transaction_count(self.account.address),
                    })
                    
                    # Sign and send transaction
                    signed_txn = self.w3.eth.account.sign_transaction(transaction, self.account.key)
                    tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
                    
                    successful_transactions.append({
                        "index": i,
                        "credential_hash": cred_info["hash"],
                        "transaction_hash": tx_hash.hex(),
                        "learner_address": cred_info["learner_address"]
                    })
                    
                except Exception as e:
                    failed_credentials.append({
                        "index": i,
                        "credential_hash": cred_info["hash"],
                        "error": str(e)
                    })
            
            logger.info(f"Batch credential issuance completed: {len(successful_transactions)} successful, {len(failed_credentials)} failed")
            
            return {
                "status": "completed",
                "total_processed": len(credentials_data),
                "successful": len(successful_transactions),
                "failed": len(failed_credentials),
                "successful_transactions": successful_transactions,
                "failed_credentials": failed_credentials,
                "issuer_did": issuer_did
            }
            
        except Exception as e:
            logger.error(f"Error in batch credential issuance: {e}")
            raise


# Global instance
blockchain_service = BlockchainService()
