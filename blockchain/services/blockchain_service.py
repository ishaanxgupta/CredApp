"""
Blockchain service for CredHub
Handles all blockchain interactions including credential issuance and verification
"""

import hashlib
import json
from typing import Dict, Any, Optional, List, Tuple
from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_account import Account
import requests

from .contract_interfaces import IssuerRegistryInterface, CredentialRegistryInterface
from ..config.blockchain_config import BlockchainConfig, NetworkType


class BlockchainService:
    """Service for blockchain interactions"""
    
    def __init__(self, config: BlockchainConfig):
        self.config = config
        self.w3 = self._setup_web3()
        self.account = self._setup_account()
        self.issuer_registry = self._setup_issuer_registry()
        self.credential_registry = self._setup_credential_registry()
    
    def _setup_web3(self) -> Web3:
        """Setup Web3 connection"""
        w3 = Web3(Web3.HTTPProvider(self.config.network.rpc_url))
        
        # Add PoA middleware for Polygon networks
        if self.config.network.chain_id in [80001, 137]:  # Mumbai or Polygon
            w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        
        if not w3.is_connected():
            raise ConnectionError(f"Failed to connect to {self.config.network.name}")
        
        return w3
    
    def _setup_account(self) -> Account:
        """Setup account from private key"""
        return Account.from_key(self.config.private_key)
    
    def _setup_issuer_registry(self) -> IssuerRegistryInterface:
        """Setup issuer registry contract interface"""
        return IssuerRegistryInterface(
            self.w3,
            self.config.contracts.issuer_registry_address,
            self.account
        )
    
    def _setup_credential_registry(self) -> CredentialRegistryInterface:
        """Setup credential registry contract interface"""
        return CredentialRegistryInterface(
            self.w3,
            self.config.contracts.credential_registry_address,
            self.account
        )
    
    def get_account_balance(self) -> float:
        """Get account balance in native currency"""
        balance_wei = self.w3.eth.get_balance(self.account.address)
        balance_eth = self.w3.from_wei(balance_wei, 'ether')
        return float(balance_eth)
    
    def get_gas_price(self) -> int:
        """Get current gas price"""
        return self.w3.eth.gas_price
    
    def estimate_gas(self, transaction: Dict[str, Any]) -> int:
        """Estimate gas for a transaction"""
        return self.w3.eth.estimate_gas(transaction)
    
    # Issuer Registry Methods
    
    def register_issuer(
        self,
        issuer_address: str,
        issuer_did: str,
        name: str,
        domain: str,
        metadata_uri: str = ""
    ) -> Dict[str, Any]:
        """Register a new issuer"""
        tx_hash = self.issuer_registry.register_issuer(
            issuer_address=issuer_address,
            issuer_did=issuer_did,
            name=name,
            domain=domain,
            metadata_uri=metadata_uri
        )
        
        return {
            "transaction_hash": tx_hash.hex(),
            "issuer_address": issuer_address,
            "issuer_did": issuer_did,
            "status": "pending"
        }
    
    def is_issuer_active(self, issuer_address: str) -> bool:
        """Check if an issuer is active"""
        return self.issuer_registry.is_issuer_active(issuer_address)
    
    def get_issuer_info(self, issuer_address: str) -> Dict[str, Any]:
        """Get issuer information"""
        return self.issuer_registry.get_issuer(issuer_address)
    
    def get_active_issuers(self) -> List[str]:
        """Get list of all active issuers"""
        return self.issuer_registry.get_active_issuers()
    
    # Credential Registry Methods
    
    def calculate_credential_hash(
        self,
        credential_data: Dict[str, Any],
        include_signature: bool = True
    ) -> str:
        """
        Calculate SHA-256 hash of credential data
        
        Args:
            credential_data: Dictionary containing credential information
            include_signature: Whether to include signature in hash calculation
        
        Returns:
            Hex string of the SHA-256 hash
        """
        # Create a deterministic string representation of the credential
        hash_data = {
            "credential_id": credential_data.get("credential_id", ""),
            "learner_id": credential_data.get("learner_id", ""),
            "issuer_id": credential_data.get("issuer_id", ""),
            "credential_type": credential_data.get("credential_type", ""),
            "issued_at": credential_data.get("issued_at", ""),
            "credential_data": credential_data.get("credential_data", {}),
            "metadata": credential_data.get("metadata", {})
        }
        
        if include_signature and credential_data.get("signature"):
            hash_data["signature"] = credential_data.get("signature")
        
        # Sort keys for deterministic JSON
        sorted_data = json.dumps(hash_data, sort_keys=True, separators=(',', ':'))
        
        # Calculate SHA-256 hash
        hash_bytes = hashlib.sha256(sorted_data.encode('utf-8')).digest()
        return "0x" + hash_bytes.hex()
    
    def issue_credential(
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
        # Calculate credential hash
        credential_hash = self.calculate_credential_hash(credential_data)
        
        # Issue credential on blockchain
        tx_hash = self.credential_registry.issue_credential(
            credential_hash=credential_hash,
            learner_address=learner_address,
            credential_id=credential_data.get("credential_id", ""),
            issuer_did=credential_data.get("issuer_did", ""),
            credential_type=credential_data.get("credential_type", ""),
            expires_at=expires_at or 0,
            metadata_uri=metadata_uri
        )
        
        return {
            "transaction_hash": tx_hash.hex(),
            "credential_hash": credential_hash,
            "credential_id": credential_data.get("credential_id", ""),
            "learner_address": learner_address,
            "status": "pending"
        }
    
    def verify_credential(self, credential_hash: str) -> Dict[str, Any]:
        """
        Verify a credential by checking its hash on blockchain
        
        Args:
            credential_hash: SHA-256 hash of the credential
        
        Returns:
            Dictionary with verification results
        """
        result = self.credential_registry.verify_credential(credential_hash)
        
        return {
            "credential_hash": credential_hash,
            "is_valid": result["isValid"],
            "issuer_address": result["issuerAddress"],
            "learner_address": result["learnerAddress"],
            "issued_at": result["issuedAt"],
            "expires_at": result["expiresAt"],
            "is_expired": result["isExpired"],
            "verified_at": int(self.w3.eth.get_block('latest')['timestamp'])
        }
    
    def revoke_credential(
        self,
        credential_hash: str,
        revocation_reason: str = "Credential revoked by issuer"
    ) -> Dict[str, Any]:
        """Revoke a credential"""
        tx_hash = self.credential_registry.revoke_credential(
            credential_hash=credential_hash,
            revocation_reason=revocation_reason
        )
        
        return {
            "transaction_hash": tx_hash.hex(),
            "credential_hash": credential_hash,
            "revocation_reason": revocation_reason,
            "status": "pending"
        }
    
    def get_credential_info(self, credential_hash: str) -> Dict[str, Any]:
        """Get credential information from blockchain"""
        return self.credential_registry.get_credential(credential_hash)
    
    def get_learner_credentials(self, learner_address: str) -> List[str]:
        """Get all credentials for a learner"""
        return self.credential_registry.get_learner_credentials(learner_address)
    
    def get_issuer_credentials(self, issuer_address: str) -> List[str]:
        """Get all credentials issued by an issuer"""
        return self.credential_registry.get_issuer_credentials(issuer_address)
    
    def batch_verify_credentials(self, credential_hashes: List[str]) -> List[Dict[str, Any]]:
        """Batch verify multiple credentials"""
        results = self.credential_registry.batch_verify_credentials(credential_hashes)
        
        verification_results = []
        for i, credential_hash in enumerate(credential_hashes):
            verification_results.append({
                "credential_hash": credential_hash,
                "is_valid": results[i],
                "verified_at": int(self.w3.eth.get_block('latest')['timestamp'])
            })
        
        return verification_results
    
    # Utility Methods
    
    def wait_for_transaction(self, tx_hash: str, timeout: int = 300) -> Dict[str, Any]:
        """Wait for transaction to be mined"""
        try:
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
            return {
                "transaction_hash": tx_hash,
                "status": "success" if receipt.status == 1 else "failed",
                "block_number": receipt.blockNumber,
                "gas_used": receipt.gasUsed,
                "effective_gas_price": receipt.effectiveGasPrice
            }
        except Exception as e:
            return {
                "transaction_hash": tx_hash,
                "status": "failed",
                "error": str(e)
            }
    
    def get_transaction_status(self, tx_hash: str) -> Dict[str, Any]:
        """Get transaction status"""
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
        latest_block = self.w3.eth.get_block('latest')
        
        return {
            "network_name": self.config.network.name,
            "chain_id": self.config.network.chain_id,
            "currency": self.config.network.currency,
            "explorer_url": self.config.network.explorer_url,
            "latest_block": latest_block.number,
            "gas_price_gwei": self.w3.from_wei(self.get_gas_price(), 'gwei'),
            "account_balance": self.get_account_balance(),
            "account_address": self.account.address
        }
