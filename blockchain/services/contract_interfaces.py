"""
Smart contract interfaces for CredHub blockchain interactions
"""

from typing import Dict, Any, List, Optional
from web3 import Web3
from web3.contract import Contract
from eth_account import Account
from eth_typing import HexStr


class ContractInterface:
    """Base contract interface class"""
    
    def __init__(self, w3: Web3, contract_address: str, account: Account):
        self.w3 = w3
        self.contract_address = contract_address
        self.account = account
        self.contract = None
    
    def _send_transaction(self, function_call, gas_limit: Optional[int] = None) -> HexStr:
        """Send a transaction to the blockchain"""
        # Build transaction
        transaction = function_call.build_transaction({
            'from': self.account.address,
            'gas': gas_limit or 8000000,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(self.account.address)
        })
        
        # Sign transaction
        signed_txn = self.w3.eth.account.sign_transaction(transaction, self.account.key)
        
        # Send transaction
        tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        
        return tx_hash


class IssuerRegistryInterface(ContractInterface):
    """Interface for IssuerRegistry contract"""
    
    def __init__(self, w3: Web3, contract_address: str, account: Account):
        super().__init__(w3, contract_address, account)
        self._setup_contract()
    
    def _setup_contract(self):
        """Setup contract instance with ABI"""
        # This would typically load the ABI from compiled artifacts
        # For now, we'll define the essential ABI methods
        abi = [
            {
                "inputs": [
                    {"internalType": "address", "name": "issuerAddress", "type": "address"},
                    {"internalType": "string", "name": "issuerDID", "type": "string"},
                    {"internalType": "string", "name": "name", "type": "string"},
                    {"internalType": "string", "name": "domain", "type": "string"},
                    {"internalType": "string", "name": "metadataURI", "type": "string"}
                ],
                "name": "registerIssuer",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "issuerAddress", "type": "address"}],
                "name": "isIssuerActive",
                "outputs": [{"internalType": "bool", "name": "isRegistered", "type": "bool"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "issuerAddress", "type": "address"}],
                "name": "getIssuer",
                "outputs": [
                    {
                        "components": [
                            {"internalType": "address", "name": "issuerAddress", "type": "address"},
                            {"internalType": "string", "name": "issuerDID", "type": "string"},
                            {"internalType": "string", "name": "name", "type": "string"},
                            {"internalType": "string", "name": "domain", "type": "string"},
                            {"internalType": "bool", "name": "isActive", "type": "bool"},
                            {"internalType": "uint256", "name": "registrationDate", "type": "uint256"},
                            {"internalType": "uint256", "name": "lastUpdated", "type": "uint256"},
                            {"internalType": "string", "name": "metadataURI", "type": "string"}
                        ],
                        "internalType": "struct IssuerRegistry.Issuer",
                        "name": "issuer",
                        "type": "tuple"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "getActiveIssuers",
                "outputs": [{"internalType": "address[]", "name": "activeIssuers", "type": "address[]"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
        
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=abi
        )
    
    def register_issuer(
        self,
        issuer_address: str,
        issuer_did: str,
        name: str,
        domain: str,
        metadata_uri: str = ""
    ) -> HexStr:
        """Register a new issuer"""
        function_call = self.contract.functions.registerIssuer(
            issuer_address,
            issuer_did,
            name,
            domain,
            metadata_uri
        )
        return self._send_transaction(function_call)
    
    def is_issuer_active(self, issuer_address: str) -> bool:
        """Check if an issuer is active"""
        result = self.contract.functions.isIssuerActive(issuer_address).call()
        return result
    
    def get_issuer(self, issuer_address: str) -> Dict[str, Any]:
        """Get issuer information"""
        result = self.contract.functions.getIssuer(issuer_address).call()
        return {
            "issuer_address": result[0],
            "issuer_did": result[1],
            "name": result[2],
            "domain": result[3],
            "is_active": result[4],
            "registration_date": result[5],
            "last_updated": result[6],
            "metadata_uri": result[7]
        }
    
    def get_active_issuers(self) -> List[str]:
        """Get list of all active issuers"""
        result = self.contract.functions.getActiveIssuers().call()
        return [address for address in result]


class CredentialRegistryInterface(ContractInterface):
    """Interface for CredentialRegistry contract"""
    
    def __init__(self, w3: Web3, contract_address: str, account: Account):
        super().__init__(w3, contract_address, account)
        self._setup_contract()
    
    def _setup_contract(self):
        """Setup contract instance with ABI"""
        abi = [
            {
                "inputs": [
                    {"internalType": "bytes32", "name": "credentialHash", "type": "bytes32"},
                    {"internalType": "address", "name": "learnerAddress", "type": "address"},
                    {"internalType": "string", "name": "credentialId", "type": "string"},
                    {"internalType": "string", "name": "issuerDID", "type": "string"},
                    {"internalType": "string", "name": "credentialType", "type": "string"},
                    {"internalType": "uint256", "name": "expiresAt", "type": "uint256"},
                    {"internalType": "string", "name": "metadataURI", "type": "string"}
                ],
                "name": "issueCredential",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "bytes32", "name": "credentialHash", "type": "bytes32"},
                    {"internalType": "string", "name": "revocationReason", "type": "string"}
                ],
                "name": "revokeCredential",
                "outputs": [],
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
                    {"internalType": "bool", "name": "isExpired", "type": "bool"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "bytes32", "name": "credentialHash", "type": "bytes32"}],
                "name": "getCredential",
                "outputs": [
                    {
                        "components": [
                            {"internalType": "bytes32", "name": "credentialHash", "type": "bytes32"},
                            {"internalType": "address", "name": "issuerAddress", "type": "address"},
                            {"internalType": "address", "name": "learnerAddress", "type": "address"},
                            {"internalType": "string", "name": "credentialId", "type": "string"},
                            {"internalType": "string", "name": "issuerDID", "type": "string"},
                            {"internalType": "string", "name": "credentialType", "type": "string"},
                            {"internalType": "uint256", "name": "issuedAt", "type": "uint256"},
                            {"internalType": "uint256", "name": "expiresAt", "type": "uint256"},
                            {"internalType": "bool", "name": "isRevoked", "type": "bool"},
                            {"internalType": "uint256", "name": "revokedAt", "type": "uint256"},
                            {"internalType": "string", "name": "revocationReason", "type": "string"},
                            {"internalType": "string", "name": "metadataURI", "type": "string"}
                        ],
                        "internalType": "struct CredentialRegistry.CredentialRecord",
                        "name": "credential",
                        "type": "tuple"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "learnerAddress", "type": "address"}],
                "name": "getLearnerCredentials",
                "outputs": [{"internalType": "bytes32[]", "name": "credentialHashes", "type": "bytes32[]"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "issuerAddress", "type": "address"}],
                "name": "getIssuerCredentials",
                "outputs": [{"internalType": "bytes32[]", "name": "credentialHashes", "type": "bytes32[]"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "bytes32[]", "name": "credentialHashes", "type": "bytes32[]"}],
                "name": "batchVerifyCredentials",
                "outputs": [{"internalType": "bool[]", "name": "results", "type": "bool[]"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
        
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=abi
        )
    
    def issue_credential(
        self,
        credential_hash: str,
        learner_address: str,
        credential_id: str,
        issuer_did: str,
        credential_type: str,
        expires_at: int,
        metadata_uri: str = ""
    ) -> HexStr:
        """Issue a credential"""
        function_call = self.contract.functions.issueCredential(
            credential_hash,
            learner_address,
            credential_id,
            issuer_did,
            credential_type,
            expires_at,
            metadata_uri
        )
        return self._send_transaction(function_call)
    
    def revoke_credential(
        self,
        credential_hash: str,
        revocation_reason: str = "Credential revoked by issuer"
    ) -> HexStr:
        """Revoke a credential"""
        function_call = self.contract.functions.revokeCredential(
            credential_hash,
            revocation_reason
        )
        return self._send_transaction(function_call)
    
    def verify_credential(self, credential_hash: str) -> Dict[str, Any]:
        """Verify a credential"""
        result = self.contract.functions.verifyCredential(credential_hash).call()
        return {
            "isValid": result[0],
            "issuerAddress": result[1],
            "learnerAddress": result[2],
            "issuedAt": result[3],
            "expiresAt": result[4],
            "isExpired": result[5]
        }
    
    def get_credential(self, credential_hash: str) -> Dict[str, Any]:
        """Get credential information"""
        result = self.contract.functions.getCredential(credential_hash).call()
        return {
            "credential_hash": result[0],
            "issuer_address": result[1],
            "learner_address": result[2],
            "credential_id": result[3],
            "issuer_did": result[4],
            "credential_type": result[5],
            "issued_at": result[6],
            "expires_at": result[7],
            "is_revoked": result[8],
            "revoked_at": result[9],
            "revocation_reason": result[10],
            "metadata_uri": result[11]
        }
    
    def get_learner_credentials(self, learner_address: str) -> List[str]:
        """Get all credentials for a learner"""
        result = self.contract.functions.getLearnerCredentials(learner_address).call()
        return [hash.hex() for hash in result]
    
    def get_issuer_credentials(self, issuer_address: str) -> List[str]:
        """Get all credentials issued by an issuer"""
        result = self.contract.functions.getIssuerCredentials(issuer_address).call()
        return [hash.hex() for hash in result]
    
    def batch_verify_credentials(self, credential_hashes: List[str]) -> List[bool]:
        """Batch verify multiple credentials"""
        result = self.contract.functions.batchVerifyCredentials(credential_hashes).call()
        return result
