"""
Blockchain configuration for CredHub
Handles different network configurations and contract addresses
"""

import os
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class NetworkType(Enum):
    """Supported blockchain networks"""
    LOCAL = "local"
    MUMBAI = "mumbai"
    AMOY = "amoy"
    POLYGON = "polygon"


@dataclass
class NetworkConfig:
    """Network configuration for blockchain interactions"""
    name: str
    rpc_url: str
    chain_id: int
    currency: str
    explorer_url: str
    gas_price_gwei: int
    gas_limit: int


@dataclass
class ContractConfig:
    """Contract configuration"""
    issuer_registry_address: str
    credential_registry_address: str
    deployed_at: str
    deployment_tx_hash: str


@dataclass
class BlockchainConfig:
    """Complete blockchain configuration"""
    network: NetworkConfig
    contracts: ContractConfig
    private_key: str
    wallet_address: str


# Network configurations
NETWORKS = {
    NetworkType.LOCAL: NetworkConfig(
        name="localhost",
        rpc_url="http://127.0.0.1:8545",
        chain_id=31337,
        currency="ETH",
        explorer_url="http://localhost:8545",
        gas_price_gwei=20,
        gas_limit=8000000
    ),
    NetworkType.MUMBAI: NetworkConfig(
        name="mumbai",
        rpc_url="https://rpc-mumbai.maticvigil.com",
        chain_id=80001,
        currency="MATIC",
        explorer_url="https://mumbai.polygonscan.com",
        gas_price_gwei=10,
        gas_limit=8000000
    ),
    NetworkType.AMOY: NetworkConfig(
        name="amoy",
        rpc_url="https://rpc-amoy.polygon.technology",
        chain_id=80002,
        currency="POL",
        explorer_url="https://amoy.polygonscan.com",
        gas_price_gwei=30,
        gas_limit=8000000
    ),
    NetworkType.POLYGON: NetworkConfig(
        name="polygon",
        rpc_url="https://polygon-rpc.com",
        chain_id=137,
        currency="MATIC",
        explorer_url="https://polygonscan.com",
        gas_price_gwei=30,
        gas_limit=8000000
    )
}


def get_network_config(network_type: NetworkType) -> NetworkConfig:
    """Get network configuration by type"""
    return NETWORKS[network_type]


def get_contract_config(network_type: NetworkType) -> Optional[ContractConfig]:
    """Get contract configuration for a network"""
    # This would typically load from a deployed config file
    # For now, return None (contracts need to be deployed first)
    
    config_file = f"deployed-config-{network_type.value}.json"
    if os.path.exists(config_file):
        import json
        with open(config_file, 'r') as f:
            data = json.load(f)
            return ContractConfig(
                issuer_registry_address=data.get("issuerRegistryAddress"),
                credential_registry_address=data.get("credentialRegistryAddress"),
                deployed_at=data.get("timestamp"),
                deployment_tx_hash=data.get("credentialRegistryTxHash") or data.get("transactionHash")
            )
    return None


def get_blockchain_config(network_type: NetworkType) -> BlockchainConfig:
    """Get complete blockchain configuration"""
    network = get_network_config(network_type)
    contracts = get_contract_config(network_type)
    
    private_key = os.getenv("PRIVATE_KEY")
    wallet_address = os.getenv("WALLET_ADDRESS")
    
    if not private_key:
        raise ValueError(f"PRIVATE_KEY not found in environment variables for {network_type.value}")
    
    if not wallet_address:
        raise ValueError(f"WALLET_ADDRESS not found in environment variables for {network_type.value}")
    
    if not contracts:
        raise ValueError(f"Contracts not deployed for {network_type.value}. Deploy contracts first.")
    
    return BlockchainConfig(
        network=network,
        contracts=contracts,
        private_key=private_key,
        wallet_address=wallet_address
    )


def get_production_config() -> BlockchainConfig:
    """Get production blockchain configuration (Polygon mainnet)"""
    return get_blockchain_config(NetworkType.POLYGON)


def get_testnet_config() -> BlockchainConfig:
    """Get testnet blockchain configuration (Amoy)"""
    return get_blockchain_config(NetworkType.AMOY)

def get_mumbai_config() -> BlockchainConfig:
    """Get Mumbai testnet blockchain configuration"""
    return get_blockchain_config(NetworkType.MUMBAI)


def get_local_config() -> BlockchainConfig:
    """Get local blockchain configuration"""
    return get_blockchain_config(NetworkType.LOCAL)
