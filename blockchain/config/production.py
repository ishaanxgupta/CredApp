"""
Production blockchain configuration for Polygon Mainnet
"""
from pydantic_settings import BaseSettings
from typing import Optional
import os

class ProductionBlockchainSettings(BaseSettings):
    """Production blockchain settings for Polygon Mainnet"""
    
    # Network configuration
    network_name: str = "polygon"
    rpc_url: str = "https://polygon-rpc.com"
    chain_id: int = 137
    network_type: str = "mainnet"
    
    # Contract configuration (will be set after deployment)
    contract_address: Optional[str] = None
    
    # Wallet configuration (from environment)
    private_key: Optional[str] = None
    wallet_address: Optional[str] = None
    
    # Gas configuration
    gas_price_gwei: int = 30  # 30 gwei for Polygon mainnet
    gas_limit: int = 8000000
    
    # API keys
    polygonscan_api_key: Optional[str] = None
    
    class Config:
        env_file = ".env"
        case_sensitive = False

def get_production_config() -> ProductionBlockchainSettings:
    """Get production blockchain configuration"""
    settings = ProductionBlockchainSettings()
    
    # Validate required settings
    if not settings.private_key:
        raise ValueError(
            "Private key is required for production deployment. "
            "Set PRIVATE_KEY environment variable."
        )
    
    if not settings.contract_address:
        print("⚠️  Warning: Contract address not set. Please deploy contract first.")
        print("   Run: npm run deploy:mainnet")
    
    return settings

# Environment-specific configurations
PRODUCTION_CONFIG = {
    "polygon": {
        "rpc_url": "https://polygon-rpc.com",
        "chain_id": 137,
        "gas_price_gwei": 30,
        "explorer_url": "https://polygonscan.com"
    },
    "mumbai": {
        "rpc_url": "https://rpc-mumbai.maticvigil.com", 
        "chain_id": 80001,
        "gas_price_gwei": 10,
        "explorer_url": "https://mumbai.polygonscan.com"
    }
}
