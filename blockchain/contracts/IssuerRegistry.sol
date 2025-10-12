// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IssuerRegistry
 * @dev Manages a registry of verified credential issuers
 * @notice This contract maintains a whitelist of approved issuers who can issue credentials
 */
contract IssuerRegistry {
    struct Issuer {
        address issuerAddress;
        string issuerDID;
        string name;
        string domain;
        bool isActive;
        uint256 registrationDate;
        uint256 lastUpdated;
        string metadataURI; // IPFS or HTTP URL for issuer metadata
    }

    // State variables
    mapping(address => Issuer) public issuers;
    mapping(string => address) public didToAddress; // DID to address mapping
    address[] public issuerAddresses;
    
    // Access control
    address public owner;
    mapping(address => bool) public admins;
    
    // Events
    event IssuerRegistered(
        address indexed issuerAddress,
        string indexed issuerDID,
        string name,
        uint256 timestamp
    );
    
    event IssuerUpdated(
        address indexed issuerAddress,
        string name,
        bool isActive,
        uint256 timestamp
    );
    
    event IssuerDeactivated(
        address indexed issuerAddress,
        uint256 timestamp
    );
    
    event AdminAdded(address indexed admin);
    event AdminRemoved(address indexed admin);

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }
    
    modifier onlyAdmin() {
        require(admins[msg.sender] || msg.sender == owner, "Only admin can perform this action");
        _;
    }
    
    modifier onlyActiveIssuer(address issuerAddress) {
        require(issuers[issuerAddress].isActive, "Issuer is not active");
        _;
    }

    constructor() {
        owner = msg.sender;
        admins[msg.sender] = true;
    }

    /**
     * @dev Register a new issuer
     * @param issuerAddress The wallet address of the issuer
     * @param issuerDID The decentralized identifier of the issuer
     * @param name The display name of the issuer
     * @param domain The domain/website of the issuer
     * @param metadataURI URI pointing to issuer metadata
     */
    function registerIssuer(
        address issuerAddress,
        string memory issuerDID,
        string memory name,
        string memory domain,
        string memory metadataURI
    ) external onlyAdmin {
        require(issuerAddress != address(0), "Invalid issuer address");
        require(bytes(issuerDID).length > 0, "DID cannot be empty");
        require(bytes(name).length > 0, "Name cannot be empty");
        require(!issuers[issuerAddress].isActive, "Issuer already registered");
        require(didToAddress[issuerDID] == address(0), "DID already exists");

        Issuer memory newIssuer = Issuer({
            issuerAddress: issuerAddress,
            issuerDID: issuerDID,
            name: name,
            domain: domain,
            isActive: true,
            registrationDate: block.timestamp,
            lastUpdated: block.timestamp,
            metadataURI: metadataURI
        });

        issuers[issuerAddress] = newIssuer;
        didToAddress[issuerDID] = issuerAddress;
        issuerAddresses.push(issuerAddress);

        emit IssuerRegistered(issuerAddress, issuerDID, name, block.timestamp);
    }

    /**
     * @dev Update issuer information
     * @param issuerAddress The address of the issuer to update
     * @param name New name for the issuer
     * @param domain New domain for the issuer
     * @param metadataURI New metadata URI
     * @param isActive New active status
     */
    function updateIssuer(
        address issuerAddress,
        string memory name,
        string memory domain,
        string memory metadataURI,
        bool isActive
    ) external onlyAdmin {
        require(issuers[issuerAddress].issuerAddress != address(0), "Issuer not found");
        
        issuers[issuerAddress].name = name;
        issuers[issuerAddress].domain = domain;
        issuers[issuerAddress].metadataURI = metadataURI;
        issuers[issuerAddress].isActive = isActive;
        issuers[issuerAddress].lastUpdated = block.timestamp;

        emit IssuerUpdated(issuerAddress, name, isActive, block.timestamp);
    }

    /**
     * @dev Deactivate an issuer
     * @param issuerAddress The address of the issuer to deactivate
     */
    function deactivateIssuer(address issuerAddress) external onlyAdmin {
        require(issuers[issuerAddress].isActive, "Issuer already inactive");
        
        issuers[issuerAddress].isActive = false;
        issuers[issuerAddress].lastUpdated = block.timestamp;

        emit IssuerDeactivated(issuerAddress, block.timestamp);
    }

    /**
     * @dev Add an admin
     * @param adminAddress The address to grant admin privileges
     */
    function addAdmin(address adminAddress) external onlyOwner {
        require(adminAddress != address(0), "Invalid admin address");
        admins[adminAddress] = true;
        emit AdminAdded(adminAddress);
    }

    /**
     * @dev Remove an admin
     * @param adminAddress The address to remove admin privileges from
     */
    function removeAdmin(address adminAddress) external onlyOwner {
        require(adminAddress != owner, "Cannot remove owner");
        admins[adminAddress] = false;
        emit AdminRemoved(adminAddress);
    }

    /**
     * @dev Check if an address is a registered and active issuer
     * @param issuerAddress The address to check
     * @return isRegistered True if the issuer is registered and active
     */
    function isIssuerActive(address issuerAddress) external view returns (bool isRegistered) {
        return issuers[issuerAddress].isActive;
    }

    /**
     * @dev Get issuer information by address
     * @param issuerAddress The address of the issuer
     * @return issuer The issuer struct
     */
    function getIssuer(address issuerAddress) external view returns (Issuer memory issuer) {
        return issuers[issuerAddress];
    }

    /**
     * @dev Get issuer address by DID
     * @param issuerDID The DID of the issuer
     * @return issuerAddress The address of the issuer
     */
    function getIssuerByDID(string memory issuerDID) external view returns (address issuerAddress) {
        return didToAddress[issuerDID];
    }

    /**
     * @dev Get total number of registered issuers
     * @return count The total number of issuers
     */
    function getIssuerCount() external view returns (uint256 count) {
        return issuerAddresses.length;
    }

    /**
     * @dev Get all active issuers
     * @return activeIssuers Array of active issuer addresses
     */
    function getActiveIssuers() external view returns (address[] memory activeIssuers) {
        uint256 activeCount = 0;
        
        // Count active issuers
        for (uint256 i = 0; i < issuerAddresses.length; i++) {
            if (issuers[issuerAddresses[i]].isActive) {
                activeCount++;
            }
        }
        
        // Create array with active issuers
        activeIssuers = new address[](activeCount);
        uint256 index = 0;
        
        for (uint256 i = 0; i < issuerAddresses.length; i++) {
            if (issuers[issuerAddresses[i]].isActive) {
                activeIssuers[index] = issuerAddresses[i];
                index++;
            }
        }
        
        return activeIssuers;
    }
}
