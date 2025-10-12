// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title CredentialRegistry
 * @dev Manages credential hashes and verification data on blockchain
 * @notice This contract stores credential fingerprints for immutable verification
 */
contract CredentialRegistry {
    struct CredentialRecord {
        bytes32 credentialHash;
        address issuerAddress;
        address learnerAddress;
        string credentialId;
        string issuerDID;
        string credentialType;
        uint256 issuedAt;
        uint256 expiresAt;
        bool isRevoked;
        uint256 revokedAt;
        string revocationReason;
        string metadataURI; // IPFS or HTTP URL for full credential data
    }

    // State variables
    mapping(bytes32 => CredentialRecord) public credentials;
    mapping(string => bytes32) public credentialIdToHash; // credentialId to hash mapping
    mapping(address => bytes32[]) public learnerCredentials; // learner address to credential hashes
    mapping(address => bytes32[]) public issuerCredentials; // issuer address to credential hashes
    bytes32[] public allCredentialHashes;
    
    // Issuer Registry contract reference
    address public issuerRegistryAddress;
    
    // Access control
    address public owner;
    mapping(address => bool) public admins;
    
    // Events
    event CredentialIssued(
        bytes32 indexed credentialHash,
        address indexed issuerAddress,
        address indexed learnerAddress,
        string credentialId,
        uint256 issuedAt
    );
    
    event CredentialRevoked(
        bytes32 indexed credentialHash,
        address indexed issuerAddress,
        string revocationReason,
        uint256 revokedAt
    );
    
    event CredentialVerified(
        bytes32 indexed credentialHash,
        address indexed verifierAddress,
        bool isValid,
        uint256 verifiedAt
    );
    
    event IssuerRegistryUpdated(
        address indexed oldRegistry,
        address indexed newRegistry
    );

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }
    
    modifier onlyAdmin() {
        require(admins[msg.sender] || msg.sender == owner, "Only admin can perform this action");
        _;
    }
    
    modifier onlyRegisteredIssuer() {
        require(
            issuerRegistryAddress != address(0),
            "Issuer registry not set"
        );
        
        // Import the IssuerRegistry interface
        (bool success, bytes memory data) = issuerRegistryAddress.call(
            abi.encodeWithSignature("isIssuerActive(address)", msg.sender)
        );
        
        require(success, "Issuer registry call failed");
        bool isActive = abi.decode(data, (bool));
        require(isActive, "Only registered issuers can perform this action");
        _;
    }

    constructor(address _issuerRegistryAddress) {
        owner = msg.sender;
        admins[msg.sender] = true;
        issuerRegistryAddress = _issuerRegistryAddress;
    }

    /**
     * @dev Issue a new credential by storing its hash
     * @param credentialHash SHA-256 hash of the credential
     * @param learnerAddress Address of the credential recipient
     * @param credentialId Unique identifier for the credential
     * @param issuerDID DID of the issuer
     * @param credentialType Type of credential (certificate, badge, degree, etc.)
     * @param expiresAt Expiration timestamp (0 for no expiration)
     * @param metadataURI URI pointing to full credential data
     */
    function issueCredential(
        bytes32 credentialHash,
        address learnerAddress,
        string memory credentialId,
        string memory issuerDID,
        string memory credentialType,
        uint256 expiresAt,
        string memory metadataURI
    ) external onlyRegisteredIssuer {
        require(credentialHash != bytes32(0), "Credential hash cannot be zero");
        require(learnerAddress != address(0), "Invalid learner address");
        require(bytes(credentialId).length > 0, "Credential ID cannot be empty");
        require(bytes(issuerDID).length > 0, "Issuer DID cannot be empty");
        require(credentials[credentialHash].credentialHash == bytes32(0), "Credential already exists");
        require(credentialIdToHash[credentialId] == bytes32(0), "Credential ID already exists");
        require(
            expiresAt == 0 || expiresAt > block.timestamp,
            "Invalid expiration time"
        );

        CredentialRecord memory newCredential = CredentialRecord({
            credentialHash: credentialHash,
            issuerAddress: msg.sender,
            learnerAddress: learnerAddress,
            credentialId: credentialId,
            issuerDID: issuerDID,
            credentialType: credentialType,
            issuedAt: block.timestamp,
            expiresAt: expiresAt,
            isRevoked: false,
            revokedAt: 0,
            revocationReason: "",
            metadataURI: metadataURI
        });

        credentials[credentialHash] = newCredential;
        credentialIdToHash[credentialId] = credentialHash;
        learnerCredentials[learnerAddress].push(credentialHash);
        issuerCredentials[msg.sender].push(credentialHash);
        allCredentialHashes.push(credentialHash);

        emit CredentialIssued(
            credentialHash,
            msg.sender,
            learnerAddress,
            credentialId,
            block.timestamp
        );
    }

    /**
     * @dev Revoke a credential
     * @param credentialHash Hash of the credential to revoke
     * @param revocationReason Reason for revocation
     */
    function revokeCredential(
        bytes32 credentialHash,
        string memory revocationReason
    ) external {
        CredentialRecord storage credential = credentials[credentialHash];
        
        require(credential.credentialHash != bytes32(0), "Credential not found");
        require(!credential.isRevoked, "Credential already revoked");
        
        // Only the issuer or admin can revoke
        require(
            msg.sender == credential.issuerAddress || admins[msg.sender] || msg.sender == owner,
            "Only issuer or admin can revoke credential"
        );

        credential.isRevoked = true;
        credential.revokedAt = block.timestamp;
        credential.revocationReason = revocationReason;

        emit CredentialRevoked(
            credentialHash,
            credential.issuerAddress,
            revocationReason,
            block.timestamp
        );
    }

    /**
     * @dev Verify a credential
     * @param credentialHash Hash of the credential to verify
     * @return isValid True if credential is valid and not revoked
     * @return issuerAddress Address of the issuer
     * @return learnerAddress Address of the learner
     * @return issuedAt Timestamp when credential was issued
     * @return expiresAt Expiration timestamp
     * @return isExpired True if credential has expired
     */
    function verifyCredential(bytes32 credentialHash)
        external
        view
        returns (
            bool isValid,
            address issuerAddress,
            address learnerAddress,
            uint256 issuedAt,
            uint256 expiresAt,
            bool isExpired
        )
    {
        CredentialRecord memory credential = credentials[credentialHash];
        
        if (credential.credentialHash == bytes32(0)) {
            return (false, address(0), address(0), 0, 0, false);
        }

        isExpired = credential.expiresAt > 0 && block.timestamp > credential.expiresAt;
        isValid = !credential.isRevoked && !isExpired;

        return (
            isValid,
            credential.issuerAddress,
            credential.learnerAddress,
            credential.issuedAt,
            credential.expiresAt,
            isExpired
        );
    }

    /**
     * @dev Get credential record by hash
     * @param credentialHash Hash of the credential
     * @return credential The credential record
     */
    function getCredential(bytes32 credentialHash)
        external
        view
        returns (CredentialRecord memory credential)
    {
        return credentials[credentialHash];
    }

    /**
     * @dev Get credential hash by ID
     * @param credentialId The credential ID
     * @return credentialHash The hash of the credential
     */
    function getCredentialHash(string memory credentialId)
        external
        view
        returns (bytes32 credentialHash)
    {
        return credentialIdToHash[credentialId];
    }

    /**
     * @dev Get all credentials for a learner
     * @param learnerAddress Address of the learner
     * @return credentialHashes Array of credential hashes
     */
    function getLearnerCredentials(address learnerAddress)
        external
        view
        returns (bytes32[] memory credentialHashes)
    {
        return learnerCredentials[learnerAddress];
    }

    /**
     * @dev Get all credentials issued by an issuer
     * @param issuerAddress Address of the issuer
     * @return credentialHashes Array of credential hashes
     */
    function getIssuerCredentials(address issuerAddress)
        external
        view
        returns (bytes32[] memory credentialHashes)
    {
        return issuerCredentials[issuerAddress];
    }

    /**
     * @dev Get total number of credentials
     * @return count Total number of credentials
     */
    function getTotalCredentials() external view returns (uint256 count) {
        return allCredentialHashes.length;
    }

    /**
     * @dev Batch verify multiple credentials
     * @param credentialHashes Array of credential hashes to verify
     * @return results Array of verification results
     */
    function batchVerifyCredentials(bytes32[] memory credentialHashes)
        external
        view
        returns (bool[] memory results)
    {
        results = new bool[](credentialHashes.length);
        
        for (uint256 i = 0; i < credentialHashes.length; i++) {
            CredentialRecord memory credential = credentials[credentialHashes[i]];
            
            if (credential.credentialHash == bytes32(0)) {
                results[i] = false;
                continue;
            }

            bool isExpired = credential.expiresAt > 0 && block.timestamp > credential.expiresAt;
            results[i] = !credential.isRevoked && !isExpired;
        }
        
        return results;
    }

    /**
     * @dev Update issuer registry address
     * @param newRegistryAddress Address of the new issuer registry
     */
    function updateIssuerRegistry(address newRegistryAddress) external onlyOwner {
        require(newRegistryAddress != address(0), "Invalid registry address");
        address oldRegistry = issuerRegistryAddress;
        issuerRegistryAddress = newRegistryAddress;
        
        emit IssuerRegistryUpdated(oldRegistry, newRegistryAddress);
    }

    /**
     * @dev Add an admin
     * @param adminAddress The address to grant admin privileges
     */
    function addAdmin(address adminAddress) external onlyOwner {
        require(adminAddress != address(0), "Invalid admin address");
        admins[adminAddress] = true;
    }

    /**
     * @dev Remove an admin
     * @param adminAddress The address to remove admin privileges from
     */
    function removeAdmin(address adminAddress) external onlyOwner {
        require(adminAddress != owner, "Cannot remove owner");
        admins[adminAddress] = false;
    }

    /**
     * @dev Emergency function to pause credential issuance (admin only)
     */
    function isCredentialIssuancePaused(bytes32 /* credentialHash */) external pure returns (bool) {
        // This is a placeholder for future emergency pause functionality
        return false;
    }
}
