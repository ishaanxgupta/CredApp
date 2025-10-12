const hre = require("hardhat");
const fs = require("fs");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying CredHub contracts with account:", deployer.address);

  // Check balance
  const balance = await deployer.getBalance();
  console.log("Deployer balance:", hre.ethers.utils.formatEther(balance), "MATIC");

  if (balance.lt(hre.ethers.utils.parseEther("0.01"))) {
    console.log("⚠️  Warning: Low balance. You need at least 0.01 MATIC for deployment.");
  }

  console.log("\n🚀 Deploying CredHub contracts to Mumbai testnet...");
  
  // Step 1: Deploy IssuerRegistry
  console.log("\n1️⃣ Deploying IssuerRegistry...");
  const IssuerRegistry = await hre.ethers.getContractFactory("IssuerRegistry");
  const issuerRegistry = await IssuerRegistry.deploy();
  await issuerRegistry.waitForDeployment();
  const issuerRegistryAddress = await issuerRegistry.getAddress();
  console.log("✅ IssuerRegistry deployed to:", issuerRegistryAddress);

  // Step 2: Deploy CredentialRegistry (depends on IssuerRegistry)
  console.log("\n2️⃣ Deploying CredentialRegistry...");
  const CredentialRegistry = await hre.ethers.getContractFactory("CredentialRegistry");
  const credentialRegistry = await CredentialRegistry.deploy(issuerRegistryAddress);
  await credentialRegistry.waitForDeployment();
  const credentialRegistryAddress = await credentialRegistry.getAddress();
  console.log("✅ CredentialRegistry deployed to:", credentialRegistryAddress);
  
  // Get network info
  const network = await hre.ethers.provider.getNetwork();
  const deploymentInfo = {
    issuerRegistryAddress: issuerRegistryAddress,
    credentialRegistryAddress: credentialRegistryAddress,
    network: "mumbai",
    chainId: "80001",
    deployer: deployer.address,
    issuerRegistryTxHash: issuerRegistry.deploymentTransaction().hash,
    credentialRegistryTxHash: credentialRegistry.deploymentTransaction().hash,
    gasUsed: {
      issuerRegistry: issuerRegistry.deploymentTransaction().gasLimit.toString(),
      credentialRegistry: credentialRegistry.deploymentTransaction().gasLimit.toString()
    },
    timestamp: new Date().toISOString(),
    rpcUrl: "https://rpc-mumbai.maticvigil.com"
  };
  
  // Save deployment info
  fs.writeFileSync("./deployed-config-mumbai.json", JSON.stringify(deploymentInfo, null, 2));
  console.log("📄 Deployment config saved to deployed-config-mumbai.json");
  
  // Verify contracts on Polygonscan (if API key is provided)
  if (process.env.POLYGONSCAN_API_KEY) {
    console.log("\n🔍 Verifying contracts on Polygonscan...");
    
    try {
      // Verify IssuerRegistry
      console.log("Verifying IssuerRegistry...");
      await hre.run("verify:verify", {
        address: issuerRegistryAddress,
        constructorArguments: [],
      });
      console.log("✅ IssuerRegistry verified on Polygonscan");
    } catch (error) {
      console.log("❌ IssuerRegistry verification failed:", error.message);
    }
    
    try {
      // Verify CredentialRegistry
      console.log("Verifying CredentialRegistry...");
      await hre.run("verify:verify", {
        address: credentialRegistryAddress,
        constructorArguments: [issuerRegistryAddress],
      });
      console.log("✅ CredentialRegistry verified on Polygonscan");
    } catch (error) {
      console.log("❌ CredentialRegistry verification failed:", error.message);
    }
  }
  
  console.log("\n🎉 CredHub deployment completed successfully!");
  console.log("\n📋 Deployment Summary:");
  console.log(`IssuerRegistry: ${issuerRegistryAddress}`);
  console.log(`CredentialRegistry: ${credentialRegistryAddress}`);
  console.log(`Network: Mumbai Testnet (Chain ID: 80001)`);
  console.log(`Deployer: ${deployer.address}`);
  console.log("\n🔗 View on Polygonscan:");
  console.log(`IssuerRegistry: https://mumbai.polygonscan.com/address/${issuerRegistryAddress}`);
  console.log(`CredentialRegistry: https://mumbai.polygonscan.com/address/${credentialRegistryAddress}`);
  
  console.log("\n📝 Next Steps:");
  console.log("1. Update your backend configuration with these contract addresses");
  console.log("2. Register issuers using the IssuerRegistry contract");
  console.log("3. Start issuing credentials using the CredentialRegistry contract");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Deployment failed:", error);
    process.exit(1);
  });
