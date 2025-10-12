const hre = require("hardhat");
const fs = require("fs");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying CredHub contracts with account:", deployer.address);

  // Check balance
  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log("Deployer balance:", hre.ethers.formatEther(balance), "POL");

  if (balance < hre.ethers.parseEther("0.01")) {
    console.log("⚠️  Warning: Low balance. You need at least 0.01 POL for deployment.");
    console.log("💡 Get test POL from: https://faucet.polygon.technology/");
  }

  console.log("\n🚀 Deploying CredHub contracts to Amoy testnet...");
  
  // Step 1: Deploy IssuerRegistry
  console.log("\n1️⃣ Deploying IssuerRegistry...");
  const IssuerRegistry = await hre.ethers.getContractFactory("IssuerRegistry");
  console.log("   📦 Contract factory created, deploying...");
  const issuerRegistry = await IssuerRegistry.deploy();
  console.log("   ⏳ Waiting for deployment confirmation...");
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
    network: "amoy",
    chainId: "80002",
    deployer: deployer.address,
    issuerRegistryTxHash: issuerRegistry.deploymentTransaction().hash,
    credentialRegistryTxHash: credentialRegistry.deploymentTransaction().hash,
    gasUsed: {
      issuerRegistry: issuerRegistry.deploymentTransaction().gasLimit.toString(),
      credentialRegistry: credentialRegistry.deploymentTransaction().gasLimit.toString()
    },
    timestamp: new Date().toISOString(),
    rpcUrl: "https://rpc-amoy.polygon.technology",
    currency: "POL"
  };
  
  // Save deployment info
  fs.writeFileSync("./deployed-config-amoy.json", JSON.stringify(deploymentInfo, null, 2));
  console.log("📄 Deployment config saved to deployed-config-amoy.json");
  
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
  console.log(`Network: Amoy Testnet (Chain ID: 80002)`);
  console.log(`Deployer: ${deployer.address}`);
  console.log("\n🔗 View on Polygonscan:");
  console.log(`IssuerRegistry: https://amoy.polygonscan.com/address/${issuerRegistryAddress}`);
  console.log(`CredentialRegistry: https://amoy.polygonscan.com/address/${credentialRegistryAddress}`);
  
  console.log("\n📝 Next Steps:");
  console.log("1. Update your backend configuration with these contract addresses");
  console.log("2. Register issuers using the IssuerRegistry contract");
  console.log("3. Start issuing credentials using the CredentialRegistry contract");
  console.log("4. Test credential verification workflow");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Deployment failed:", error);
    process.exit(1);
  });
