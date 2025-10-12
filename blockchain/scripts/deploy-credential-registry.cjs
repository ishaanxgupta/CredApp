const hre = require("hardhat");
const fs = require("fs");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying CredentialRegistry with account:", deployer.address);

  // Check balance
  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log("Deployer balance:", hre.ethers.formatEther(balance), "POL");

  // Use the already deployed IssuerRegistry address
  const issuerRegistryAddress = "0x5868c5Fa4eeF9db8Ca998F16845CCffA3B85C472";
  console.log("Using IssuerRegistry:", issuerRegistryAddress);

  console.log("\n🚀 Deploying CredentialRegistry...");
  
  const CredentialRegistry = await hre.ethers.getContractFactory("CredentialRegistry");
  console.log("   📦 Contract factory created, deploying...");
  const credentialRegistry = await CredentialRegistry.deploy(issuerRegistryAddress);
  console.log("   ⏳ Waiting for deployment confirmation...");
  await credentialRegistry.waitForDeployment();
  const credentialRegistryAddress = await credentialRegistry.getAddress();
  console.log("✅ CredentialRegistry deployed to:", credentialRegistryAddress);
  
  // Save deployment info
  const deploymentInfo = {
    issuerRegistryAddress: issuerRegistryAddress,
    credentialRegistryAddress: credentialRegistryAddress,
    network: "amoy",
    chainId: "80002",
    deployer: deployer.address,
    credentialRegistryTxHash: credentialRegistry.deploymentTransaction().hash,
    gasUsed: credentialRegistry.deploymentTransaction().gasLimit.toString(),
    timestamp: new Date().toISOString(),
    rpcUrl: "https://rpc-amoy.polygon.technology"
  };
  
  fs.writeFileSync("./deployed-config-amoy.json", JSON.stringify(deploymentInfo, null, 2));
  console.log("📄 Deployment config saved to deployed-config-amoy.json");
  
  console.log("\n🎉 CredHub deployment completed successfully!");
  console.log("\n📋 Deployment Summary:");
  console.log(`IssuerRegistry: ${issuerRegistryAddress}`);
  console.log(`CredentialRegistry: ${credentialRegistryAddress}`);
  console.log(`Network: Amoy Testnet (Chain ID: 80002)`);
  console.log(`Deployer: ${deployer.address}`);
  console.log("\n🔗 View on Polygonscan:");
  console.log(`IssuerRegistry: https://amoy.polygonscan.com/address/${issuerRegistryAddress}`);
  console.log(`CredentialRegistry: https://amoy.polygonscan.com/address/${credentialRegistryAddress}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Deployment failed:", error);
    process.exit(1);
  });
