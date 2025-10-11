const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying contracts with account:", deployer.address);

  const CredentialAnchor = await hre.ethers.getContractFactory("CredentialAnchor");
  const credentialAnchor = await CredentialAnchor.deploy();

  await credentialAnchor.waitForDeployment();

  console.log("CredentialAnchor deployed to:", await credentialAnchor.getAddress());
  
  // Save deployment info
  const deploymentInfo = {
    contractAddress: await credentialAnchor.getAddress(),
    network: "localhost",
    rpcUrl: "http://127.0.0.1:8545",
    chainId: 31337,
    deployer: deployer.address
  };
  
  const fs = require("fs");
  fs.writeFileSync("./deployed-config.json", JSON.stringify(deploymentInfo, null, 2));
  console.log("Deployment config saved to deployed-config.json");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
