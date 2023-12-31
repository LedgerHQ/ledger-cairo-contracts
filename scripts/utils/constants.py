import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from starknet_py.net.gateway_client import GatewayClient
from starknet_py.net.models.chains import StarknetChainId

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
load_dotenv()

NETWORKS = {
    "mainnet": {
        "name": "mainnet",
        "feeder_gateway_url": "https://alpha-mainnet.starknet.io/feeder_gateway",
        "gateway_url": "https://alpha-mainnet.starknet.io/gateway",
    },
    "testnet": {
        "name": "testnet",
        "explorer_url": "https://testnet.starkscan.co",
        "rpc_url": f"https://starknet-goerli.infura.io/v3/{os.getenv('INFURA_KEY')}",
        "feeder_gateway_url": "https://alpha4.starknet.io/feeder_gateway",
        "gateway_url": "https://alpha4.starknet.io/gateway",
    },
    "devnet": {
        "name": "devnet",
        "explorer_url": "",
        "rpc_url": "http://127.0.0.1:5050/rpc",
        "feeder_gateway_url": "http://localhost:5050/feeder_gateway",
        "gateway_url": "http://localhost:5050/gateway",
    },
}

NETWORK = NETWORKS[os.getenv("STARKNET_NETWORK", "devnet")]
NETWORK["account_address"] = os.environ.get(
    f"{NETWORK['name'].upper()}_ACCOUNT_ADDRESS"
)
if NETWORK["account_address"] is None:
    logger.warning(
        f"⚠️ {NETWORK['name'].upper()}_ACCOUNT_ADDRESS not set, defaulting to ACCOUNT_ADDRESS"
    )
    NETWORK["account_address"] = os.getenv("ACCOUNT_ADDRESS")
NETWORK["deployer_address"] = os.environ.get(
    f"{NETWORK['name'].upper()}_DEPLOYER_ADDRESS"
)
if NETWORK["deployer_address"] is None:
    logger.warning(
        f"⚠️ {NETWORK['name'].upper()}_DEPLOYER_ADDRESS not set, defaulting to DEPLOYER_ADDRESS"
    )
    NETWORK["deployer_address"] = os.getenv("DEPLOYER_ADDRESS")
NETWORK["private_key"] = os.environ.get(f"{NETWORK['name'].upper()}_PRIVATE_KEY")
if NETWORK["private_key"] is None:
    logger.warning(
        f"⚠️  {NETWORK['name'].upper()}_PRIVATE_KEY not set, defaulting to PRIVATE_KEY"
    )
    NETWORK["private_key"] = os.getenv("PRIVATE_KEY")
if NETWORK["name"] == "mainnet":
    NETWORK["chain_id"] = StarknetChainId.MAINNET
elif NETWORK["name"] == "testnet2":
    StarknetChainId.TESTNET2
else:
    NETWORK["chain_id"] = StarknetChainId.TESTNET

GATEWAY_CLIENT = GatewayClient(
    net={
        "feeder_gateway_url": NETWORK["feeder_gateway_url"],
        "gateway_url": NETWORK["gateway_url"],
    }
)

ETH_TOKEN_ADDRESS = 0x49D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7
ETH_CLASS_HASH = 0x6a22bf63c7bc07effa39a25dfbd21523d211db0100a0afd054d172b81840eaf
SOURCE_DIR = Path("src")
CONTRACTS = {p.stem: p for p in list(SOURCE_DIR.glob("**/*.cairo"))}

BUILD_DIR = Path("target/dev")
BUILD_DIR.mkdir(exist_ok=True, parents=True)
DEPLOYMENTS_DIR = Path("deployments") / NETWORK["name"]
DEPLOYMENTS_DIR.mkdir(exist_ok=True, parents=True)

COMPILED_CONTRACTS = [
    {"contract_name": "ledgerCairoContract_StarkSigner", "is_account_contract": False},
    {"contract_name": "ledgerCairoContract_AccountPlugin", "is_account_contract": True},
    # {"contract_name": "referral_Naming", "is_account_contract": False}, // uncomment to test on devnet
]

NAMING_ADDRESS = 0x6ac597f8116f886fa1c97a23fa4e08299975ecaf6b598873ca6792b9bbfb678