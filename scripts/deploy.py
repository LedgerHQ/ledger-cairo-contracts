# %% Imports
import logging
from asyncio import run

from utils.constants import COMPILED_CONTRACTS, NETWORK
from utils.starknet import (
    declare_v2,
    deploy_v2,
    dump_declarations,
    dump_deployments,
    get_declarations,
    get_starknet_account,
    invoke,
    get_eth_contract,
    int_to_uint256,
)

logging.basicConfig()#
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# %% Main
async def main():
    class_hash = {
        contract["contract_name"]: await declare_v2(contract["contract_name"])
        for contract in COMPILED_CONTRACTS
    }
    dump_declarations(class_hash)

    # %% Deployments
    class_hash = get_declarations()

    print('class_hash', class_hash)

    
    deployments = {}
    deployments["ledgerCairoContract_AccountPlugin"] = await deploy_v2(
        "ledgerCairoContract_AccountPlugin", 
        0x482b3eafec46566b33dfce310425147f962c0ae992ad03155ea12e739568245, 
        [0x031829f92a41964bf75e0181e24bb486ef2f0a008233cfe478ef00da5ebd4248]
    )
    dump_deployments(deployments)


# %% Run
if __name__ == "__main__":
    run(main())