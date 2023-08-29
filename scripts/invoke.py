# %% Imports
import logging
from asyncio import run

from utils.constants import NETWORK
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

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# %% Main
async def main():
    # %% Declarations
    account = await get_starknet_account(address=NETWORK["account_address"])
    
    logger.info(f"ℹ️  Using account {hex(account.address)} as account")

    eth_contract = await get_eth_contract()

    transfer = eth_contract.functions["transfer"].prepare(
        recipient=0x06f19B187AABB71473c27e01719fc33d53377703E7063c3151cd2481bEE1C94C, 
        amount=int_to_uint256(100000000000), 
        max_fee=int(1e13)
    ) 
    transfer2 = eth_contract.functions["transfer"].prepare(
        recipient=0x06f19B187AABB71473c27e01719fc33d53377703E7063c3151cd2481bEE1C94C, 
        amount=int_to_uint256(1000000000), 
        max_fee=int(1e13)
    )

    # logger.info(transfer)

    response = await account.execute(calls=[transfer, transfer2], max_fee=int(1e14), cairo_version=1)
    logger.info(response)
    await account.client.wait_for_tx(response.transaction_hash)


# %% Run
if __name__ == "__main__":
    run(main())