#[starknet::contract]
mod SnakeAccountMock {
    use ledgerCairoContract::account::AccountPlugin;
    use ledgerCairoContract::account::StarkSigner;
    use starknet::ClassHash;    
    use option::OptionTrait;
    use array::ArrayTrait;
    use starknet::class_hash_try_from_felt252;
    
    fn CLASS_HASH() -> ClassHash {
        class_hash_try_from_felt252(StarkSigner::TEST_CLASS_HASH).unwrap()
    }
    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState, _public_key: felt252) {
        let mut unsafe_state = AccountPlugin::unsafe_new_contract_state();
        // let mut unsafe_state = AccountPlugin::unsafe_new_contract_state();
        let mut calldata: Array<felt252> = ArrayTrait::new();
        calldata.append(_public_key);
        AccountPlugin::InternalImpl::initializer(ref unsafe_state, CLASS_HASH(), calldata.span());
    }

    #[external(v0)]
    fn is_valid_signature(
        self: @ContractState, hash: felt252, signature: Array<felt252>
    ) -> felt252 {
        let unsafe_state = AccountPlugin::unsafe_new_contract_state();
        AccountPlugin::SRC6Impl::is_valid_signature(@unsafe_state, hash, signature)
    }

    #[external(v0)]
    fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
        let unsafe_state = AccountPlugin::unsafe_new_contract_state();
        AccountPlugin::SRC5Impl::supports_interface(@unsafe_state, interface_id)
    }
}
