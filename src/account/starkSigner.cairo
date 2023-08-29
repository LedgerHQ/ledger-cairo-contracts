// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts for Cairo v0.7.0 (account/account.cairo)

use array::ArrayTrait;
use array::SpanTrait;
use option::OptionTrait;
use serde::Serde;
use starknet::ContractAddress;
use starknet::account::Call;

const TRANSACTION_VERSION: felt252 = 1;

#[starknet::interface]
trait IPlugin<TContractState> {
    fn is_valid_signature(self: @TContractState, hash:felt252, sig: Span<felt252>) -> bool;
    fn initialize(ref self: TContractState, plugin_calldata: Span<felt252>);
    fn set_public_key(ref self: TContractState, plugin_calldata: Span<felt252>);
    fn get_public_key(ref self: TContractState) -> Span<felt252>;
}


#[starknet::contract]
mod StarkSigner {
    use super::{IPluginDispatcherTrait, IPluginLibraryDispatcher};

    use array::ArrayTrait;
    use array::SpanTrait;
    use box::BoxTrait;
    use ecdsa::check_ecdsa_signature;

    use ledgerCairoContract::account::interface;
    use ledgerCairoContract::introspection::interface::ISRC5;
    use ledgerCairoContract::introspection::interface::ISRC5Camel;
    use ledgerCairoContract::introspection::src5::SRC5;
    use option::OptionTrait;
    use traits::Into;
    use starknet::ClassHash;
    use starknet::class_hash_try_from_felt252;


    use starknet::get_caller_address;
    use starknet::get_contract_address;
    use starknet::get_tx_info;

    use super::Call;
    use super::TRANSACTION_VERSION;
    use zeroable::Zeroable;

    #[storage]
    struct Storage {
        // public_key: felt252,
        StarkSigner_public_key: felt252
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        PubKeyAdded: PubKeyAdded,
        PubKeyRemoved: PubKeyRemoved,
    }

    #[derive(Drop, starknet::Event)]
    struct PubKeyAdded {
        new_pubkey: felt252
    }

    #[derive(Drop, starknet::Event)]
    struct PubKeyRemoved {
        removed_pubkey: felt252
    }


    #[external(v0)]
    fn validate(self: @ContractState) -> felt252 {
        let tx_info = get_tx_info().unbox();
        let tx_hash = tx_info.transaction_hash;
        let signature = tx_info.signature;
        assert(self._is_valid_signature(tx_hash, signature), 'Account: invalid signature');
        starknet::VALIDATED
    }
    //
    // External
    //
    #[external(v0)]
    fn is_valid_signature(
        self: @ContractState,
        hash:felt252, 
        signature: Span<felt252>
    ) -> bool {
        self._is_valid_signature(hash, signature)
    }

    #[external(v0)]
    fn initialize(
        ref self: ContractState, 
        calldata: Span<felt252>
    ) {
        assert(self.StarkSigner_public_key.read() == 0, 'already initialized');
        assert(calldata.len() == 1, 'initialize failed');
        self.StarkSigner_public_key.write(*calldata.at(0));
        self.emit(PubKeyAdded { new_pubkey: *calldata.at(0) });
    }

    #[external(v0)]
    fn set_public_key(
        ref self: ContractState, 
        calldata: Span<felt252>
    ) {
        assert(calldata.len() == 1, 'pubkey len invalid');
        self.emit(PubKeyRemoved { removed_pubkey: self.StarkSigner_public_key.read() });
        self.StarkSigner_public_key.write(*calldata.at(0));
        self.emit(PubKeyAdded { new_pubkey: *calldata.at(0) });
    }

    #[external(v0)]
    fn get_public_key(
        self: @ContractState
    ) -> Span<felt252> {
        let mut res = ArrayTrait::new();
        res.append(self.StarkSigner_public_key.read());
        res.span()
    }
   
    //
    // Internal
    //
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _is_valid_signature(
            self: @ContractState,
            hash:felt252, 
            signature: Span<felt252>
        ) -> bool {
             let valid_length = signature.len() == 3_u32;

            if valid_length {
                check_ecdsa_signature(
                    hash, self.StarkSigner_public_key.read(), *signature.at(1_u32), *signature.at(2_u32)
                )
            } else {
                false
            }
        }
    }
}
