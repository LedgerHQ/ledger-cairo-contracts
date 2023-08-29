// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts for Cairo v0.7.0 (account/account.cairo)

use array::ArrayTrait;
use array::SpanTrait;
use option::OptionTrait;
use serde::Serde;
use starknet::ContractAddress;
use starknet::account::Call;
use starknet::ClassHash;

const TRANSACTION_VERSION: felt252 = 1;

// 2**128 + TRANSACTION_VERSION
const QUERY_VERSION: felt252 = 340282366920938463463374607431768211457;
const INITIALIZE_SELECTOR: felt252 = 215307247182100370520050591091822763712463273430149262739280891880522753123;

#[starknet::interface]
trait IPlugin<TContractState> {
    fn is_valid_signature(self: @TContractState, hash:felt252, sig: Span<felt252>) -> bool;
    fn initialize(ref self: TContractState, plugin_calldata: Span<felt252>);
    fn set_public_key(ref self: TContractState, plugin_calldata: Span<felt252>);
    fn get_public_key(ref self: TContractState) -> Span<felt252>;
}

trait PublicKeyTrait<TState> {
    fn set_public_key(ref self: TState, plugin: ClassHash, plugin_calldata: Span<felt252>);
    fn get_public_key(self: @TState, plugin: ClassHash) -> Span<felt252>;
}

#[starknet::contract]
mod AccountPlugin {
    use super::{IPluginDispatcherTrait, IPluginLibraryDispatcher};

    use array::ArrayTrait;
    use array::SpanTrait;
    use box::BoxTrait;

    use ledgerCairoContract::account::interface;
    use ledgerCairoContract::introspection::interface::ISRC5;
    use ledgerCairoContract::introspection::interface::ISRC5Camel;
    use ledgerCairoContract::introspection::src5::SRC5;
    use option::OptionTrait;
    use traits::Into;

    use starknet::class_hash_try_from_felt252;
    use starknet::ClassHash;
    use starknet::get_caller_address;
    use starknet::get_contract_address;
    use starknet::get_tx_info;

    use super::Call;
    use super::QUERY_VERSION;
    use super::TRANSACTION_VERSION;
    use zeroable::Zeroable;

    #[storage]
    struct Storage {
        // public_key: felt252,
        plugins: LegacyMap<felt252, felt252>
    }

    #[constructor]
    fn constructor(ref self: ContractState, plugin: ClassHash, plugin_calldata: Span<felt252>) {
        self.initializer(plugin, plugin_calldata);
    }

    //
    // External
    //

    #[external(v0)]
    impl SRC6Impl of interface::ISRC6<ContractState> {
        fn __execute__(self: @ContractState, mut calls: Array<Call>) -> Array<Span<felt252>> {
            // Avoid calls from other contracts
            // https://github.com/OpenZeppelin/cairo-contracts/issues/344
            let sender = get_caller_address();
            assert(sender.is_zero(), 'Account: invalid caller');

            // Check tx version
            let tx_info = get_tx_info().unbox();
            let version = tx_info.version;
            if version != TRANSACTION_VERSION {
                assert(version == QUERY_VERSION, 'Account: invalid tx version');
            }

            _execute_calls(calls)
        }

        fn __validate__(self: @ContractState, mut calls: Array<Call>) -> felt252 {
            self.validate_transaction()
        }

        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            if self._is_valid_signature(hash, signature.span()) {
                starknet::VALIDATED
            } else {
                0
            }
        }
    }

    #[external(v0)]
    impl SRC6CamelOnlyImpl of interface::ISRC6CamelOnly<ContractState> {
        fn isValidSignature(
            self: @ContractState, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            SRC6Impl::is_valid_signature(self, hash, signature)
        }
    }

    #[external(v0)]
    impl DeclarerImpl of interface::IDeclarer<ContractState> {
        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            self.validate_transaction()
        }
    }

    #[external(v0)]
    impl SRC5Impl of ISRC5<ContractState> {
        fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
            let unsafe_state = SRC5::unsafe_new_contract_state();
            SRC5::SRC5Impl::supports_interface(@unsafe_state, interface_id)
        }
    }

    #[external(v0)]
    impl SRC5CamelImpl of ISRC5Camel<ContractState> {
        fn supportsInterface(self: @ContractState, interfaceId: felt252) -> bool {
            let unsafe_state = SRC5::unsafe_new_contract_state();
            SRC5::SRC5CamelImpl::supportsInterface(@unsafe_state, interfaceId)
        }
    }

    #[external(v0)]
    fn __validate_deploy__(
        self: @ContractState,
        class_hash: felt252,
        contract_address_salt: felt252,
        _public_key: felt252
    ) -> felt252 {
        self.validate_transaction()
    }

    #[external(v0)]
    impl PublicKeyImpl of super::PublicKeyTrait<ContractState> {
        fn get_public_key(self: @ContractState, plugin: ClassHash) -> Span<felt252> {
            get_public_key(plugin)
        }

        fn set_public_key(ref self: ContractState, plugin: ClassHash, plugin_calldata: Span<felt252>) {
            assert_only_self();
            set_public_key(plugin, plugin_calldata);
        }
    }

    //
    // Internal
    //

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn initializer(ref self: ContractState, plugin: ClassHash, plugin_calldata: Span<felt252>) {
            let mut unsafe_state = SRC5::unsafe_new_contract_state();
            SRC5::InternalImpl::register_interface(ref unsafe_state, interface::ISRC6_ID);
            initialize_plugin(plugin, plugin_calldata);
            self.plugins.write(plugin.into(), 1);
        }

        fn validate_transaction(self: @ContractState) -> felt252 {
            let tx_info = get_tx_info().unbox();
            let tx_hash = tx_info.transaction_hash;
            let signature = tx_info.signature;
            assert(self._is_valid_signature(tx_hash, signature), 'Account: invalid signature');
            starknet::VALIDATED
        }

        fn _is_valid_signature(
            self: @ContractState, hash: felt252, signature: Span<felt252>
        ) -> bool {
            let plugin = self.get_plugin_from_signature(signature);
            return IPluginLibraryDispatcher {
                class_hash:plugin
            }.is_valid_signature(hash, signature);
        }

        fn get_plugin_from_signature(self: @ContractState, signature: Span<felt252>) -> ClassHash {
            let pluginId = *signature.at(0);
            let isRegistered = self.plugins.read(pluginId);
            assert(isRegistered == 1, 'Account: plugin not registered');
            return class_hash_try_from_felt252(pluginId).unwrap();
        }
    }   

    #[internal]
    fn assert_only_self() {
        let caller = get_caller_address();
        let self = get_contract_address();
        assert(self == caller, 'Account: unauthorized');
    }

    #[internal]
    fn _execute_calls(mut calls: Array<Call>) -> Array<Span<felt252>> {
        let mut res = ArrayTrait::new();
        loop {
            match calls.pop_front() {
                Option::Some(call) => {
                    let _res = _execute_single_call(call);
                    res.append(_res);
                },
                Option::None(_) => {
                    break ();
                },
            };
        };
        res
    }

    #[internal]
    fn _execute_single_call(call: Call) -> Span<felt252> {
        let Call{to, selector, calldata } = call;
        starknet::call_contract_syscall(to, selector, calldata.span()).unwrap()
    }

    #[internal]
    fn initialize_plugin(plugin: ClassHash, plugin_calldata: Span<felt252>) {
        if plugin_calldata.len() == 0 {
            return;
        }
        IPluginLibraryDispatcher {
            class_hash:plugin
        }.initialize(plugin_calldata);
    }

    #[internal]
    fn set_public_key(plugin: ClassHash, plugin_calldata: Span<felt252>) {
        if plugin_calldata.len() == 0 {
            return;
        }
        IPluginLibraryDispatcher {
            class_hash:plugin
        }.set_public_key(plugin_calldata);
    }

    #[internal]
    fn get_public_key(plugin: ClassHash) -> Span<felt252> {
        IPluginLibraryDispatcher {
            class_hash:plugin
        }.get_public_key()
    }
}
