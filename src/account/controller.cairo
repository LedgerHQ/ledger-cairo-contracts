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
}


#[starknet::contract]
mod Controller {
    use super::{IPluginDispatcherTrait, IPluginLibraryDispatcher};

    use array::ArrayTrait;
    use array::SpanTrait;
    use box::BoxTrait;
    use ecdsa::check_ecdsa_signature;
    use ledgerCairoContract::webauthn2::verify;
    use alexandria_math::{sha256::sha256, BitShift};

    use option::OptionTrait;
    use traits::TryInto;
    use traits::Into;
    use ledgerCairoContract::utils::StoreSecp256r1Point;

    use core::starknet::secp256_trait::Secp256PointTrait;
    use starknet::secp256r1::Secp256r1Point;
    use starknet::secp256r1::Secp256r1Impl;
    use starknet::secp256r1::Secp256r1PointImpl;
    use core::integer::u8_try_from_felt252;
    use core::integer::u128_try_from_felt252;
    use core::integer::u128s_from_felt252;
    use core::integer::U128sFromFelt252Result;
    use core::integer::u128_safe_divmod;
    use starknet::get_caller_address;
    use starknet::get_contract_address;
    use starknet::get_tx_info;

    #[storage]
    struct Storage {
        // public_key: felt252,
        // Controller_admin_keys: u256,
        Controller_admin_key: Secp256r1Point,
        Controller_device_key: LegacyMap<felt252, bool>
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
        let (x, y) = self.Controller_admin_key.read().get_coordinates().unwrap();
        assert(x + y == 0, 'already initialized');
        assert(calldata.len() == 5, 'initialize failed');
        let key = Secp256r1Impl::secp256_ec_new_syscall(
            u256 { 
                low: u128_try_from_felt252(*calldata.at(0)).unwrap(),
                high:u128_try_from_felt252(*calldata.at(1)).unwrap() 
            },
            u256 { 
                low: u128_try_from_felt252(*calldata.at(2)).unwrap(),
                high: u128_try_from_felt252(*calldata.at(3)).unwrap() 
            }).unwrap().unwrap();
        self.Controller_admin_key.write(key);
        self.Controller_device_key.write(*calldata.at(4), true);
    }

    #[external(v0)]
    fn add_device_key(
        ref self: ContractState, 
        key: felt252
    ) {
        assert_only_self();
        self.Controller_device_key.write(key, true);
    }

    // #[external(v0)]
    // fn get_admin_key(
    //     self: @ContractState
    // ) -> Secp256r1Point {
    //     self.Controller_admin_key.read()
    // }

    #[external(v0)]
    fn is_public_key(
        self: @ContractState,
        key: felt252
    ) -> bool {
        self.Controller_device_key.read(key)
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
            if (*signature[0] == 0) {
                let sig_r = u256 { 
                    low: u128_try_from_felt252(*signature.at(1)).unwrap(),
                    high:u128_try_from_felt252(*signature.at(2)).unwrap() 
                };
                let sig_s = u256 { 
                    low: u128_try_from_felt252(*signature.at(2)).unwrap(),
                    high:u128_try_from_felt252(*signature.at(3)).unwrap() 
                };
                let challenge_offset_len: usize = (*signature[7]).try_into().unwrap();
                let challenge_offset_rem: usize = (*signature[8]).try_into().unwrap();
                let client_data_json_len: usize = (*signature[9]).try_into().unwrap();
                let client_data_json_rem: usize = (*signature[10]).try_into().unwrap();
                
                let authenticator_data_len: usize = (*signature[11 + client_data_json_len]).try_into().unwrap();
                
                let mut challenge: Array<u8> = extract_challenge(hash);
            
                let client_data_json = extract_client_data_json(signature, client_data_json_len);
                let authenticator_data = extract_authenticator_data(signature, client_data_json_len);
                let mut origin: Array<u8> = ArrayTrait::new();
                let verify_result = verify(
                    self.Controller_admin_key.read(),
                    sig_r,
                    sig_s,
                    0, 
                    11,
                    0,
                    client_data_json,
                    challenge,
                    origin,
                    authenticator_data
                );
                match verify_result {
                    Result::Ok => (true),
                    Result::Err(e) => (false)
                }
            } else {
                // let public_key = *signature.at(0);
                let public_key = *signature[0];
                let sig_r = *signature[1];
                let sig_s = *signature[2];

                let is_pub = self.Controller_device_key.read(public_key);
                if is_pub {
                    check_ecdsa_signature(
                        hash,
                        public_key,
                        sig_r,
                        sig_s
                    )
                } else {
                    false
                }
            }
        }
    }

    #[internal]
    fn assert_only_self() {
        let caller = get_caller_address();
        let self = get_contract_address();
        assert(self == caller, 'Account: unauthorized');
    }

    #[internal]
    fn split_felt(felt: felt252) -> (u128, u128) {
        match u128s_from_felt252(felt) {
            U128sFromFelt252Result::Narrow(low) => (0_u128, low),
            U128sFromFelt252Result::Wide((high, low)) => (high, low),
        }
    }

    #[internal]
    fn extract_challenge(hash: felt252) -> Array<u8> {
        let mut challenge: Array<u8> = ArrayTrait::new();

        let (high, low) = split_felt(hash);

        // Extract 24bit chunks
        let b0 = low & (BitShift::fpow(2, 16) - 1);

        let q1 = low / BitShift::fpow(2, 16);
        let b1 = q1 & (BitShift::fpow(2, 24) - 1);

        let q2 = q1 / BitShift::fpow(2, 24);
        let b2 = q2 & (BitShift::fpow(2, 24) - 1);

        let q3 = q2 / BitShift::fpow(2, 24);
        let b3 = q3 & (BitShift::fpow(2, 24) - 1);

        let q4 = q3 / BitShift::fpow(2, 24);
        let b4 = q4 & (BitShift::fpow(2, 24) - 1);

        let q5 = q4 / BitShift::fpow(2, 24);

        let b50 = high & (BitShift::fpow(2, 8) - 1);
        let b5 = b50 * BitShift::fpow(2, 16) + q5;

        let q6 = high / BitShift::fpow(2, 8);
        let b6 = q6 & (BitShift::fpow(2, 24) - 1);

        let q7 = q6 / BitShift::fpow(2, 24);
        let b7 = q7 & (BitShift::fpow(2, 24) - 1);

        let q8 = q7 / BitShift::fpow(2, 24);
        let b8 = q8 & (BitShift::fpow(2, 24) - 1);

        let q9 = q8 / BitShift::fpow(2, 24);
        let b9 = q9 & (BitShift::fpow(2, 24) - 1);

        let q10 = q9 / BitShift::fpow(2, 24);
        let b10 = q10 & (BitShift::fpow(2, 24) - 1);

        challenge.append(b10.try_into().unwrap());
        challenge.append(b9.try_into().unwrap());
        challenge.append(b8.try_into().unwrap());
        challenge.append(b7.try_into().unwrap());
        challenge.append(b6.try_into().unwrap());
        challenge.append(b5.try_into().unwrap());
        challenge.append(b4.try_into().unwrap());
        challenge.append(b3.try_into().unwrap());
        challenge.append(b2.try_into().unwrap());
        challenge.append(b1.try_into().unwrap());
        challenge.append(b0.try_into().unwrap());
        challenge
    }

    #[internal]
    fn extract_client_data_json(signature: Span<felt252>, client_data_json_len: u32) -> Array<u8>{
        // Allocate space for the output array
        let mut arr: Array<u8> = ArrayTrait::new();
        // client data json starts at index 12
        let mut i: u32 = 12;
        // Calculate the end index of the client_data_json
        let len = client_data_json_len + 12;
        loop {
            if i >= len {
                break;
            }
            let felt_val = signature.at(i);
            let byte_val = u8_try_from_felt252(*felt_val).unwrap();
            arr.append(byte_val);

            i += 1;
        };
        arr
    }

    #[internal]
    fn extract_authenticator_data(signature: Span<felt252>, client_data_json_len: u32) -> Array<u8>{
        let authenticator_data_len: usize = (*signature[11 + client_data_json_len]).try_into().unwrap();
        // Allocate space for the output array
        let mut arr: Array<u8> = ArrayTrait::new();
        // client data json starts at index 12
        let mut i: u32 = client_data_json_len + 14;
        // Calculate the end index of the client_data_json
        let len = authenticator_data_len + 14 + client_data_json_len;
        loop {
            if i >= len {
                break;
            }
            let felt_val = signature.at(i);
            let byte_val = u8_try_from_felt252(*felt_val).unwrap();
            arr.append(byte_val);
            i += 1;
        };
        arr
    }


}
