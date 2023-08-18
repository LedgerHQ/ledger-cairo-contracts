use core::array::SpanTrait;
use array::ArrayTrait;
use core::traits::Into;
use ledgerCairoContract::account::AccountPlugin;
use ledgerCairoContract::account::StarkSigner;
use ledgerCairoContract::account::AccountABIDispatcher;
use ledgerCairoContract::account::AccountABIDispatcherTrait;
use ledgerCairoContract::account::QUERY_VERSION;
use ledgerCairoContract::account::TRANSACTION_VERSION;
use ledgerCairoContract::account::interface::ISRC6_ID;
use ledgerCairoContract::introspection::interface::ISRC5_ID;
use ledgerCairoContract::tests::utils;
use ledgerCairoContract::token::erc20::ERC20;
use ledgerCairoContract::token::erc20::interface::IERC20Dispatcher;
use ledgerCairoContract::token::erc20::interface::IERC20DispatcherTrait;
use ledgerCairoContract::utils::selectors;
use ledgerCairoContract::utils::serde::SerializedAppend;
use option::OptionTrait;
use serde::Serde;
use starknet::ContractAddress;
use starknet::ClassHash;
use starknet::class_hash_try_from_felt252;
use starknet::account::Call;
use starknet::contract_address_const;
use starknet::testing;

//
// Constants
//

const PUBLIC_KEY: felt252 = 0x333333;
const NEW_PUBKEY: felt252 = 0x789789;
const SALT: felt252 = 123;

#[derive(Drop)]
struct SignedTransactionData {
    private_key: felt252,
    public_key: felt252,
    transaction_hash: felt252,
    r: felt252,
    s: felt252
}

fn STATE() -> AccountPlugin::ContractState {
    AccountPlugin::contract_state_for_testing()
}
fn CLASS_HASH() -> felt252 {
    AccountPlugin::TEST_CLASS_HASH
}
fn CLASS_HASH_SS() -> ClassHash {
        class_hash_try_from_felt252(StarkSigner::TEST_CLASS_HASH).unwrap()
    }
fn ACCOUNT_ADDRESS() -> ContractAddress {
    contract_address_const::<0x111111>()
}
fn SIGNED_TX_DATA() -> SignedTransactionData {
    SignedTransactionData {
        private_key: 1234,
        public_key: 883045738439352841478194533192765345509759306772397516907181243450667673002,
        transaction_hash: 2717105892474786771566982177444710571376803476229898722748888396642649184538,
        r: 3068558690657879390136740086327753007413919701043650133111397282816679110801,
        s: 3355728545224320878895493649495491771252432631648740019139167265522817576501
    }
}

//
// Setup
//

fn setup_dispatcher(data: Option<@SignedTransactionData>) -> AccountABIDispatcher {
    testing::set_version(TRANSACTION_VERSION);

    let mut calldata = array![];
    if data.is_some() {
        let data = data.unwrap();
        testing::set_signature(array![StarkSigner::TEST_CLASS_HASH, *data.r, *data.s].span());
        testing::set_transaction_hash(*data.transaction_hash);

        calldata.append(StarkSigner::TEST_CLASS_HASH);
        calldata.append(1);
        calldata.append(*data.public_key);
    } else {
        calldata.append(StarkSigner::TEST_CLASS_HASH);
        calldata.append(1);
        calldata.append(PUBLIC_KEY);
    }
    let address = utils::deploy(CLASS_HASH(), calldata);
    AccountABIDispatcher { contract_address: address }
}

fn deploy_erc20(recipient: ContractAddress, initial_supply: u256) -> IERC20Dispatcher {
    let name = 0;
    let symbol = 0;
    let mut calldata = array![];

    calldata.append_serde(name);
    calldata.append_serde(symbol);
    calldata.append_serde(initial_supply);
    calldata.append_serde(recipient);

    let address = utils::deploy(ERC20::TEST_CLASS_HASH, calldata);
    IERC20Dispatcher { contract_address: address }
}

//
// constructor
//

#[test]
#[available_gas(2000000)]
fn test_constructor() {
    let mut state = STATE();
    let mut calldata: Array<felt252> = ArrayTrait::new();
    calldata.append(PUBLIC_KEY);
    AccountPlugin::constructor(ref state, CLASS_HASH_SS(), calldata.span());
    let res: felt252 = *AccountPlugin::PublicKeyImpl::get_public_key(@state, CLASS_HASH_SS()).at(0);
    assert(
        res == PUBLIC_KEY, 'Should return public key'
    );
}

//
// supports_interface & supportsInterface
//

#[test]
#[available_gas(2000000)]
fn test_supports_interface() {
    let mut state = STATE();
    let mut calldata: Array<felt252> = ArrayTrait::new();
    calldata.append(PUBLIC_KEY);
    AccountPlugin::constructor(ref state, CLASS_HASH_SS(), calldata.span());
    let supports_default_interface = AccountPlugin::SRC5Impl::supports_interface(@state, ISRC5_ID);
    assert(supports_default_interface, 'Should support base interface');

    let supports_account_interface = AccountPlugin::SRC5Impl::supports_interface(@state, ISRC6_ID);
    assert(supports_account_interface, 'Should support account id');
}

#[test]
#[available_gas(2000000)]
fn test_supportsInterface() {
    let mut state = STATE();
   let mut calldata: Array<felt252> = ArrayTrait::new();
    calldata.append(PUBLIC_KEY);
    AccountPlugin::constructor(ref state, CLASS_HASH_SS(), calldata.span());

    let supports_default_interface = AccountPlugin::SRC5CamelImpl::supportsInterface(@state, ISRC5_ID);
    assert(supports_default_interface, 'Should support base interface');

    let supports_account_interface = AccountPlugin::SRC5CamelImpl::supportsInterface(@state, ISRC6_ID);
    assert(supports_account_interface, 'Should support account id');
}

//
// is_valid_signature & isValidSignature
//

#[test]
#[available_gas(2000000)]
fn test_is_valid_signature() {
    let mut state = STATE();
    let data = SIGNED_TX_DATA();
    let hash = data.transaction_hash;

    let mut good_signature = array![StarkSigner::TEST_CLASS_HASH, data.r, data.s];
    let mut bad_signature = array![StarkSigner::TEST_CLASS_HASH, 0x987, 0x564];

    let mut calldata: Array<felt252> = ArrayTrait::new();
    calldata.append(data.public_key);
    AccountPlugin::constructor(ref state, CLASS_HASH_SS(), calldata.span());
    let is_valid = AccountPlugin::SRC6Impl::is_valid_signature(@state, hash, good_signature);
    assert(is_valid == starknet::VALIDATED, 'Should accept valid signature');

    let is_valid = AccountPlugin::SRC6Impl::is_valid_signature(@state, hash, bad_signature);
    assert(is_valid == 0, 'Should reject invalid signature');
}

#[test]
#[available_gas(2000000)]
fn test_isValidSignature() {
    let mut state = STATE();
    let data = SIGNED_TX_DATA();
    let hash = data.transaction_hash;

    let mut good_signature = array![StarkSigner::TEST_CLASS_HASH, data.r, data.s];
    let mut bad_signature = array![StarkSigner::TEST_CLASS_HASH, 0x987, 0x564];

    let mut calldata: Array<felt252> = ArrayTrait::new();
    calldata.append(data.public_key);
    AccountPlugin::constructor(ref state, CLASS_HASH_SS(), calldata.span());
    let is_valid = AccountPlugin::SRC6CamelOnlyImpl::isValidSignature(@state, hash, good_signature);
    assert(is_valid == starknet::VALIDATED, 'Should accept valid signature');

    let is_valid = AccountPlugin::SRC6CamelOnlyImpl::isValidSignature(@state, hash, bad_signature);
    assert(is_valid == 0, 'Should reject invalid signature');
}

//
// Entry points
//

#[test]
#[available_gas(2000000)]
fn test_validate_deploy() {
    let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA()));

    // `__validate_deploy__` does not directly use the passed arguments. Their
    // values are already integrated in the tx hash. The passed arguments in this
    // testing context are decoupled from the signature and have no effect on the test.
    assert(
        account.__validate_deploy__(CLASS_HASH(), SALT, PUBLIC_KEY) == starknet::VALIDATED,
        'Should validate correctly'
    );
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_validate_deploy_invalid_signature_data() {
    let mut data = SIGNED_TX_DATA();
    data.transaction_hash += 1;
    let account = setup_dispatcher(Option::Some(@data));

    account.__validate_deploy__(CLASS_HASH(), SALT, PUBLIC_KEY);
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_validate_deploy_invalid_signature_length() {
    let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA()));
    let mut signature = array![StarkSigner::TEST_CLASS_HASH];

    signature.append(0x1);
    testing::set_signature(signature.span());

    account.__validate_deploy__(CLASS_HASH(), SALT, PUBLIC_KEY);
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_validate_deploy_empty_signature() {
    let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA()));
    let mut empty_sig = array![StarkSigner::TEST_CLASS_HASH];

    testing::set_signature(empty_sig.span());
    account.__validate_deploy__(CLASS_HASH(), SALT, PUBLIC_KEY);
}

#[test]
#[available_gas(2000000)]
fn test_validate_declare() {
    let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA()));

    // `__validate_declare__` does not directly use the class_hash argument. Its
    // value is already integrated in the tx hash. The class_hash argument in this
    // testing context is decoupled from the signature and has no effect on the test.
    assert(
        account.__validate_declare__(CLASS_HASH()) == starknet::VALIDATED,
        'Should validate correctly'
    );
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_validate_declare_invalid_signature_data() {
    let mut data = SIGNED_TX_DATA();
    data.transaction_hash += 1;
    let account = setup_dispatcher(Option::Some(@data));

    account.__validate_declare__(CLASS_HASH());
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_validate_declare_invalid_signature_length() {
    let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA()));
    let mut signature = array![StarkSigner::TEST_CLASS_HASH];

    signature.append(0x1);
    testing::set_signature(signature.span());

    account.__validate_declare__(CLASS_HASH());
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_validate_declare_empty_signature() {
    let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA()));
    let mut empty_sig = array![StarkSigner::TEST_CLASS_HASH];

    testing::set_signature(empty_sig.span());

    account.__validate_declare__(CLASS_HASH());
}

fn test_execute_with_version(version: Option<felt252>) {
    let data = SIGNED_TX_DATA();
    let account = setup_dispatcher(Option::Some(@data));
    let erc20 = deploy_erc20(account.contract_address, 1000);
    let recipient = contract_address_const::<0x123>();

    // Craft call and add to calls array
    let mut calldata = array![];
    let amount: u256 = 200;
    calldata.append_serde(recipient);
    calldata.append_serde(amount);
    let call = Call {
        to: erc20.contract_address, selector: selectors::transfer, calldata: calldata
    };
    let mut calls = array![];
    calls.append(call);

    // Handle version for test
    if version.is_some() {
        testing::set_version(version.unwrap());
    }

    // Execute
    let ret = account.__execute__(calls);

    // Assert that the transfer was successful
    assert(erc20.balance_of(account.contract_address) == 800, 'Should have remainder');
    assert(erc20.balance_of(recipient) == amount, 'Should have transferred');

    // Test return value
    let mut call_serialized_retval = *ret.at(0);
    let call_retval = Serde::<bool>::deserialize(ref call_serialized_retval);
    assert(call_retval.unwrap(), 'Should have succeeded');
}

#[test]
#[available_gas(2000000)]
fn test_execute() {
    test_execute_with_version(Option::None(()));
}

#[test]
#[available_gas(2000000)]
fn test_execute_query_version() {
    test_execute_with_version(Option::Some(QUERY_VERSION));
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Account: invalid tx version', 'ENTRYPOINT_FAILED'))]
fn test_execute_invalid_version() {
    test_execute_with_version(Option::Some(TRANSACTION_VERSION - 1));
}

#[test]
#[available_gas(2000000)]
fn test_validate() {
    let calls = array![];
    let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA()));

    assert(account.__validate__(calls) == starknet::VALIDATED, 'Should validate correctly');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_validate_invalid() {
    let calls = array![];
    let mut data = SIGNED_TX_DATA();
    data.transaction_hash += 1;
    let account = setup_dispatcher(Option::Some(@data));

    account.__validate__(calls);
}

#[test]
#[available_gas(20000000)]
fn test_multicall() {
    let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA()));
    let erc20 = deploy_erc20(account.contract_address, 1000);
    let recipient1 = contract_address_const::<0x123>();
    let recipient2 = contract_address_const::<0x456>();
    let mut calls = array![];

    // Craft call1
    let mut calldata1 = array![];
    let amount1: u256 = 300;
    calldata1.append_serde(recipient1);
    calldata1.append_serde(amount1);
    let call1 = Call {
        to: erc20.contract_address, selector: selectors::transfer, calldata: calldata1
    };

    // Craft call2
    let mut calldata2 = array![];
    let amount2: u256 = 500;
    calldata2.append_serde(recipient2);
    calldata2.append_serde(amount2);
    let call2 = Call {
        to: erc20.contract_address, selector: selectors::transfer, calldata: calldata2
    };

    // Bundle calls and exeute
    calls.append(call1);
    calls.append(call2);
    let ret = account.__execute__(calls);

    // Assert that the transfers were successful
    assert(erc20.balance_of(account.contract_address) == 200, 'Should have remainder');
    assert(erc20.balance_of(recipient1) == 300, 'Should have transferred');
    assert(erc20.balance_of(recipient2) == 500, 'Should have transferred');

    // Test return value
    let mut call1_serialized_retval = *ret.at(0);
    let mut call2_serialized_retval = *ret.at(1);
    let call1_retval = Serde::<bool>::deserialize(ref call1_serialized_retval);
    let call2_retval = Serde::<bool>::deserialize(ref call2_serialized_retval);
    assert(call1_retval.unwrap(), 'Should have succeeded');
    assert(call2_retval.unwrap(), 'Should have succeeded');
}

#[test]
#[available_gas(2000000)]
fn test_multicall_zero_calls() {
    let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA()));
    let mut calls = array![];

    let ret = account.__execute__(calls);

    // Test return value
    assert(ret.len() == 0, 'Should have an empty response');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Account: invalid caller', ))]
fn test_account_called_from_contract() {
    let calls = array![];
    let caller = contract_address_const::<0x123>();

    testing::set_contract_address(ACCOUNT_ADDRESS());
    testing::set_caller_address(caller);

    AccountPlugin::SRC6Impl::__execute__(@STATE(), calls);
}

//
// set_public_key & get_public_key
//


//
// setPublicKey & getPublicKey
//
//
// Test internals
//

#[test]
#[available_gas(2000000)]
fn test_assert_only_self_true() {
    testing::set_contract_address(ACCOUNT_ADDRESS());
    testing::set_caller_address(ACCOUNT_ADDRESS());
    AccountPlugin::assert_only_self();
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Account: unauthorized', ))]
fn test_assert_only_self_false() {
    testing::set_contract_address(ACCOUNT_ADDRESS());
    let other = contract_address_const::<0x4567>();
    testing::set_caller_address(other);
    AccountPlugin::assert_only_self();
}

#[test]
#[available_gas(2000000)]
fn test__is_valid_signature() {
    let mut state = STATE();
    let data = SIGNED_TX_DATA();
    let hash = data.transaction_hash;

    let mut good_signature = array![StarkSigner::TEST_CLASS_HASH, data.r, data.s];
    let mut bad_signature = array![StarkSigner::TEST_CLASS_HASH, 0x987, 0x564];
    let mut invalid_length_signature = array![StarkSigner::TEST_CLASS_HASH, 0x987];
    let mut calldata: Array<felt252> = ArrayTrait::new();
    calldata.append(data.public_key);
    AccountPlugin::constructor(ref state, CLASS_HASH_SS(), calldata.span());
    let is_valid = AccountPlugin::InternalImpl::_is_valid_signature(@state, hash, good_signature.span());
    assert(is_valid, 'Should accept valid signature');

    let is_valid = AccountPlugin::InternalImpl::_is_valid_signature(@state, hash, bad_signature.span());
    assert(!is_valid, 'Should reject invalid signature');

    let is_valid = AccountPlugin::InternalImpl::_is_valid_signature(
        @state, hash, invalid_length_signature.span()
    );
    assert(!is_valid, 'Should reject invalid length');
}
