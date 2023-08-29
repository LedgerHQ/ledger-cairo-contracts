use result::ResultTrait;
use starknet::{
    StorageBaseAddress, Store, SyscallResult, storage_read_syscall, storage_write_syscall,
    storage_address_from_base_and_offset
};
use starknet::secp256r1::Secp256r1Point;
use starknet::secp256r1::Secp256r1Impl;
use starknet::secp256r1::Secp256PointTrait;
use option::OptionTrait;

// ANCHOR: StorageAccessImpl
impl StoreSecp256r1Point of Store<Secp256r1Point> {
    fn read(address_domain: u32, base: StorageBaseAddress) -> SyscallResult<Secp256r1Point> {
        StoreSecp256r1Point::read_at_offset(address_domain, base, 0)
    }

    fn write(
        address_domain: u32, base: StorageBaseAddress, value: Secp256r1Point
    ) -> SyscallResult<()> {
        StoreSecp256r1Point::write_at_offset(address_domain, base, 0, value)
    }

    fn read_at_offset(
        address_domain: u32, base: StorageBaseAddress, mut offset: u8
    ) -> SyscallResult<Secp256r1Point> {
    
        let low: u256 = Store::<u256>::read_at_offset(address_domain, base, offset).unwrap();
        offset += Store::<u256>::size();
        let high: u256 = Store::<u256>::read_at_offset(address_domain, base, offset).unwrap();
        // Return the point.
        let point: Secp256r1Point = Secp256r1Impl::secp256_ec_new_syscall(low, high).unwrap().unwrap();
        Result::Ok(point)
    }


    fn write_at_offset(
        address_domain: u32, base: StorageBaseAddress, mut offset: u8, mut value: Secp256r1Point
    ) -> SyscallResult<()> {
        let (x, y) = value.get_coordinates().unwrap();
        Store::<u256>::write_at_offset(address_domain, base, offset, x);
        offset += Store::<u256>::size();
        Store::<u256>::write_at_offset(address_domain, base, offset, y);
        Result::Ok(())        
    }

     fn size() -> u8 {
        2 * Store::<u256>::size()
    }
}