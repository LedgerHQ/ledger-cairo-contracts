# Ledger Contracts for Cairo based on OpenZeppelin

> **Warning**
> This repo contains highly experimental code.
> It has no code coverage checks.
> It hasn't been audited.
> **Use at your own risk.**

## Prepare the environment

Simply [install Cairo and scarb](https://docs.swmansion.com/scarb/download).

## Development

### Set up the project

Clone the repository:

```bash
git clone git@github.com:LedgerHQ/ledger-cairo-contracts.git
```

`cd` into it and build:

```bash
$ cd ledger-cairo-contracts
$ scarb build

Compiling lib(ledgerCairoContract) ledgerCairoContract v0.1.0 (~/ledger-cairo-contracts/Scarb.toml)
Compiling starknet-contract(ledgerCairoContract) ledgerCairoContract v0.1.0 (~/ledger-cairo-contracts/Scarb.toml)
Finished release target(s) in 10 seconds
```

### Run tests

```bash
scarb test
```

### Deploiement

```bash
pip install -r requirements.txt
```

To use invoke do not forget to set the address of the account in .env!

```bash
python3 scripts/deploy.py 
python3 scripts/invoke.py 
```

## Security

> ⚠️ Warning! ⚠️
> This project is still in a very early and experimental phase. It has never been audited nor thoroughly reviewed for security vulnerabilities. Do not use in production.

## License

Contracts are released under the [MIT License](LICENSE).

## Special thanks to OpenZeppelin

Base contracts can be found [on Github](https://github.com/OpenZeppelin/cairo-contracts/)