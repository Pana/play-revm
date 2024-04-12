#![allow(dead_code, unused)]
use revm::{
    db::{CacheDB, EmptyDB, EthersDB},
    inspector_handle_register,
    inspectors::TracerEip3155,
    primitives::{
        address, hex::FromHex, keccak256, AccountInfo, Address, BlockEnv, Bytecode, Bytes, CfgEnv,
        CreateScheme, EVMError, Env, EnvWithHandlerCfg, HandlerCfg, ResultAndState, SpecId,
        TransactTo, TxEnv, B256, U256,
    },
    Database, Evm, GetInspector,
};
use revm_inspectors::tracing::{self, TracingInspector, TracingInspectorConfig};
use ruint::uint;
use std::{convert::From, env, error::Error, fmt::Display, str::FromStr};

use alloy_rpc_types_trace::geth::{
    GethDebugTracingOptions, GethDefaultTracingOptions, GethTrace, NoopFrame,
};

use crate::{
    error::RevmError,
    static_data::{COUNTER_CONTRACT_CODE, ERC20_ADDR, ERC20_CONTRACT_CODE, TEST_ADDRESS},
};

pub async fn trace_transaction(
    tx_hash: B256,
    opts: GethDebugTracingOptions,
) -> Result<GethTrace, RevmError> {
    Ok(GethTrace::NoopTracer(NoopFrame::default()))
}

/**
 * Create an EVM Builder and use evm_inspectors
 * 1. Setup db
 * 2. Setup config
 * 3. Setup TracingInspector
 * 4. Run inspect
 * 5. Get the result and frame
 */
pub fn collect_trace() -> Result<String, RevmError> {
    let mut cache_db = init_db();

    let mut tracing_inspector = TracingInspector::new(TracingInspectorConfig::default_geth());

    // config the tx env
    let transact_to = TransactTo::Create(CreateScheme::Create); // deploy contract
    let data =
        Bytes::from_hex(COUNTER_CONTRACT_CODE).expect("The counter code parse should not failed");
    let tx = TxEnv {
        caller: TEST_ADDRESS,
        gas_limit: 1000_000,
        gas_price: uint!(1_U256),
        transact_to,
        value: uint!(0_U256),
        data,
        nonce: Some(0),
        chain_id: Some(1),
        ..Default::default()
    };

    // config the block env
    let block = BlockEnv {
        number: uint!(1000_U256),
        coinbase: TEST_ADDRESS,
        timestamp: U256::from(1712029289),
        gas_limit: U256::from(3000_0000),
        difficulty: U256::from(1000),
        ..Default::default()
    };

    let env_with_hander_cfg = setup_env(tx, block);

    let (res, _) = inspect(&mut cache_db, env_with_hander_cfg, &mut tracing_inspector)?;

    let gas_used = res.result.gas_used();
    let return_value = res.result.into_output().unwrap_or_default();
    let config = GethDefaultTracingOptions::default()
        .with_enable_memory(true)
        .with_enable_return_data(true)
        .with_disable_storage(false)
        .with_debug(true);

    let frame = tracing_inspector
        .into_geth_builder()
        .geth_traces(gas_used, return_value, config);

    let frame_json = serde_json::to_string_pretty(&frame).map_err(|e| format!("{}", e))?;

    Ok(frame_json)
}

/// Executes the [EnvWithHandlerCfg] against the given [Database] without committing state changes.
pub(crate) fn inspect<DB, I>(
    db: DB,
    env: EnvWithHandlerCfg,
    inspector: I,
) -> Result<(ResultAndState, EnvWithHandlerCfg), String>
where
    DB: Database,
    I: GetInspector<DB>,
{
    let mut evm = revm::Evm::builder()
        .with_db(db)
        .with_external_context(inspector)
        .with_env_with_handler_cfg(env)
        .append_handler_register(inspector_handle_register)
        .build();
    let res = evm
        .transact()
        .map_err(|e: EVMError<<DB as Database>::Error>| match e {
            EVMError::Transaction(_) => "Transaction error".to_string(),
            EVMError::Header(e) => e.to_string(),
            EVMError::Database(e) => "database error".to_string(),
            EVMError::Custom(e) => e,
        })
        // .map_err(|e: EVMError<<DB as Database>::Error>| evm_error_to_string(e))  // TODO: why this line is not working?
        ?;
    let (_, env) = evm.into_db_and_env_with_handler_cfg();
    Ok((res, env))
}

fn evm_error_to_string<DB: Database>(e: EVMError<<DB as Database>::Error>) -> String {
    match e {
        EVMError::Transaction(_) => "Transaction error".to_string(),
        EVMError::Header(e) => e.to_string(),
        EVMError::Database(e) => "database error".to_string(),
        EVMError::Custom(e) => e,
    }
}

fn insert_account_info(cache_db: &mut CacheDB<EmptyDB>, addr: Address, code: Bytes) {
    let code_hash = hex::encode(keccak256(code.clone()));
    let account_info = AccountInfo::new(
        U256::from(0),
        0,
        B256::from_str(&code_hash).unwrap(),
        Bytecode::new_raw(code),
    );
    cache_db.insert_account_info(addr, account_info);
}

fn init_db() -> CacheDB<EmptyDB> {
    let mut cache_db = CacheDB::new(EmptyDB::default());

    insert_account_info(&mut cache_db, ERC20_ADDR, ERC20_CONTRACT_CODE);

    // setup a test account with 1000 eth balance
    let balance = uint!(1000_000_000_000_000_000_000_U256); // 1000 eth   // ? where is alloy's eth related util methods or documentations
    let account_info = AccountInfo::from_balance(balance);
    cache_db.insert_account_info(TEST_ADDRESS, account_info);

    // account storage set example
    // cache_db
    //     .insert_account_storage(
    //         BURNTPIX_MAIN_ADDRESS,
    //         U256::from(0),
    //         U256::from_be_bytes(*STORAGE_ZERO),
    //     )
    //     .unwrap();

    cache_db
}

fn setup_env(tx: TxEnv, block: BlockEnv) -> EnvWithHandlerCfg {
    let cfg_env = CfgEnv::default(); // config the chain env
    let env = Env::boxed(cfg_env, block, tx);
    let handler_cfg = HandlerCfg::new(SpecId::CANCUN); // default use cancun
    EnvWithHandlerCfg::new(env, handler_cfg)
}

pub fn setup_evm() {
    let mut cache_db = CacheDB::new(EmptyDB::default());

    // setup a test account with balance
    let test_address = address!("7deFad05B632Ba2CeF7EA20731021657e20a7596"); // a test address
    let balance = uint!(1000_000_000_000_000_000_000_U256); // 1000 eth   // ? where is alloy's eth related util methods or documentations
    let account_info = AccountInfo::from_balance(balance);
    cache_db.insert_account_info(test_address, account_info);

    // setup a erc20 contract with bytecode
    // let nonce = 2;
    // let erc20_address = test_address.create(nonce); // calculate contract address from sender and nonce
    // let byte_code = ""; // todo use a erc20 contract bytecode
    // let b = Bytes::from_hex(byte_code).unwrap();
    // let erc20_bcode = Bytecode::new_raw(b);
    // let erc20_contract_info = AccountInfo::new(U256::from(0), 0, B256::default(), erc20_bcode.to_checked());
    // cache_db.insert_account_info(erc20_address, erc20_contract_info);

    let tracing_inspector = TracingInspector::new(TracingInspectorConfig::default_geth());

    let mut evm = Evm::builder()
        .with_db(&mut cache_db)
        .with_external_context(tracing_inspector)
        .append_handler_register(inspector_handle_register)
        .build();
}
