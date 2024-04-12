#![allow(unused_imports)]

use ethers_core::types::{Block, BlockId, Transaction};
use ethers_providers::Middleware;
use ethers_providers::{Http, Provider};

use alloy_primitives::B256;
// use alloy_rpc_types::Transaction;
use alloy_rpc_types_trace::geth::{
    FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions,
    GethTrace, NoopFrame,
};
use revm_inspectors::tracing::js::{JsInspector, TransactionContext};
use revm_inspectors::tracing::{
    FourByteInspector, MuxInspector, TracingInspector, TracingInspectorConfig,
};

use anyhow;
use std::fmt::Debug;
use std::sync::Arc;

use revm::db::{CacheDB, Database, EthersDB, State, StateBuilder, DatabaseRef};
use revm::inspectors::TracerEip3155;
use revm::primitives::{Address, EnvWithHandlerCfg, ResultAndState, TransactTo, U256};
use revm::{inspector_handle_register, Evm, GetInspector};

use crate::utils::{convert_hash, from_hash};

macro_rules! local_fill {
    ($left:expr, $right:expr, $fun:expr) => {
        if let Some(right) = $right {
            $left = $fun(right.0)
        }
    };
    ($left:expr, $right:expr) => {
        if let Some(right) = $right {
            $left = Address::from(right.as_fixed_bytes())
        }
    };
}

pub struct EVM {
    chain_id: u64,
    client: Arc<Provider<Http>>,
}

impl EVM {
    pub fn new(url: &'static str, chain_id: u64) -> Self {
        let client = Provider::<Http>::try_from(url).expect("could not create provider");
        let client = Arc::new(client);

        EVM { chain_id, client }
    }

    pub async fn get_block_with_tx(&self, block_id: BlockId) -> anyhow::Result<Block<Transaction>> {
        let block = match self.client.get_block_with_txs(block_id).await {
            Ok(Some(block)) => block,
            Ok(None) => anyhow::bail!("Block not found"),
            Err(error) => anyhow::bail!("Error: {:?}", error),
        };
        Ok(block)
    }

    pub async fn get_tx(&self, tx_hash: B256) -> anyhow::Result<Transaction> {
        let tx = match self.client.get_transaction(convert_hash(tx_hash)).await {
            Ok(Some(tx)) => tx,
            Ok(None) => anyhow::bail!("Transaction not found"),
            Err(error) => anyhow::bail!("Error: {:?}", error),
        };
        Ok(tx)
    }

    pub fn prepare_db_env(
        &self,
        tx_hash: B256,
        block: Block<Transaction>,
    ) -> anyhow::Result<(State<CacheDB<EthersDB<Provider<Http>>>>, EnvWithHandlerCfg)> {
        let previous_block_number = block.number.unwrap() - 1;
        // Use the previous block state as the db with caching
        let prev_id: BlockId = previous_block_number.into();
        // SAFETY: This cannot fail since this is in the top-level tokio runtime
        let state_db = EthersDB::new(Arc::clone(&self.client), Some(prev_id)).expect("panic");
        let cache_db: CacheDB<EthersDB<Provider<Http>>> = CacheDB::new(state_db);
        let mut state = StateBuilder::new_with_database(cache_db).build();

        let mut evm = Evm::builder()
            .with_db(&mut state)
            .modify_block_env(|b| {
                if let Some(number) = block.number {
                    let nn = number.0[0];
                    b.number = U256::from(nn);
                }
                local_fill!(b.coinbase, block.author);
                local_fill!(b.timestamp, Some(block.timestamp), U256::from_limbs);
                local_fill!(b.difficulty, Some(block.difficulty), U256::from_limbs);
                local_fill!(b.gas_limit, Some(block.gas_limit), U256::from_limbs);
                if let Some(base_fee) = block.base_fee_per_gas {
                    local_fill!(b.basefee, Some(base_fee), U256::from_limbs);
                }
            })
            .modify_cfg_env(|c| {
                c.chain_id = self.chain_id;
            })
            .build();

        for tx in block.transactions {
            evm = evm
                .modify()
                .modify_tx_env(|etx| {
                    etx.caller = Address::from(tx.from.as_fixed_bytes());
                    etx.gas_limit = tx.gas.as_u64();
                    local_fill!(etx.gas_price, tx.gas_price, U256::from_limbs);
                    local_fill!(etx.value, Some(tx.value), U256::from_limbs);
                    etx.data = tx.input.0.into();
                    let mut gas_priority_fee = U256::ZERO;
                    local_fill!(
                        gas_priority_fee,
                        tx.max_priority_fee_per_gas,
                        U256::from_limbs
                    );
                    etx.gas_priority_fee = Some(gas_priority_fee);
                    etx.chain_id = Some(self.chain_id);
                    etx.nonce = Some(tx.nonce.as_u64());
                    if let Some(access_list) = tx.access_list {
                        etx.access_list = access_list
                            .0
                            .into_iter()
                            .map(|item| {
                                let new_keys: Vec<U256> = item
                                    .storage_keys
                                    .into_iter()
                                    .map(|h256| U256::from_le_bytes(h256.0))
                                    .collect();
                                (Address::from(item.address.as_fixed_bytes()), new_keys)
                            })
                            .collect();
                    } else {
                        etx.access_list = Default::default();
                    }

                    etx.transact_to = match tx.to {
                        Some(to_address) => {
                            TransactTo::Call(Address::from(to_address.as_fixed_bytes()))
                        }
                        None => TransactTo::create(),
                    };
                })
                .build();

            if tx.hash == convert_hash(tx_hash) {  // There will be only one tx with this hash
                break;
            } else {
                evm.transact_commit()?;
            }
        }

        let (_, env) = evm.into_db_and_env_with_handler_cfg();

        Ok((state, env))
    }

    pub async fn trace_transaction(
        &self,
        tx_hash: B256,
        opts: GethDebugTracingOptions,
    ) -> anyhow::Result<GethTrace> {
        let tx = self.get_tx(tx_hash).await?;
        let block = self
            .get_block_with_tx(tx.block_hash.unwrap().into())
            .await?;

        let (db, env) = self.prepare_db_env(tx_hash, block)?;

        let GethDebugTracingOptions {
            config,
            tracer,
            tracer_config,
            ..
        } = opts;

        if let Some(tracer) = tracer {
            return match tracer {
                GethDebugTracerType::BuiltInTracer(tracer) => match tracer {
                    GethDebugBuiltInTracerType::FourByteTracer => {
                        let mut inspector = FourByteInspector::default();
                        let (_res, _) = inspect(db, env, &mut inspector)?;
                        return Ok(FourByteFrame::from(inspector).into());
                    }
                    GethDebugBuiltInTracerType::CallTracer => {
                        let call_config = tracer_config.into_call_config()?;

                        let mut inspector = TracingInspector::new(
                            TracingInspectorConfig::from_geth_call_config(&call_config),
                        );

                        let (res, _) = inspect(db, env, &mut inspector)?;

                        let frame = inspector
                            .into_geth_builder()
                            .geth_call_traces(call_config, res.result.gas_used());

                        return Ok(frame.into());
                    }
                    GethDebugBuiltInTracerType::PreStateTracer => {
                        let prestate_config = tracer_config
                            .into_pre_state_config()?;

                        let mut inspector = TracingInspector::new(
                            TracingInspectorConfig::from_geth_prestate_config(&prestate_config),
                        );
                        let (res, _, db) = inspect_and_return_db(db, env, &mut inspector)?;

                        let frame = inspector.into_geth_builder().geth_prestate_traces(
                            &res,
                            prestate_config,
                            db.database,
                        )?;

                        return Ok(frame.into())
                    }
                    GethDebugBuiltInTracerType::NoopTracer => Ok(NoopFrame::default().into()),
                    GethDebugBuiltInTracerType::MuxTracer => {
                        let mux_config = tracer_config
                            .into_mux_config()?;

                        let mut inspector = MuxInspector::try_from_config(mux_config)?;

                        let (res, _, db) = inspect_and_return_db(db, env, &mut inspector)?;
                        let frame = inspector.try_into_mux_frame(&res, &db.database)?;
                        return Ok(frame.into())
                    }
                },
                GethDebugTracerType::JsTracer(_code) => {
                    // let config = tracer_config.into_json();
                    // let mut inspector = JsInspector::with_transaction_context(
                    //     code,
                    //     config,
                    //     TransactionContext{
                    //         block_hash: Some(from_hash(block.hash.unwrap())),
                    //         ..Default::default()
                    //     },
                    // ).map_err(|e| anyhow::anyhow!("{e}"))?;
                    // let (res, env, db) = inspect_and_return_db(db, env, &mut inspector)?;

                    // let state = res.state.clone();
                    // let result = inspector.json_result(res, &env, db)?;
                    // Ok(GethTrace::JS(result))

                    Ok(NoopFrame::default().into())
                }
            };
        }

        // default structlog tracer

        let mut tracing_inspector =
            TracingInspector::new(TracingInspectorConfig::from_geth_config(&config));

        let (res, _) = inspect(db, env, &mut tracing_inspector)?;

        let gas_used = res.result.gas_used();
        let return_value = res.result.into_output().unwrap_or_default();

        let frame =
            tracing_inspector
                .into_geth_builder()
                .geth_traces(gas_used, return_value, opts.config);

        Ok(frame.into())
    }
}

/// Executes the [EnvWithHandlerCfg] against the given [Database] without committing state changes.
pub(crate) fn inspect<DB, I>(
    db: DB,
    env: EnvWithHandlerCfg,
    inspector: I,
) -> anyhow::Result<(ResultAndState, EnvWithHandlerCfg)>
where
    DB: Database,
    <DB as Database>::Error: Debug,
    I: GetInspector<DB>,
{
    let mut evm = revm::Evm::builder()
        .with_db(db)
        .with_external_context(inspector)
        .with_env_with_handler_cfg(env)
        .append_handler_register(inspector_handle_register)
        .build();
    let res = evm.transact().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let (_, env) = evm.into_db_and_env_with_handler_cfg();
    Ok((res, env))
}

/// Same as [inspect] but also returns the database again.
///
/// Even though [Database] is also implemented on `&mut`
/// this is still useful if there are certain trait bounds on the Inspector's database generic type
#[allow(dead_code)]
pub(crate) fn inspect_and_return_db<DB, I>(
    db: DB,
    env: EnvWithHandlerCfg,
    inspector: I,
) -> anyhow::Result<(ResultAndState, EnvWithHandlerCfg, DB)>
where
    DB: Database,
    <DB as Database>::Error: Debug,
    I: GetInspector<DB>,
{
    let mut evm = revm::Evm::builder()
        .with_db(db)
        .with_external_context(inspector)
        .with_env_with_handler_cfg(env)
        .append_handler_register(inspector_handle_register)
        .build();
    let res = evm.transact().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let (db, env) = evm.into_db_and_env_with_handler_cfg();
    Ok((res, env, db))
}
