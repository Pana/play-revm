mod error;
mod evm;
mod revm_misc;
mod rpc_server;
mod static_data;
mod utils;

use alloy_primitives::B256;
use alloy_rpc_types_trace::geth::GethDebugTracingOptions;
use jsonrpc_http_server::{
    jsonrpc_core::{to_value, Error, ErrorCode, IoHandler, Params},
    ServerBuilder,
};

use evm::EVM;

fn main() -> anyhow::Result<()> {
    let mut io = IoHandler::new();

    io.add_method("debug_traceTransaction", |params: Params| async {
        let (tx_hash, opts): (B256, GethDebugTracingOptions) = params.parse()?; // TODO: support second parameter to be optional

        let evm = EVM::new("https://evmtestnet.confluxrpc.com", 71);

        let result = evm
            .trace_transaction(tx_hash, opts)
            .await
            .map_err(|e| Error {
                code: ErrorCode::InternalError,
                message: format!("{}", e),
                data: None,
            })?;

        let value = to_value(result).map_err(|e| Error {
            code: ErrorCode::InternalError,
            message: format!("{}", e),
            data: None,
        })?;

        Ok(value)
    });

    let listen_addr = "127.0.0.1:3030";

    let server = ServerBuilder::new(io)
        .threads(3)
        .start_http(&listen_addr.parse()?)?;

    println!("RPC Server started at {listen_addr}");

    server.wait();

    Ok(())
}
