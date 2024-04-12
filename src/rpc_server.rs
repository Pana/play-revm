use alloy_primitives::B256;
use alloy_rpc_types_trace::geth::{GethDebugTracingOptions, GethTrace, NoopFrame};
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

#[rpc]
pub trait Rpc {
    /// Adds two numbers and returns a result
    #[rpc(name = "add")]
    fn add(&self, a: u64, b: u64) -> Result<u64>;

    #[rpc(name = "debug_traceTransaction_1")]
    fn debug_trace_transaction(
        &self,
        tx_hash: B256,
        opts: Option<GethDebugTracingOptions>,
    ) -> Result<GethTrace>;
}

pub struct RpcImpl;

impl Rpc for RpcImpl {
    fn add(&self, a: u64, b: u64) -> Result<u64> {
        Ok(a + b)
    }

    fn debug_trace_transaction(
        &self,
        _tx_hash: B256,
        _opts: Option<GethDebugTracingOptions>,
    ) -> Result<GethTrace> {
        // Empty impl
        Ok(GethTrace::NoopTracer(NoopFrame::default()))
    }
}
