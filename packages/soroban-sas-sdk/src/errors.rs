//! Specialized error handling for SDK

#[derive(Debug)]
pub enum SdkError {
    ContractError(u32),
    DecodingError(String),
    RpcError(String),
}
