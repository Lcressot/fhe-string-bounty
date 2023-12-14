use crate::core_crypto::fft_impl::common::tests::test_bootstrap_generic;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKeyOwned;
use crate::core_crypto::prelude::test::{FFT_U32_PARAMS, FFT_U64_PARAMS};

#[test]
fn test_bootstrap_u64() {
    test_bootstrap_generic::<u64, FourierLweBootstrapKeyOwned>(FFT_U64_PARAMS);
}

#[test]
fn test_bootstrap_u32() {
    test_bootstrap_generic::<u32, FourierLweBootstrapKeyOwned>(FFT_U32_PARAMS);
}
