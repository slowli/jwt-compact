//! Provides compatibility layer for using `digest 0.10` digests where `digest 0.9` traits
//! are required. Motivated by `k256` and `rsa` crates depending on `digest 0.9`.

#[cfg(feature = "k256")]
use k256::ecdsa::digest as digest_legacy;

use digest_legacy::{generic_array::GenericArray, BlockInput, FixedOutput, Reset, Update};
use sha2::digest::{self, crypto_common::BlockSizeUser, Output};

/// Thin wrapper around a `digest 0.10` hash digest. Implements traits from both 0.9 and 0.10.
#[derive(Debug, Clone, Copy, Default)]
#[repr(transparent)]
pub(crate) struct Compat<T>(T);

impl<T: digest::Update> Update for Compat<T> {
    fn update(&mut self, data: impl AsRef<[u8]>) {
        <T as digest::Update>::update(&mut self.0, data.as_ref());
    }
}

impl<T: digest::Update> digest::Update for Compat<T> {
    fn update(&mut self, data: &[u8]) {
        <T as digest::Update>::update(&mut self.0, data);
    }
}

impl<T> FixedOutput for Compat<T>
where
    T: digest::FixedOutputReset,
{
    type OutputSize = <T as digest::OutputSizeUser>::OutputSize;

    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        <T as digest::FixedOutput>::finalize_into(self.0, out);
    }

    fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        <T as digest::FixedOutputReset>::finalize_into_reset(&mut self.0, out);
    }
}

impl<T: digest::OutputSizeUser> digest::OutputSizeUser for Compat<T> {
    type OutputSize = <T as digest::OutputSizeUser>::OutputSize;
}

impl<T: digest::FixedOutput> digest::FixedOutput for Compat<T> {
    fn finalize_into(self, out: &mut Output<Self>) {
        <T as digest::FixedOutput>::finalize_into(self.0, out);
    }
}

impl<T: digest::Reset> digest::Reset for Compat<T> {
    fn reset(&mut self) {
        <T as digest::Reset>::reset(&mut self.0);
    }
}

impl<T: digest::Reset> Reset for Compat<T> {
    fn reset(&mut self) {
        <T as digest::Reset>::reset(&mut self.0);
    }
}

impl<T: digest::FixedOutputReset> digest::FixedOutputReset for Compat<T> {
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        <T as digest::FixedOutputReset>::finalize_into_reset(&mut self.0, out);
    }
}

impl<T: digest::HashMarker> digest::HashMarker for Compat<T> {}

impl<T: BlockSizeUser> BlockInput for Compat<T> {
    type BlockSize = <T as BlockSizeUser>::BlockSize;
}
