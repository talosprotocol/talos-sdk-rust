use talos_core_rs::adapters::crypto::RealCryptoProvider;
use talos_core_rs::domain::wallet::Wallet;

pub struct Identity {
    wallet: Wallet,
    provider: RealCryptoProvider,
}

impl Identity {
    /// Generate a new random identity
    pub fn generate() -> Self {
        let provider = RealCryptoProvider;
        let wallet = Wallet::generate(None, &provider);
        Self { wallet, provider }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.wallet.sign(message, &self.provider)
    }

    /// Get public key as hex string
    pub fn public_key(&self) -> String {
        hex::encode(self.wallet.public_key())
    }

    /// Get DID
    pub fn did(&self) -> String {
        self.wallet.to_did()
    }
}
