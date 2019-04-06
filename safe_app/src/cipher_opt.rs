// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Cipher options.

use crate::client::AppClient;
use crate::errors::AppError;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use rust_sodium::crypto::{box_, sealedbox, secretbox};
use safe_core::{Client, CoreError};
use crate::AppContext;

/// Cipher Options
#[derive(Debug)]
pub enum CipherOpt {
    /// No encryption
    PlainText,
    /// Encrypt using symmetric keys (usually for private data)
    Symmetric,
    /// Encrypt using asymmetric encryption (encrypting for peer to read)
    Asymmetric {
        /// PublicKey of the peer to whom we want to encrypt
        peer_encrypt_key: box_::PublicKey,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum WireFormat {
    Plain(Vec<u8>),
    Symmetric {
        nonce: secretbox::Nonce,
        cipher_text: Vec<u8>,
    },
    Asymmetric(Vec<u8>),
}

impl CipherOpt {
    /// Encrypt plain text
    pub fn encrypt(&self, plain_text: &[u8], app_ctx: &AppContext) -> Result<Vec<u8>, AppError> {
        match *self {
            CipherOpt::PlainText => Ok(serialise(&WireFormat::Plain(plain_text.to_owned()))?),
            CipherOpt::Symmetric => {
                let nonce = secretbox::gen_nonce();
                let cipher_text = secretbox::seal(plain_text, &nonce, app_ctx.sym_enc_key()?);
                let wire_format = WireFormat::Symmetric { nonce, cipher_text };

                Ok(serialise(&wire_format)?)
            }
            CipherOpt::Asymmetric {
                ref peer_encrypt_key,
            } => {
                let cipher_text = sealedbox::seal(plain_text, peer_encrypt_key);
                Ok(serialise(&WireFormat::Asymmetric(cipher_text))?)
            }
        }
    }

    /// Decrypt something encrypted by CipherOpt::encrypt()
    pub fn decrypt(
        cipher_text: &[u8],
        app_ctx: &AppContext,
        client: &AppClient,
    ) -> Result<Vec<u8>, AppError> {
        if cipher_text.is_empty() {
            return Ok(Vec::new());
        }

        match deserialise::<WireFormat>(cipher_text)? {
            WireFormat::Plain(plain_text) => Ok(plain_text),
            WireFormat::Symmetric { nonce, cipher_text } => Ok(secretbox::open(
                &cipher_text,
                &nonce,
                app_ctx.sym_enc_key()?,
            ).map_err(|()| CoreError::SymmetricDecipherFailure)?),
            WireFormat::Asymmetric(cipher_text) => {
                let (asym_pk, asym_sk) = client
                    .encryption_keypair()
                    .ok_or(AppError::UnregisteredClientAccess)?;
                Ok(sealedbox::open(&cipher_text, &asym_pk, &asym_sk)
                    .map_err(|()| CoreError::AsymmetricDecipherFailure)?)
            }
        }
    }
}
