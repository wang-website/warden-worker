use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use constant_time_eq::constant_time_eq;
use js_sys::Uint8Array;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Crypto, CryptoKey, SubtleCrypto};
use worker::js_sys;

use crate::error::AppError;

/// Minimum PBKDF2 iterations for server-side password hashing.
pub const MIN_SERVER_PBKDF2_ITERATIONS: u32 = 600_000;

/// Salt length in bytes for server-side password hashing.
pub const PASSWORD_SALT_LENGTH: usize = 64;
/// Derived key length in bits
const KEY_LENGTH_BITS: u32 = 256;

/// Gets the Crypto interface from the global scope.
fn get_crypto() -> Result<Crypto, AppError> {
    let global = js_sys::global();
    let crypto_value = js_sys::Reflect::get(&global, &JsValue::from_str("crypto"))
        .map_err(|e| AppError::Crypto(format!("Failed to get crypto property: {:?}", e)))?;

    crypto_value
        .dyn_into::<Crypto>()
        .map_err(|_| AppError::Crypto("Failed to cast to Crypto".to_string()))
}

/// Gets the SubtleCrypto interface from the global scope.
fn subtle_crypto() -> Result<SubtleCrypto, AppError> {
    Ok(get_crypto()?.subtle())
}

/// Derives a key using PBKDF2-HMAC-SHA256 (pure Rust).
pub fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length_bits: u32,
) -> Result<Vec<u8>, AppError> {
    let dk_len = (key_length_bits / 8) as usize;
    let mut out = vec![0u8; dk_len];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out);
    Ok(out)
}

/// Derives a key using WebCrypto PBKDF2-SHA256 (for client-side compatible operations).
pub async fn pbkdf2_sha256_webcrypto(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length_bits: u32,
) -> Result<Vec<u8>, AppError> {
    let subtle = subtle_crypto()?;

    let password_array = Uint8Array::new_from_slice(password);
    let password_obj = password_array.as_ref();
    let key_material = JsFuture::from(
        subtle
            .import_key_with_str(
                "raw",
                password_obj,
                "PBKDF2",
                false,
                &js_sys::Array::of1(&JsValue::from_str("deriveBits")),
            )
            .map_err(|e| AppError::Crypto(format!("PBKDF2 import_key failed: {:?}", e)))?,
    )
    .await
    .map_err(|e| AppError::Crypto(format!("PBKDF2 import_key await failed: {:?}", e)))?;

    let salt_array = Uint8Array::new_from_slice(salt);
    let params = web_sys::Pbkdf2Params::new(
        "PBKDF2",
        JsValue::from_str("SHA-256").as_ref(),
        iterations,
        salt_array.as_ref(),
    );

    let derived_bits = JsFuture::from(
        subtle
            .derive_bits_with_object(
                params.as_ref(),
                &CryptoKey::from(key_material),
                key_length_bits,
            )
            .map_err(|e| AppError::Crypto(format!("PBKDF2 derive_bits failed: {:?}", e)))?,
    )
    .await
    .map_err(|e| AppError::Crypto(format!("PBKDF2 derive_bits await failed: {:?}", e)))?;

    Ok(js_sys::Uint8Array::new(&derived_bits).to_vec())
}

/// Generates a cryptographically secure random salt.
pub fn generate_salt() -> Result<String, AppError> {
    let crypto = get_crypto()?;
    let salt = Uint8Array::new_with_length(PASSWORD_SALT_LENGTH as u32);
    crypto
        .get_random_values_with_array_buffer_view(&salt)
        .map_err(|e| AppError::Crypto(format!("Failed to generate random salt: {:?}", e)))?;

    Ok(BASE64.encode(salt.to_vec()))
}

/// Hashes the client-provided master password hash with server-side PBKDF2.
pub async fn hash_password_for_storage(
    client_password_hash: &str,
    salt: &str,
    iterations: u32,
) -> Result<String, AppError> {
    let salt_bytes = BASE64
        .decode(salt)
        .map_err(|e| AppError::Crypto(format!("Failed to decode salt: {:?}", e)))?;

    let derived = pbkdf2_sha256(
        client_password_hash.as_bytes(),
        &salt_bytes,
        iterations,
        KEY_LENGTH_BITS,
    )?;

    Ok(BASE64.encode(derived))
}

/// Verifies a password against a stored hash.
pub async fn verify_password(
    client_password_hash: &str,
    stored_hash: &str,
    salt: &str,
    iterations: u32,
) -> Result<bool, AppError> {
    let computed_hash = hash_password_for_storage(client_password_hash, salt, iterations).await?;
    Ok(constant_time_eq(
        computed_hash.as_bytes(),
        stored_hash.as_bytes(),
    ))
}

/// Generates a hash of the master key for password verification (WebCrypto).
pub async fn hash_master_key(
    master_key: &[u8],
    master_password: &[u8],
) -> Result<Vec<u8>, AppError> {
    pbkdf2_sha256_webcrypto(master_key, master_password, 1, 256).await
}

/// Constant-time string comparison wrapper.
pub fn ct_eq(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}
