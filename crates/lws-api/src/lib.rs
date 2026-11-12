//! Wire types of the Monero light wallet server REST API.
//!
//! The shapes follow the community specification
//! (monero-project/meta, `api/lightwallet_rest.md`) and the extensions
//! monero-lws added on top of it without changing it: subaddress
//! provisioning (`/get_subaddrs`, `/upsert_subaddrs`, `/provision_subaddrs`),
//! `/get_version`, `received_output` lists on transactions, and the
//! `lookahead` fields. A client that knows only the community spec can
//! ignore every extension field.
//!
//! Every request is an HTTP `POST` of a JSON object to `/<method>`; every
//! response is a JSON object. Amounts travel as decimal strings
//! ([`Amount`]), keys and hashes as lowercase hex ([`Hex32`], [`Hex8`]),
//! timestamps as ISO 8601 text ([`Timestamp`]).
//!
//! `Debug` on the types that carry a private view key ([`Login`] and the
//! admin requests) prints neither the key nor the address, and a type's
//! deserialization errors never quote the value that failed, so neither
//! ends up in a log by accident.

#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A `uint64-string`: a 64-bit amount or index written as a decimal string,
/// since JSON numbers past 2^53 lose precision in many readers.
///
/// Reading accepts a number too, for lenient clients.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(pub u64);

impl Serialize for Amount {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl de::Visitor<'_> for V {
            type Value = Amount;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a decimal string or an unsigned integer")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Amount, E> {
                v.parse().map(Amount).map_err(|_| E::custom("not an unsigned decimal"))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Amount, E> {
                Ok(Amount(v))
            }
        }
        d.deserialize_any(V)
    }
}

impl From<u64> for Amount {
    fn from(v: u64) -> Self {
        Amount(v)
    }
}

/// For an [`Amount`] that monero-lws writes as a JSON number rather than a
/// string (`per_byte_fee`, `fee_mask`, an output's `global_index`), though
/// the community spec says string: written as a number, read as either.
pub mod as_number {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Amount, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(v.0)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Amount, D::Error> {
        Amount::deserialize(d)
    }
}

/// Fixed-size binary, as lowercase hex on the wire. Reading accepts either case.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hex<const N: usize>(pub [u8; N]);

/// A 32-byte key, hash or key image.
pub type Hex32 = Hex<32>;
/// An 8-byte short payment id.
pub type Hex8 = Hex<8>;

impl<const N: usize> fmt::Debug for Hex<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl<const N: usize> fmt::Display for Hex<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl<const N: usize> Default for Hex<N> {
    fn default() -> Self {
        Hex([0; N])
    }
}

impl<const N: usize> From<[u8; N]> for Hex<N> {
    fn from(v: [u8; N]) -> Self {
        Hex(v)
    }
}

impl<const N: usize> Serialize for Hex<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&hex::encode(self.0))
    }
}

/// A string, borrowed or not (a JSON string with an escape in it can't be
/// borrowed, and `&str`'s error for it would quote the whole string).
fn text<'de, D: Deserializer<'de>>(d: D) -> Result<Cow<'de, str>, D::Error> {
    struct V;
    impl<'de> de::Visitor<'de> for V {
        type Value = Cow<'de, str>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a hex string")
        }
        fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
            Ok(Cow::Borrowed(v))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Cow::Owned(v.to_owned()))
        }
        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(Cow::Owned(v))
        }
    }
    d.deserialize_str(V)
}

impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = text(d)?;
        let mut out = [0u8; N];
        if s.len() != 2 * N {
            return Err(de::Error::custom(format!(
                "expected {} hex characters, got {}",
                2 * N,
                s.len()
            )));
        }
        // Not the decoder's own error, which names the offending character.
        hex::decode_to_slice(s.as_bytes(), &mut out).map_err(|_| de::Error::custom("not hex"))?;
        Ok(Hex(out))
    }
}

/// Variable-length binary (a raw transaction, a packed RingCT blob), as hex.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct HexBytes(pub Vec<u8>);

impl fmt::Debug for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl Serialize for HexBytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = text(d)?;
        hex::decode(s.as_bytes())
            .map(HexBytes)
            .map_err(|_| de::Error::custom("not hex"))
    }
}

/// Defines a 32-byte secret: 64 hex characters on the wire, held on the
/// heap (so moving the value moves a pointer, not the secret) and wiped
/// when dropped. It is neither `Copy` nor `Clone`: a copy is made only on
/// purpose, from [`as_bytes`](PrivateViewKey::as_bytes). `==` compares in
/// constant time (`subtle`); `Debug` and `Display` print `<redacted>`.
macro_rules! secret32 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub struct $name(Box<[u8; 32]>);

        impl $name {
            /// The key in these bytes. The caller still holds (and should
            /// wipe) its own copy.
            pub fn from_bytes(bytes: &[u8; 32]) -> Self {
                let mut key = Self(Box::new([0; 32]));
                key.0.copy_from_slice(bytes);
                key
            }

            /// The key in 64 hex characters (either case); `None` for
            /// anything else.
            pub fn from_hex(s: &str) -> Option<Self> {
                let mut key = Self(Box::new([0; 32]));
                hex::decode_to_slice(s.as_bytes(), key.0.as_mut_slice()).ok()?;
                Some(key)
            }

            /// The key in a 32-byte slice; `None` for any other length.
            pub fn from_slice(bytes: &[u8]) -> Option<Self> {
                let bytes: &[u8; 32] = bytes.try_into().ok()?;
                Some(Self::from_bytes(bytes))
            }

            /// The key itself, to compute with. Any copy made from it is the
            /// caller's to wipe.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.0.as_mut().zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl ZeroizeOnDrop for $name {}

        impl ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.0.as_slice().ct_eq(other.0.as_slice())
            }
        }

        /// Constant time, whatever the bytes.
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).into()
            }
        }

        impl Eq for $name {}

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(REDACTED)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(REDACTED)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let mut text = Zeroizing::new([0u8; 64]);
                hex::encode_to_slice(self.0.as_slice(), text.as_mut_slice()).expect("64 bytes for 32");
                s.serialize_str(std::str::from_utf8(text.as_slice()).expect("hex is ASCII"))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = text(d)?;
                if s.len() != 64 {
                    return Err(de::Error::custom(format!("expected 64 hex characters, got {}", s.len())));
                }
                let mut key = Self(Box::new([0; 32]));
                // Not the decoder's own error, which names the offending character.
                hex::decode_to_slice(s.as_bytes(), key.0.as_mut_slice()).map_err(|_| de::Error::custom("not hex"))?;
                if let Cow::Owned(owned) = s {
                    drop(Zeroizing::new(owned));
                }
                Ok(key)
            }
        }
    };
}

secret32! {
    /// A private view key: the only credential a wallet login has.
    PrivateViewKey
}

secret32! {
    /// An admin API key, as presented in a request's `auth`.
    AdminKey
}

/// A moment, as `YYYY-MM-DDTHH:MM:SSZ` (what monero-lws writes). It is kept
/// as text: a client that wants the number can parse it, and a server builds
/// it with [`Timestamp::from_unix`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp(pub String);

impl Timestamp {
    /// ISO 8601 in UTC from seconds since the epoch.
    pub fn from_unix(secs: u64) -> Timestamp {
        let days = (secs / 86_400) as i64;
        let rem = secs % 86_400;
        let (y, m, d) = civil_from_days(days);
        Timestamp(format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        ))
    }
}

/// Howard Hinnant's days-to-civil, for the proleptic Gregorian calendar.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Every account-scoped request: the primary address and its private view
/// key. The view key is the only credential the protocol has. `Debug`
/// prints neither. Not `Clone`, as the key isn't.
#[derive(Serialize, Deserialize)]
pub struct Login {
    pub address: String,
    pub view_key: PrivateViewKey,
}

/// What a secret or an address prints as in `Debug`.
const REDACTED: &str = "<redacted>";

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Login")
            .field("address", &REDACTED)
            .field("view_key", &REDACTED)
            .finish()
    }
}

/// A subaddress index: major (account) and minor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressMeta {
    pub maj_i: u32,
    pub min_i: u32,
}

/// A candidate spend: an input whose ring holds one of the account's
/// outputs. Only the client, with the spend key, can tell a real spend from
/// a decoy use by recomputing the key image of the output at `out_index`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Spend {
    pub amount: Amount,
    pub key_image: Hex32,
    /// The transaction public key of the transaction holding the output
    /// spent (not of the spending transaction).
    pub tx_pub_key: Hex32,
    /// The index of the possibly spent output within its own transaction.
    pub out_index: u16,
    /// Ring size less one.
    pub mixin: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<AddressMeta>,
}

/// Proof that a transaction is in a block: enough for a client to recompute
/// the block's hash and the transaction's hash itself and check the block's
/// hash against any node, so a server that knows the view key cannot invent
/// an output the chain does not hold. An extension of the API; monero-lws
/// does not serve it, and a transaction still in the pool has none.
///
/// `block` is the block as Monero serialises it (header, miner transaction,
/// the hashes of the other transactions): its hash is the block hash, and
/// the transaction's hash must be among the hashes it lists (or be the miner
/// transaction's). For a transaction other than the miner's, `tx_prefix`,
/// `rct_base` and `prunable_hash` are the pruned transaction: its hash is
/// keccak(keccak(tx_prefix) ‖ keccak(rct_base) ‖ prunable_hash). For the
/// miner transaction they are absent, as the block holds it whole. The
/// prefix carries the transaction key (in extra) and the one-time keys; the
/// RingCT base carries the commitments and the fee.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub block: HexBytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_prefix: Option<HexBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rct_base: Option<HexBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prunable_hash: Option<Hex32>,
}

/// An output received, as `/get_unspent_outs` lists them. Fields are in
/// monero-lws's order, and typed as monero-lws writes them where that
/// differs from the community spec (`global_index` is a number).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output {
    pub amount: Amount,
    pub public_key: Hex32,
    pub index: u16,
    /// The output's global (RingCT) index, a JSON number as monero-lws
    /// writes it; read from a string too, as the spec has it.
    #[serde(with = "as_number")]
    pub global_index: Amount,
    /// What monero-lws puts here: the output's global index again, not a
    /// transaction index as the spec describes. Nothing should rely on it.
    pub tx_id: u64,
    pub tx_hash: Hex32,
    pub tx_prefix_hash: Hex32,
    pub tx_pub_key: Hex32,
    pub timestamp: Timestamp,
    pub height: u64,
    /// Key images of every candidate spend of this output. Left out when
    /// there are none, as monero-lws does.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spend_key_images: Vec<Hex32>,
    /// 96 bytes, absent for a non-RingCT output. For any other output: its
    /// commitment, then its mask and its amount (as a 32-byte scalar) each
    /// encrypted the original (pre-Bulletproofs2, `ecdhEncode` v1) way,
    /// `mask + H_s(s)` and `amount + H_s(H_s(s))` where
    /// `s = H_s(8·a·R ‖ index)`. For a coinbase output, as monero-lws and
    /// the spec have it: 32 zero bytes (not the commitment), the identity
    /// mask (the scalar 1), then 32 zero bytes (the amount is `amount`); a
    /// client recognises a coinbase output by that mask and computes its
    /// commitment, `G + amount·H`, itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rct: Option<HexBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<AddressMeta>,
}

/// An output received, as monero-lws lists them on each transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceivedOutput {
    pub amount: Amount,
    pub public_key: Hex32,
    pub index: u16,
    pub global_index: u64,
    pub tx_pub_key: Hex32,
    /// The unencrypted RingCT mask. Absent for a non-RingCT output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rct: Option<Hex32>,
    /// The output's Pedersen commitment as it is on the chain (the
    /// transaction's RingCT base `outPk`), so a client can check that
    /// `mask·G + amount·H` is what the chain holds and not trust the
    /// server's `amount` and `rct`. Absent for a non-RingCT output, and
    /// from servers that do not serve it (monero-lws).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<Hex32>,
    pub recipient: AddressMeta,
}

/// A transaction that touched the account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub id: u64,
    pub hash: Hex32,
    /// Absent while in the mempool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,
    pub total_received: Amount,
    /// The sum of the candidate spends' amounts.
    pub total_sent: Amount,
    /// The fee the transaction paid, as monero-lws serves it: `"0"` for a
    /// coinbase transaction. Absent only from servers that do not serve it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee: Option<Amount>,
    pub unlock_time: u64,
    /// Absent while in the mempool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    pub spent_outputs: Vec<Spend>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receives: Vec<ReceivedOutput>,
    /// 8-byte (decrypted) or 32-byte payment id, as hex. Absent if none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_id: Option<HexBytes>,
    pub coinbase: bool,
    pub mempool: bool,
    pub mixin: u32,
    /// Where the transaction is in the chain, for a client to check. Absent
    /// in the pool and from servers that do not serve it; monokulo-lws also
    /// leaves it out for a transaction that only (maybe) spends, and for one
    /// it scanned before it kept proofs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

/// Fiat rates, as the spec lists them. Omitted fields are unavailable.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct Rates {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eur: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gbp: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub btc: Option<f64>,
}

/// `/get_address_info` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressInfo {
    pub locked_funds: Amount,
    pub total_received: Amount,
    pub total_sent: Amount,
    pub scanned_height: u64,
    pub scanned_block_height: u64,
    pub start_height: u64,
    pub transaction_height: u64,
    pub blockchain_height: u64,
    pub spent_outputs: Vec<Spend>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookahead: Option<AddressMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rates: Option<Rates>,
}

/// `/get_address_txs` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressTxs {
    pub total_received: Amount,
    pub scanned_height: u64,
    pub scanned_block_height: u64,
    pub start_height: u64,
    pub transaction_height: u64,
    pub blockchain_height: u64,
    pub transactions: Vec<Transaction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookahead: Option<AddressMeta>,
}

/// `/get_unspent_outs` request.
#[derive(Debug, Serialize, Deserialize)]
pub struct UnspentOutsRequest {
    #[serde(flatten)]
    pub login: Login,
    /// The amount about to be sent. The answer is every listed output all
    /// the same, not a selection reaching it; it only makes the request
    /// fail (HTTP 400) when the listed outputs add up to less.
    #[serde(default)]
    pub amount: Amount,
    /// Outputs whose transaction had a smaller mixin (ring size less one)
    /// than this are left out. A coinbase transaction has none (mixin 0),
    /// so any mixin above 0 leaves coinbase outputs out, as in monero-lws.
    #[serde(default)]
    pub mixin: u32,
    /// Ignore `dust_threshold` and list outputs of every amount.
    #[serde(default)]
    pub use_dust: bool,
    /// Outputs of a smaller amount are left out (unless `use_dust`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dust_threshold: Option<Amount>,
}

/// `/get_unspent_outs` response, as monero-lws writes it: the two fee
/// fields are JSON numbers (the spec says strings; reading takes both),
/// `outputs` is left out when empty, and `fees` is always there.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnspentOuts {
    /// The node's `get_fee_estimate` `fee` (with 10 grace blocks): the
    /// per-byte fee of the lowest priority.
    #[serde(with = "as_number")]
    pub per_byte_fee: Amount,
    /// The node's fee quantization mask; a fee is rounded up to a multiple.
    #[serde(with = "as_number")]
    pub fee_mask: Amount,
    /// The sum of the listed outputs.
    pub amount: Amount,
    /// monero-lws's count of lookahead failures; left out when 0, which is
    /// all this server sends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookahead_fail: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<Output>,
    /// The node's per-byte fees for the four priorities, lowest first
    /// (`get_fee_estimate` `fees`). Empty from a node too old to send them.
    #[serde(default)]
    pub fees: Vec<u64>,
}

/// `/get_random_outs` request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RandomOutsRequest {
    /// Ring members wanted for each ring, 0 to 20. The spec calls it the
    /// mixin, but every ring comes back with exactly this many, none of
    /// them the real output: a client making rings of 16 asks for 16 and
    /// drops a member that happens to be the output it spends (or the
    /// last one), as wallet2-derived clients do.
    pub count: u32,
    /// One entry per ring, at most 150; `"0"` for RingCT, the only amount
    /// this server answers. Duplicates are answered each.
    pub amounts: Vec<Amount>,
}

/// One possible ring member.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RandomOutput {
    pub global_index: Amount,
    pub public_key: Hex32,
    /// 96 bytes, as monero-lws sends it: the output's commitment as the
    /// node gave it (`get_outs` `mask`), then 64 zero bytes. Only the first
    /// 32 bytes mean anything.
    pub rct: HexBytes,
}

/// Ring members for one requested amount, sorted by global index.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RandomOutputs {
    pub amount: Amount,
    #[serde(default)]
    pub outputs: Vec<RandomOutput>,
}

/// `/get_random_outs` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RandomOuts {
    pub amount_outs: Vec<RandomOutputs>,
}

/// `/login` request.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    #[serde(flatten)]
    pub login: Login,
    #[serde(default)]
    pub create_account: bool,
    #[serde(default)]
    pub generated_locally: bool,
}

/// `/login` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub new_address: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_locally: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookahead: Option<AddressMeta>,
}

/// `/import_wallet_request` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImportResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_id: Option<Hex8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_fee: Option<Amount>,
    pub new_request: bool,
    pub request_fulfilled: bool,
    pub status: String,
}

/// `/submit_raw_tx` request: the transaction as the daemon's binary format.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitRequest {
    pub tx: HexBytes,
}

/// `/submit_raw_tx` response, as monero-lws writes it:
///
/// - relayed: HTTP 200, `{"status":"OK"}`;
/// - accepted but not relayed: HTTP 200,
///   `{"status":"OK","reason":"Not relayed","not_relayed":true}`;
/// - refused by the node: HTTP 422, `{"status":"Failed","reason":"..."}`,
///   the reason in monerod's words (`"double spend and fee too low"`).
///
/// A transaction that doesn't parse is HTTP 400 before the node sees it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitResponse {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_relayed: Option<bool>,
}

/// `/get_version` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Version {
    pub server_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_git_commit_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_commit_date: Option<String>,
    pub monero_version_full: String,
    pub blockchain_height: u64,
    pub api: u32,
    pub max_subaddresses: u32,
    /// `"main"`, `"stage"` or `"test"`.
    pub network: String,
    pub testnet: bool,
}

/// Minor index ranges, inclusive at both ends, under one major index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubaddrRanges {
    /// The major index.
    pub key: u32,
    /// `[low, high]` pairs of minor indices.
    pub value: Vec<[u32; 2]>,
}

/// `/get_subaddrs` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subaddrs {
    pub all_subaddrs: Vec<SubaddrRanges>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_subaddrs: Option<u64>,
}

/// `/upsert_subaddrs` request.
#[derive(Debug, Serialize, Deserialize)]
pub struct UpsertSubaddrsRequest {
    #[serde(flatten)]
    pub login: Login,
    pub subaddrs: Vec<SubaddrRanges>,
    #[serde(default)]
    pub get_all: bool,
}

/// `/provision_subaddrs` request: hand out the next minors.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProvisionSubaddrsRequest {
    #[serde(flatten)]
    pub login: Login,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maj_i: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_i: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n_maj: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n_min: Option<u32>,
    #[serde(default)]
    pub get_all: bool,
}

/// `/upsert_subaddrs` and `/provision_subaddrs` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewSubaddrs {
    pub new_subaddrs: Vec<SubaddrRanges>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all_subaddrs: Option<Vec<SubaddrRanges>>,
}

/// Admin API: every request is `{"auth": key, "params": {...}}`.
pub mod admin {
    use super::*;

    /// `Debug` leaves out the key.
    #[derive(Serialize, Deserialize)]
    #[serde(bound(deserialize = "P: Deserialize<'de> + Default"))]
    pub struct Request<P> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub auth: Option<AdminKey>,
        #[serde(default)]
        pub params: P,
    }

    impl<P: fmt::Debug> fmt::Debug for Request<P> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("Request")
                .field("auth", &self.auth.as_ref().map(|_| REDACTED))
                .field("params", &self.params)
                .finish()
        }
    }

    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct Empty {}

    /// `Debug` prints neither the address nor the key.
    #[derive(Serialize, Deserialize)]
    pub struct AddAccount {
        pub address: String,
        pub key: PrivateViewKey,
    }

    impl fmt::Debug for AddAccount {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("AddAccount")
                .field("address", &REDACTED)
                .field("key", &REDACTED)
                .finish()
        }
    }

    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct Addresses {
        pub addresses: Vec<String>,
    }

    /// What a pending request asks for: a new account, or an import (a scan
    /// from block 0) of an existing one. `"create"` or `"import"` on the wire;
    /// anything else fails to parse.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum RequestKind {
        Create,
        Import,
    }

    impl RequestKind {
        pub fn as_str(self) -> &'static str {
            match self {
                RequestKind::Create => "create",
                RequestKind::Import => "import",
            }
        }

        pub fn parse(s: &str) -> Option<RequestKind> {
            match s {
                "create" => Some(RequestKind::Create),
                "import" => Some(RequestKind::Import),
                _ => None,
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Requests {
        #[serde(rename = "type")]
        pub kind: RequestKind,
        pub addresses: Vec<String>,
    }

    /// `"active"`, `"inactive"` or `"hidden"`.
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct ModifyStatus {
        pub status: String,
        pub addresses: Vec<String>,
    }

    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct Rescan {
        pub height: u64,
        pub addresses: Vec<String>,
    }

    /// The keys of a primary address, to check that they make one on this
    /// network. `Debug` leaves out the view key (as [`PrivateViewKey`] does).
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Validate {
        pub spend_public_hex: Hex32,
        pub view_public_hex: Hex32,
        pub view_key_hex: PrivateViewKey,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct AccountRow {
        pub address: String,
        pub scan_height: u64,
        pub access_time: u64,
    }

    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct Accounts {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub active: Vec<AccountRow>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub inactive: Vec<AccountRow>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub hidden: Vec<AccountRow>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct RequestRow {
        pub address: String,
        pub start_height: u64,
    }

    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct PendingRequests {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub create: Vec<RequestRow>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub import: Vec<RequestRow>,
    }

    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct Updated {
        pub updated: Vec<String>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_are_strings_but_read_numbers() {
        assert_eq!(
            serde_json::to_string(&Amount(u64::MAX)).unwrap(),
            "\"18446744073709551615\""
        );
        assert_eq!(serde_json::from_str::<Amount>("\"12\"").unwrap(), Amount(12));
        assert_eq!(serde_json::from_str::<Amount>("12").unwrap(), Amount(12));
        assert!(serde_json::from_str::<Amount>("\"-1\"").is_err());
    }

    #[test]
    fn hex_round_trips_and_checks_length() {
        let h: Hex32 = Hex([7; 32]);
        let s = serde_json::to_string(&h).unwrap();
        assert_eq!(s.len(), 66);
        assert_eq!(serde_json::from_str::<Hex32>(&s).unwrap(), h);
        assert!(serde_json::from_str::<Hex32>("\"0707\"").is_err());
        assert!(serde_json::from_str::<Hex32>(&s.to_uppercase()).is_ok());
    }

    #[test]
    fn debug_hides_keys_and_addresses() {
        let key = [0xcd; 32];
        let hex_key = hex::encode(key);
        let login = || Login {
            address: "5SecretAddress".into(),
            view_key: PrivateViewKey::from_bytes(&key),
        };
        let printed = format!(
            "{:?} {:?}",
            login(),
            UnspentOutsRequest {
                login: login(),
                amount: Amount(1),
                mixin: 15,
                use_dust: false,
                dust_threshold: None,
            }
        );
        assert!(!printed.contains("5SecretAddress"), "{printed}");
        assert!(!printed.contains(&hex_key), "{printed}");
        let add = admin::AddAccount {
            address: "5SecretAddress".into(),
            key: PrivateViewKey::from_bytes(&key),
        };
        let req = admin::Request {
            auth: Some(AdminKey::from_bytes(&key)),
            params: add,
        };
        let validate = admin::Validate {
            spend_public_hex: Hex([1; 32]),
            view_public_hex: Hex([2; 32]),
            view_key_hex: PrivateViewKey::from_bytes(&key),
        };
        let printed = format!("{req:?} {req:#?} {validate:?}");
        assert!(!printed.contains("5SecretAddress"), "{printed}");
        assert!(!printed.contains(&hex_key), "{printed}");
        assert!(!printed.contains("205"), "{printed}");
    }

    #[test]
    fn secret_keys_print_redacted_and_compare_in_constant_time() {
        let key = PrivateViewKey::from_bytes(&[0xab; 32]);
        assert_eq!(format!("{key:?}"), "<redacted>");
        assert_eq!(format!("{key}"), "<redacted>");
        assert_eq!(format!("{:?}", AdminKey::from_bytes(&[0xab; 32])), "<redacted>");
        let same = PrivateViewKey::from_bytes(&[0xab; 32]);
        let mut other = [0xab; 32];
        other[31] ^= 1;
        let other = PrivateViewKey::from_bytes(&other);
        assert!(bool::from(key.ct_eq(&same)) && key == same);
        assert!(!bool::from(key.ct_eq(&other)) && key != other);
        assert!(PrivateViewKey::from_slice(&[0xab; 31]).is_none());
        assert!(PrivateViewKey::from_slice(&[0xab; 32]).unwrap() == key);
    }

    #[test]
    fn secret_keys_read_and_write_hex() {
        let json = format!("\"{}\"", "ab".repeat(32));
        let key: PrivateViewKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key.as_bytes(), &[0xab; 32]);
        assert_eq!(serde_json::to_string(&key).unwrap(), json);
        assert!(serde_json::from_str::<PrivateViewKey>(&json.to_uppercase()).is_ok());
        for bad in [
            "\"abab\"",
            "5",
            &format!("\"{}zz\"", "ab".repeat(31)),
            &format!("\"{}00\"", "ab".repeat(32)),
        ] {
            assert!(serde_json::from_str::<PrivateViewKey>(bad).is_err(), "{bad}");
            assert!(serde_json::from_str::<AdminKey>(bad).is_err(), "{bad}");
        }
        let mut key = key;
        key.zeroize();
        assert_eq!(key.as_bytes(), &[0; 32]);
    }

    /// The secret key types are neither `Copy` nor `Clone`: if either were,
    /// `<T as NotIf<_>>::check` would be ambiguous (two impls would fit) and
    /// this would not compile.
    #[test]
    fn secret_keys_are_neither_copy_nor_clone() {
        trait NotCopy<A> {
            fn check() {}
        }
        impl<T> NotCopy<()> for T {}
        impl<T: Copy> NotCopy<u8> for T {}
        trait NotClone<A> {
            fn check() {}
        }
        impl<T> NotClone<()> for T {}
        impl<T: Clone> NotClone<u8> for T {}
        <PrivateViewKey as NotCopy<_>>::check();
        <PrivateViewKey as NotClone<_>>::check();
        <AdminKey as NotCopy<_>>::check();
        <AdminKey as NotClone<_>>::check();
        <Login as NotClone<_>>::check();
    }

    #[test]
    fn errors_never_quote_the_value() {
        let key = "cd".repeat(31) + "zz";
        let e = serde_json::from_str::<Hex32>(&format!("\"{key}\""))
            .unwrap_err()
            .to_string();
        assert!(!e.contains("cdcd"), "{e}");
        assert!(!e.contains('z'), "{e}");
        // An escaped string can't be borrowed: still read, still not quoted.
        let escaped = format!("\"\\u0063{}\"", &"cd".repeat(32)[1..]);
        assert_eq!(serde_json::from_str::<Hex32>(&escaped).unwrap(), Hex([0xcd; 32]));
        let e = serde_json::from_str::<Login>(&format!(
            "{{\"address\":\"5Secret\",\"view_key\":\"\\u0063{}\"}}",
            "d".repeat(64)
        ))
        .unwrap_err()
        .to_string();
        assert!(!e.contains("ddd"), "{e}");
        let e = serde_json::from_str::<Amount>("\"12x5Secret\"")
            .unwrap_err()
            .to_string();
        assert!(!e.contains("5Secret"), "{e}");
    }

    #[test]
    fn request_kinds_are_create_or_import() {
        use admin::{RequestKind, Requests};
        let r: Requests = serde_json::from_str(r#"{"type":"import","addresses":["A"]}"#).unwrap();
        assert_eq!(r.kind, RequestKind::Import);
        assert!(serde_json::from_str::<Requests>(r#"{"type":"imports","addresses":[]}"#).is_err());
        for kind in [RequestKind::Create, RequestKind::Import] {
            assert_eq!(RequestKind::parse(kind.as_str()), Some(kind));
            assert_eq!(serde_json::to_string(&kind).unwrap(), format!("\"{}\"", kind.as_str()));
        }
    }

    #[test]
    fn timestamps() {
        assert_eq!(Timestamp::from_unix(0).0, "1970-01-01T00:00:00Z");
        assert_eq!(Timestamp::from_unix(1_687_301_600).0, "2023-06-20T22:53:20Z");
        assert_eq!(Timestamp::from_unix(951_782_400).0, "2000-02-29T00:00:00Z");
    }

    #[test]
    fn login_flattens_into_requests() {
        let r: UnspentOutsRequest = serde_json::from_str(
            r#"{"address":"4abc","view_key":"0000000000000000000000000000000000000000000000000000000000000001","amount":"5","mixin":15,"use_dust":true}"#,
        )
        .unwrap();
        assert_eq!(r.login.address, "4abc");
        assert_eq!(r.amount, Amount(5));
        assert!(r.use_dust);
        assert!(r.dust_threshold.is_none());
    }

    #[test]
    fn mempool_transaction_leaves_out_height_and_time() {
        let t = Transaction {
            proof: None,
            fee: None,
            id: 1,
            hash: Hex([1; 32]),
            timestamp: None,
            total_received: Amount(3),
            total_sent: Amount(0),
            unlock_time: 0,
            height: None,
            spent_outputs: vec![],
            receives: vec![],
            payment_id: None,
            coinbase: false,
            mempool: true,
            mixin: 15,
        };
        let s = serde_json::to_string(&t).unwrap();
        assert!(!s.contains("height"));
        assert!(!s.contains("timestamp"));
        assert!(!s.contains("receives"));
        assert!(s.contains("\"mempool\":true"));
    }

    /// Parses `json` as `T` and writes it back: the same bytes.
    fn round_trips<T: Serialize + for<'de> Deserialize<'de>>(json: &str) -> T {
        let value: T = serde_json::from_str(json).unwrap();
        assert_eq!(serde_json::to_string(&value).unwrap(), json);
        value
    }

    // The responses below are monero-lws's own, from its REST tests
    // (tests/unit/rest.test.cpp), with its random keys and hashes filled in.

    #[test]
    fn unspent_outs_as_monero_lws_writes_them() {
        // An account with nothing: no `outputs`, the fees as numbers.
        let empty: UnspentOuts = round_trips(r#"{"per_byte_fee":39,"fee_mask":1000,"amount":"0","fees":[40,41]}"#);
        assert!(empty.outputs.is_empty());
        assert_eq!((empty.per_byte_fee, empty.fee_mask), (Amount(39), Amount(1000)));

        let key = "11".repeat(32);
        let hash = "22".repeat(32);
        let prefix = "33".repeat(32);
        let tx_pub = "44".repeat(32);
        let image = "55".repeat(32);
        let rct = "66".repeat(96);
        let one = format!(
            concat!(
                r#"{{"per_byte_fee":39,"fee_mask":1000,"amount":"40000","outputs":["#,
                r#"{{"amount":"40000","public_key":"{key}","index":2,"global_index":35,"tx_id":35,"#,
                r#""tx_hash":"{hash}","tx_prefix_hash":"{prefix}","tx_pub_key":"{tx_pub}","#,
                r#""timestamp":"1970-01-01T01:56:40Z","height":4000,"spend_key_images":["{image}"],"#,
                r#""rct":"{rct}","recipient":{{"maj_i":2,"min_i":66}}}}"#,
                r#"],"fees":[40,41]}}"#
            ),
            key = key,
            hash = hash,
            prefix = prefix,
            tx_pub = tx_pub,
            image = image,
            rct = rct
        );
        let outs: UnspentOuts = round_trips(&one);
        let o = &outs.outputs[0];
        assert_eq!((o.global_index, o.tx_id, o.index, o.height), (Amount(35), 35, 2, 4000));
        assert_eq!(o.rct.as_ref().unwrap().0.len(), 96);
        assert_eq!(o.recipient, Some(AddressMeta { maj_i: 2, min_i: 66 }));
        // An output without candidate spends: no `spend_key_images`.
        let unspent = one.replace(&format!(r#""spend_key_images":["{image}"],"#), "");
        let outs: UnspentOuts = round_trips(&unspent);
        assert!(outs.outputs[0].spend_key_images.is_empty());

        // The spec's shape (strings for the fees and the index) reads too.
        let spec = r#"{"per_byte_fee":"39","fee_mask":"1000","amount":"0","outputs":[]}"#;
        let read: UnspentOuts = serde_json::from_str(spec).unwrap();
        assert_eq!(read.per_byte_fee, Amount(39));
        assert!(read.fees.is_empty());
    }

    #[test]
    fn submit_answers_as_monero_lws_writes_them() {
        let ok: SubmitResponse = round_trips(r#"{"status":"OK"}"#);
        assert!(ok.reason.is_none() && ok.not_relayed.is_none());
        let kept: SubmitResponse = round_trips(r#"{"status":"OK","reason":"Not relayed","not_relayed":true}"#);
        assert_eq!(kept.not_relayed, Some(true));
        let failed: SubmitResponse = round_trips(r#"{"status":"Failed","reason":"double spend and fee too low"}"#);
        assert_eq!(failed.reason.as_deref(), Some("double spend and fee too low"));
    }

    #[test]
    fn random_outs_as_monero_lws_writes_them() {
        // monero-lws's writer: `global_index` and `amount` as strings, `rct`
        // the commitment and 64 zero bytes.
        let rct = format!("{}{}", "77".repeat(32), "00".repeat(64));
        let json = format!(
            r#"{{"amount_outs":[{{"amount":"0","outputs":[{{"global_index":"123456789","public_key":"{}","rct":"{rct}"}}]}}]}}"#,
            "88".repeat(32)
        );
        let outs: RandomOuts = round_trips(&json);
        assert_eq!(outs.amount_outs[0].outputs[0].global_index, Amount(123_456_789));
        let request: RandomOutsRequest = round_trips(r#"{"count":16,"amounts":["0","0"]}"#);
        assert_eq!(request.amounts, vec![Amount(0), Amount(0)]);
    }
}
