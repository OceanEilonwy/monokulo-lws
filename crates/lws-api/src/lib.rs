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
/// prints neither.
#[derive(Clone, Serialize, Deserialize)]
pub struct Login {
    pub address: String,
    pub view_key: Hex32,
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

/// An output received, as `/get_unspent_outs` lists them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output {
    pub tx_id: u64,
    pub amount: Amount,
    pub index: u16,
    pub global_index: Amount,
    /// 96 bytes: commitment, then the mask and the amount encrypted the
    /// original (non-compact) way under the shared secret, so a client
    /// decrypts them with the view key. Absent for a non-RingCT output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rct: Option<HexBytes>,
    pub tx_hash: Hex32,
    pub tx_prefix_hash: Hex32,
    pub public_key: Hex32,
    pub tx_pub_key: Hex32,
    /// Key images of every candidate spend of this output.
    pub spend_key_images: Vec<Hex32>,
    pub timestamp: Timestamp,
    pub height: u64,
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
    /// The fee the transaction paid, as monero-lws serves it. Absent from
    /// servers that do not serve it, and for a coinbase transaction.
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnspentOutsRequest {
    #[serde(flatten)]
    pub login: Login,
    /// The amount wanted; HTTP 400 if the account never received that much.
    #[serde(default)]
    pub amount: Amount,
    /// The least ring size an output's transaction may have had.
    #[serde(default)]
    pub mixin: u32,
    /// Return every output, dust included.
    #[serde(default)]
    pub use_dust: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dust_threshold: Option<Amount>,
}

/// `/get_unspent_outs` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnspentOuts {
    pub per_byte_fee: Amount,
    pub fee_mask: Amount,
    pub amount: Amount,
    pub outputs: Vec<Output>,
    /// Per-byte fees for the four priorities, lowest first (monero-lws).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fees: Vec<u64>,
}

/// `/get_random_outs` request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RandomOutsRequest {
    /// Ring members wanted per amount (the mixin level).
    pub count: u32,
    /// One entry per ring; `"0"` for RingCT. Duplicates are answered each.
    pub amounts: Vec<Amount>,
}

/// One possible ring member.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RandomOutput {
    pub global_index: Amount,
    pub public_key: Hex32,
    /// The commitment (32 bytes hex), optionally followed by 64 zero bytes
    /// for old clients.
    pub rct: HexBytes,
}

/// Ring members for one requested amount.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RandomOutputs {
    pub amount: Amount,
    pub outputs: Vec<RandomOutput>,
}

/// `/get_random_outs` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RandomOuts {
    pub amount_outs: Vec<RandomOutputs>,
}

/// `/login` request.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// `/submit_raw_tx` response.
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpsertSubaddrsRequest {
    #[serde(flatten)]
    pub login: Login,
    pub subaddrs: Vec<SubaddrRanges>,
    #[serde(default)]
    pub get_all: bool,
}

/// `/provision_subaddrs` request: hand out the next minors.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(bound(deserialize = "P: Deserialize<'de> + Default"))]
    pub struct Request<P> {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub auth: Option<Hex32>,
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
    #[derive(Clone, Default, Serialize, Deserialize)]
    pub struct AddAccount {
        pub address: String,
        pub key: Hex32,
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

    /// `"import"` or `"create"`.
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct Requests {
        #[serde(rename = "type")]
        pub kind: String,
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

    /// `Debug` leaves out the view key.
    #[derive(Clone, Default, Serialize, Deserialize)]
    pub struct Validate {
        pub spend_public_hex: String,
        pub view_public_hex: String,
        pub view_key_hex: String,
    }

    impl fmt::Debug for Validate {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("Validate")
                .field("spend_public_hex", &self.spend_public_hex)
                .field("view_public_hex", &self.view_public_hex)
                .field("view_key_hex", &REDACTED)
                .finish()
        }
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
        let key = Hex([0xcd; 32]);
        let login = Login {
            address: "5SecretAddress".into(),
            view_key: key,
        };
        let printed = format!(
            "{login:?} {:?}",
            UnspentOutsRequest {
                login: login.clone(),
                amount: Amount(1),
                mixin: 15,
                use_dust: false,
                dust_threshold: None,
            }
        );
        assert!(!printed.contains("5SecretAddress"), "{printed}");
        assert!(!printed.contains(&key.to_string()), "{printed}");
        let add = admin::AddAccount {
            address: "5SecretAddress".into(),
            key,
        };
        let req = admin::Request {
            auth: Some(key),
            params: add,
        };
        let printed = format!("{req:?}");
        assert!(!printed.contains("5SecretAddress"), "{printed}");
        assert!(!printed.contains(&key.to_string()), "{printed}");
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
}
