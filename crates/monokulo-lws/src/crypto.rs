//! The few derivations the server does itself: checking that a view key
//! fits an address, telling which transaction key derived an output, and
//! packing an output's RingCT parts the way old clients expect.

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, edwards::EdwardsPoint, scalar::Scalar as DScalar};
use lws_api::PrivateViewKey;
use monero_wallet::{
    ViewPair,
    address::{AddressType, MoneroAddress, Network},
    ed25519::{Commitment, CompressedPoint, Scalar},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::db::NewAccount;
use crate::error::{Error, Result, bad};

/// A login checked: the address parses on this network, is a primary
/// address, and the view key is its view key. [`check_login`] is the only
/// way to get one (the fields are private and there is no other
/// constructor), so holding one is proof the check was made. `Debug` leaves
/// the key and address out (`crate::redact`); the key wipes itself.
pub struct Checked {
    address: String,
    spend_pub: [u8; 32],
    view_pub: [u8; 32],
    view_key: PrivateViewKey,
}

impl Checked {
    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn view_key(&self) -> &PrivateViewKey {
        &self.view_key
    }

    /// A new account (or request) for this login.
    pub fn into_new_account(self, start_height: u64, generated_locally: bool) -> NewAccount {
        NewAccount {
            address: self.address,
            view_key: self.view_key,
            spend_pub: self.spend_pub,
            view_pub: self.view_pub,
            start_height,
            generated_locally,
        }
    }

    /// A `Checked` without the check, for tests that need one by hand.
    #[cfg(test)]
    pub fn unchecked(address: String, spend_pub: [u8; 32], view_pub: [u8; 32], view_key: PrivateViewKey) -> Checked {
        Checked {
            address,
            spend_pub,
            view_pub,
            view_key,
        }
    }
}

/// Checks that `view_key` is the view key of `address`, a primary address on
/// `network`. The key is taken, not borrowed: the `Checked` keeps it, and no
/// copy is left behind.
pub fn check_login(network: Network, address: &str, view_key: PrivateViewKey) -> Result<Checked> {
    let parsed = MoneroAddress::from_str(network, address).map_err(|e| bad(format!("address: {e}")))?;
    if !matches!(parsed.kind(), AddressType::Legacy) {
        return Err(bad("only a primary address can log in"));
    }
    let scalar = view_scalar(&view_key)?;
    let derived = Point_mul_base(&scalar);
    let view_pub = parsed.view().compress().to_bytes();
    if derived.ct_eq(&view_pub).unwrap_u8() == 0 {
        return Err(Error::Forbidden);
    }
    Ok(Checked {
        address: parsed.to_string(),
        spend_pub: parsed.spend().compress().to_bytes(),
        view_pub,
        view_key,
    })
}

/// The view key as a scalar, refused unless canonical.
fn view_scalar(view_key: &PrivateViewKey) -> Result<Zeroizing<Scalar>> {
    Scalar::read(&mut view_key.as_bytes().as_slice())
        .map(Zeroizing::new)
        .map_err(|_| bad("the view key isn't a canonical scalar"))
}

#[allow(non_snake_case)]
fn Point_mul_base(scalar: &Scalar) -> [u8; 32] {
    let s: Zeroizing<DScalar> = Zeroizing::new((*scalar).into());
    (&*s * ED25519_BASEPOINT_TABLE).compress().to_bytes()
}

pub fn view_pair(spend_pub: &[u8; 32], view_key: &PrivateViewKey) -> Result<ViewPair> {
    let spend = CompressedPoint::from(*spend_pub)
        .decompress()
        .ok_or_else(|| bad("the spend key isn't a point"))?;
    ViewPair::new(spend, view_scalar(view_key)?).map_err(|e| bad(format!("view pair: {e}")))
}

pub fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "main",
        Network::Stagenet => "stage",
        Network::Testnet => "test",
    }
}

pub fn network_from_daemon(nettype: &str) -> Option<Network> {
    Some(match nettype {
        "mainnet" => Network::Mainnet,
        "stagenet" => Network::Stagenet,
        "testnet" => Network::Testnet,
        _ => return None,
    })
}

fn hash_to_scalar(data: &[u8]) -> DScalar {
    Scalar::hash(data).into()
}

fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// The view key as a curve25519 scalar, wiped when dropped.
fn view_dscalar(view_key: &PrivateViewKey) -> Zeroizing<DScalar> {
    Zeroizing::new(DScalar::from_bytes_mod_order(*view_key.as_bytes()))
}

/// `H_s(8·a·R ‖ i)`: the scalar an output's one-time key and amount are
/// derived from. `None` if `R` isn't a point. It is as secret as the view
/// key for that output, so it is wiped when dropped, as is everything on
/// the way to it.
pub fn shared_scalar(view_key: &PrivateViewKey, tx_pub_key: &[u8; 32], index: u64) -> Option<Zeroizing<DScalar>> {
    let r: EdwardsPoint = CompressedPoint::from(*tx_pub_key).decompress()?.into();
    let derivation = Zeroizing::new((*view_dscalar(view_key) * r).mul_by_cofactor());
    let mut data = Zeroizing::new(Vec::with_capacity(32 + 10));
    data.extend_from_slice(Zeroizing::new(derivation.compress().to_bytes()).as_slice());
    varint(index, &mut data);
    Some(Zeroizing::new(hash_to_scalar(&data)))
}

/// `H_s("SubAddr\0" ‖ a ‖ major ‖ minor)`: what a subaddress's spend key
/// adds to the primary one. Zero for the primary address itself. The hash
/// input holds the view key and is wiped.
pub fn subaddress_derivation(view_key: &PrivateViewKey, major: u32, minor: u32) -> DScalar {
    if major == 0 && minor == 0 {
        return DScalar::ZERO;
    }
    let mut data = Zeroizing::new(Vec::with_capacity(8 + 32 + 8));
    data.extend_from_slice(b"SubAddr\0");
    data.extend_from_slice(view_key.as_bytes());
    data.extend_from_slice(&major.to_le_bytes());
    data.extend_from_slice(&minor.to_le_bytes());
    hash_to_scalar(&data)
}

/// Which of the transaction's public keys derived an output whose key
/// offset the scanner found: the main one, or the additional key at the
/// output's index.
pub fn derived_by(
    view_key: &PrivateViewKey,
    index: u64,
    key_offset: &DScalar,
    (major, minor): (u32, u32),
    main: &[u8; 32],
    additional: Option<&[u8; 32]>,
) -> [u8; 32] {
    let sub = subaddress_derivation(view_key, major, minor);
    let fits = |r: &[u8; 32]| {
        shared_scalar(view_key, r, index)
            .map(|s| *s + sub == *key_offset)
            .unwrap_or(false)
    };
    match additional {
        Some(extra) if fits(extra) && !fits(main) => *extra,
        _ => *main,
    }
}

/// `mask·G + amount·H`, compressed: the Pedersen commitment an output's mask
/// and amount open.
pub fn commit(mask: &[u8; 32], amount: u64) -> [u8; 32] {
    Commitment::new(Scalar::from(DScalar::from_bytes_mod_order(*mask)), amount)
        .commit()
        .compress()
        .to_bytes()
}

/// The 96-byte `rct` blob: the output's on-chain commitment, then the mask
/// and the amount encrypted the original way (`ecdhEncode`, non-compact),
/// which the client undoes with `H_s(shared)` and `H_s(H_s(shared))`.
pub fn legacy_rct(
    view_key: &PrivateViewKey,
    tx_pub_key: &[u8; 32],
    index: u64,
    commitment: &[u8; 32],
    mask: &[u8; 32],
    amount: u64,
) -> Option<[u8; 96]> {
    let shared = shared_scalar(view_key, tx_pub_key, index)?;
    let mask_scalar = DScalar::from_bytes_mod_order(*mask);
    let s1 = Zeroizing::new(hash_to_scalar(shared.as_bytes()));
    let s2 = Zeroizing::new(hash_to_scalar(s1.as_bytes()));
    let masked = mask_scalar + *s1;
    let amount_scalar = DScalar::from(amount) + *s2;
    let mut out = [0u8; 96];
    out[..32].copy_from_slice(commitment);
    out[32..64].copy_from_slice(masked.as_bytes());
    out[64..].copy_from_slice(amount_scalar.as_bytes());
    Some(out)
}

/// The blob for a RingCT coinbase output, byte for byte as monero-lws writes
/// it (and as the spec describes it): 32 zero bytes where the commitment
/// would be, the identity mask (`rct::identity()`, which is the scalar 1),
/// then 32 zero bytes for the amount. A client tells a coinbase output by
/// that mask, takes the amount from the output's `amount` and computes the
/// commitment, `G + amount·H`, itself.
pub fn coinbase_rct() -> [u8; 96] {
    let mut out = [0u8; 96];
    out[32..64].copy_from_slice(DScalar::ONE.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address_of(spend: u64, view: u64, network: Network) -> String {
        MoneroAddress::new(
            network,
            AddressType::Legacy,
            monero_wallet::ed25519::Point::from(&DScalar::from(spend) * ED25519_BASEPOINT_TABLE),
            monero_wallet::ed25519::Point::from(&DScalar::from(view) * ED25519_BASEPOINT_TABLE),
        )
        .to_string()
    }

    fn key(scalar: &DScalar) -> PrivateViewKey {
        PrivateViewKey::from_bytes(scalar.as_bytes())
    }

    #[test]
    fn login_needs_the_matching_view_key() {
        let address = address_of(7, 123_456, Network::Stagenet);
        let wrong = || key(&DScalar::from(1u64));
        match check_login(Network::Stagenet, &address, wrong()) {
            Err(Error::Forbidden) => {}
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            check_login(Network::Mainnet, &address, wrong()),
            Err(Error::BadRequest(_))
        ));
        let not_canonical = PrivateViewKey::from_bytes(&[0xff; 32]);
        assert!(matches!(
            check_login(Network::Stagenet, &address, not_canonical),
            Err(Error::BadRequest(_))
        ));
        assert!(matches!(
            check_login(Network::Stagenet, "not an address", wrong()),
            Err(Error::BadRequest(_))
        ));
    }

    #[test]
    fn a_fresh_key_logs_in_to_its_own_address() {
        let view = DScalar::from(123_456u64);
        let address = address_of(7, 123_456, Network::Stagenet);
        let checked = check_login(Network::Stagenet, &address, key(&view)).unwrap();
        assert_eq!(checked.address(), address);
        assert!(*checked.view_key() == key(&view));
        let new = checked.into_new_account(0, false);
        assert!(view_pair(&new.spend_pub, &new.view_key).is_ok());
    }

    #[test]
    fn legacy_rct_decrypts_back() {
        let view = DScalar::from(99u64);
        let r = DScalar::from(5u64);
        let tx_pub = (&r * ED25519_BASEPOINT_TABLE).compress().to_bytes();
        let mask = DScalar::from(31u64);
        let commitment = commit(mask.as_bytes(), 1_000_000);
        let packed = legacy_rct(&key(&view), &tx_pub, 2, &commitment, mask.as_bytes(), 1_000_000).unwrap();
        let shared = shared_scalar(&key(&view), &tx_pub, 2).unwrap();
        let s1 = hash_to_scalar(shared.as_bytes());
        let s2 = hash_to_scalar(s1.as_bytes());
        let masked = DScalar::from_bytes_mod_order(packed[32..64].try_into().unwrap());
        let amount = DScalar::from_bytes_mod_order(packed[64..].try_into().unwrap());
        assert_eq!(masked - s1, mask);
        assert_eq!(amount - s2, DScalar::from(1_000_000u64));
        let expected = Commitment::new(Scalar::from(mask), 1_000_000)
            .commit()
            .compress()
            .to_bytes();
        assert_eq!(&packed[..32], &expected);
    }

    #[test]
    fn subaddress_zero_is_nothing() {
        let one = PrivateViewKey::from_bytes(&[1; 32]);
        assert_eq!(subaddress_derivation(&one, 0, 0), DScalar::ZERO);
        assert_ne!(subaddress_derivation(&one, 0, 1), DScalar::ZERO);
    }
}

#[cfg(test)]
mod tools {
    //! `cargo test -p monokulo-lws fresh_stagenet_wallet -- --ignored --nocapture`
    //! prints a throwaway stagenet wallet to try the server with.
    use super::*;

    #[test]
    #[ignore = "a tool, not a test"]
    fn fresh_stagenet_wallet() {
        let mut rng = rand::rngs::OsRng;
        let spend: DScalar = Scalar::random(&mut rng).into();
        let view: DScalar = Scalar::hash(spend.as_bytes()).into();
        let spend_point = monero_wallet::ed25519::Point::from(&spend * ED25519_BASEPOINT_TABLE);
        let view_point = monero_wallet::ed25519::Point::from(&view * ED25519_BASEPOINT_TABLE);
        let address = MoneroAddress::new(Network::Stagenet, AddressType::Legacy, spend_point, view_point);
        println!("address   {address}");
        println!("spend key {}", hex::encode(spend.as_bytes()));
        println!("view key  {}", hex::encode(view.as_bytes()));
    }
}
