//! A primary address, parsed once where it comes in (a request, the
//! command line, a database row) and passed around as this type, never as a
//! bare string: whatever holds an `Address` holds one that parsed, is a
//! primary address, and is on a known network.

use std::fmt;
use std::hash::{Hash, Hasher};

use monero_wallet::address::{AddressType, MoneroAddress, Network};
use monero_wallet::ed25519::Point;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use serde::{Serialize, Serializer};

use crate::error::{Result, bad};
use crate::redact::REDACTED;

/// A primary (not integrated, not sub-) address, in its canonical text,
/// with its two public keys. It parsed on the network it was parsed for
/// (or, from the database, on the one it names). `Debug` prints `<redacted>`
/// and there is no `Display`: the text is reached only on purpose, through
/// [`as_str`](Address::as_str). It is written as its text to JSON and to
/// the database.
#[derive(Clone, PartialEq, Eq)]
pub struct Address {
    text: String,
    spend_pub: [u8; 32],
    view_pub: [u8; 32],
}

impl Address {
    /// `s` as a primary address on `network`. The error never quotes `s`.
    pub fn parse(network: Network, s: &str) -> Result<Address> {
        let parsed = MoneroAddress::from_str(network, s).map_err(|e| bad(format!("address: {e}")))?;
        Address::from_parsed(parsed)
    }

    /// `s` as a primary address on whichever network it names: for an
    /// address read back from the database (written only once parsed), and
    /// the command line where no network is given.
    pub fn parse_any_network(s: &str) -> Result<Address> {
        let parsed = MoneroAddress::from_str_with_unchecked_network(s).map_err(|e| bad(format!("address: {e}")))?;
        Address::from_parsed(parsed)
    }

    /// The primary address of these keys on `network`.
    pub fn from_keys(network: Network, spend: Point, view: Point) -> Address {
        Address::from_parsed(MoneroAddress::new(network, AddressType::Legacy, spend, view)).expect("a primary address")
    }

    fn from_parsed(parsed: MoneroAddress) -> Result<Address> {
        if !matches!(parsed.kind(), AddressType::Legacy) {
            return Err(bad("only a primary address can log in"));
        }
        Ok(Address {
            text: parsed.to_string(),
            spend_pub: parsed.spend().compress().to_bytes(),
            view_pub: parsed.view().compress().to_bytes(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn spend_pub(&self) -> &[u8; 32] {
        &self.spend_pub
    }

    pub fn view_pub(&self) -> &[u8; 32] {
        &self.view_pub
    }
}

/// The text names the address (and its keys and network) whole.
impl Hash for Address {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.text.hash(state);
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Address").field(&REDACTED).finish()
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.text)
    }
}

impl ToSql for Address {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Borrowed(ValueRef::Text(self.text.as_bytes())))
    }
}

/// A stored address is parsed again: a row that isn't a primary address is
/// an error, not a string passed along.
impl FromSql for Address {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let text = value.as_str()?;
        Address::parse_any_network(text).map_err(|_| FromSqlError::Other("not a primary address".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::Wallet;

    #[test]
    fn only_primary_addresses_on_the_network_parse() {
        let address = Wallet::new(1).address();
        let text = address.as_str().to_owned();
        let again = Address::parse(Network::Stagenet, &text).unwrap();
        assert_eq!(again, address);
        assert!(Address::parse(Network::Mainnet, &text).is_err());
        assert!(Address::parse(Network::Stagenet, "not an address").is_err());
        assert_eq!(Address::parse_any_network(&text).unwrap(), address);
        let sub = MoneroAddress::new(
            Network::Stagenet,
            AddressType::Subaddress,
            Point::from(Wallet::new(1).spend_pub()),
            Point::from(Wallet::new(1).view_pub()),
        )
        .to_string();
        assert!(Address::parse(Network::Stagenet, &sub).is_err());
        let printed = format!("{address:?}");
        assert!(!printed.contains(&text[..12]), "{printed}");
    }

    #[test]
    fn a_stored_address_is_parsed_back() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let address = Wallet::new(2).address();
        let back: Address = db.query_row("SELECT ?1", [&address], |r| r.get(0)).unwrap();
        assert_eq!(back, address);
        let bad: rusqlite::Result<Address> = db.query_row("SELECT 'A'", [], |r| r.get(0));
        assert!(bad.is_err());
    }
}
