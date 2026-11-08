//! `Debug` for the structs that hold a view key or an address, leaving both
//! out, so a `{:?}` anywhere (a log line, a panic, a test failure) can't
//! print them. The account's row id says which account it is.

use std::fmt;

use crate::crypto::Checked;
use crate::db::{Account, NewAccount};

/// What an address or a key prints as.
pub const REDACTED: &str = "<redacted>";

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Account")
            .field("id", &self.id)
            .field("address", &REDACTED)
            .field("view_key", &REDACTED)
            .field("status", &self.status)
            .field("start_height", &self.start_height)
            .field("scan_height", &self.scan_height)
            .field("access_time", &self.access_time)
            .field("generated_locally", &self.generated_locally)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for NewAccount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("NewAccount")
            .field("address", &REDACTED)
            .field("view_key", &REDACTED)
            .field("start_height", &self.start_height)
            .field("generated_locally", &self.generated_locally)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Checked {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Checked")
            .field("address", &REDACTED)
            .field("view_key", &REDACTED)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Status;

    #[test]
    fn debug_leaves_out_keys_and_addresses() {
        let key = [0xab; 32];
        let address = "5AddressThatMustNotBePrinted".to_string();
        let account = Account {
            id: 7,
            address: address.clone(),
            view_key: key,
            spend_pub: [1; 32],
            view_pub: [2; 32],
            status: Status::Active,
            start_height: 1,
            scan_height: 2,
            access_time: 3,
            generated_locally: false,
        };
        let new = NewAccount {
            address: address.clone(),
            view_key: key,
            spend_pub: [1; 32],
            view_pub: [2; 32],
            start_height: 1,
            generated_locally: true,
        };
        let checked = Checked {
            address: address.clone(),
            spend_pub: [1; 32],
            view_pub: [2; 32],
            view_key: key,
        };
        let hex_key = hex::encode(key);
        for printed in [
            format!("{account:?}"),
            format!("{new:?}"),
            format!("{checked:?}"),
            format!("{account:#?}"),
        ] {
            assert!(!printed.contains(&address), "{printed}");
            assert!(!printed.contains(&hex_key), "{printed}");
            assert!(!printed.contains("171, 171"), "{printed}");
        }
    }
}
