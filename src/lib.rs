// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

mod ffi;
pub mod pagekite;

pub use pagekite::*;

#[test]
fn sanity_check() {
    use pagekite::{PageKite, InitFlags, LOG_ALL};
    {
        let pk = PageKite::init(Some("kite_test"),
                                1,
                                1,
                                1,
                                None,
                                &[InitFlags::WithDefaults],
                                &LOG_ALL)
            .unwrap();
        pk.enable_fake_ping(true);
        pk.enable_http_forwarding_headers(true);
        pk.thread_start();
        assert!(pk.get_log().starts_with("t="));
    }
}
