// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.


/// See the documentation at https://github.com/pagekite/libpagekite/blob/master/doc/API.md

use ffi::*;
use std::ffi::{CStr, CString};
use std::mem::transmute;
use std::{convert, ptr};
use std::time::Duration;
#[derive(Clone, Copy)]
pub enum InitFlags {
    WithDefaults = 0x8000,
    WithoutDefaults = 0x4000,
    WithSsl = 0x0001,
    WithIpv4 = 0x0002,
    WithIpv6 = 0x0004,
    WithServiceFrontends = 0x0008,
    WithoutServiceFrontends = 0x0010,
    WithDynamicFeList = 0x0020,
    WithFrontendSni = 0x0040,
    AsFrontendRelay = 0x0100,
    WithSyslog = 0x0200,
}

#[derive(Clone, Copy)]
pub enum VerbosityFlags {
    LogTunnelData = 0x000100,
    LogTunnelHeaders = 0x000200,
    LogTunnelConns = 0x000400,
    LogBeData = 0x001000,
    LogBeHeaders = 0x002000,
    LogBeConns = 0x004000,
    LogManagerError = 0x010000,
    LogManagerInfo = 0x020000,
    LogManagerDebug = 0x040000,
    LogTrace = 0x080000,
    LogLuaDebug = 0x008000,
    LogLuaInfo = 0x000800,
    LogError = 0x100000,
}

#[repr(i32)]
pub enum Status {
    Startup = 10,
    Connecting = 20,
    UpdatingDns = 30,
    Flying = 40,
    PROProblems = 50,
    Rejected = 60,
    NoNetwork = 90,
}

impl convert::Into<Status> for i32 {
    fn into(self) -> Status {
        unsafe { transmute::<i32, Status>(self) }
    }
}

pub static LOG_ERRORS: [VerbosityFlags; 2] = [VerbosityFlags::LogError,
                                              VerbosityFlags::LogManagerError];
pub static LOG_MANAGER: [VerbosityFlags; 2] = [VerbosityFlags::LogManagerError,
                                               VerbosityFlags::LogManagerInfo];
pub static LOG_CONNS: [VerbosityFlags; 2] = [VerbosityFlags::LogBeConns,
                                             VerbosityFlags::LogTunnelConns];
pub static LOG_NORMAL: [VerbosityFlags; 7] = [VerbosityFlags::LogError,
                                              VerbosityFlags::LogManagerError,
                                              VerbosityFlags::LogBeConns,
                                              VerbosityFlags::LogTunnelConns,
                                              VerbosityFlags::LogManagerError,
                                              VerbosityFlags::LogManagerInfo,
                                              VerbosityFlags::LogLuaInfo];
pub static LOG_ALL: [VerbosityFlags; 13] = [VerbosityFlags::LogTunnelData,
                                            VerbosityFlags::LogTunnelHeaders,
                                            VerbosityFlags::LogTunnelConns,
                                            VerbosityFlags::LogBeData,
                                            VerbosityFlags::LogBeHeaders,
                                            VerbosityFlags::LogBeConns,
                                            VerbosityFlags::LogManagerError,
                                            VerbosityFlags::LogManagerInfo,
                                            VerbosityFlags::LogManagerDebug,
                                            VerbosityFlags::LogTrace,
                                            VerbosityFlags::LogLuaDebug,
                                            VerbosityFlags::LogLuaInfo,
                                            VerbosityFlags::LogError];

pub struct PageKite {
    inner: pagekite_mgr,
}

macro_rules! str_cstring(
    ($a:ident) => ( CString::new($a).unwrap().as_ptr() )
);

macro_rules! build_flag(
    ($flag:ident, $array:ident) => (
        let mut $flag = 0;
        for item in $array {
            $flag |= *item as i32;
        }
    )
);

#[inline]
fn bool2int(val: bool) -> i32 {
    if val { 1 } else { 0 }
}

impl PageKite {
    pub fn init(app_id: Option<&str>,
                max_kites: i32,
                max_frontends: i32,
                max_conns: i32,
                dyndns_url: Option<&str>,
                flags: &[InitFlags],
                verbosity: &[VerbosityFlags])
                -> Option<Self> {

        build_flag!(c_flags, flags);
        build_flag!(c_verbosity, verbosity);

        let c_app_id = match app_id {
            Some(value) => str_cstring!(value),
            None => ptr::null(),
        };

        let c_dyndns_url = match dyndns_url {
            Some(value) => str_cstring!(value),
            None => ptr::null(),
        };

        let raw = unsafe {
            pagekite_init(c_app_id,
                          max_kites,
                          max_frontends,
                          max_conns,
                          c_dyndns_url,
                          c_flags,
                          c_verbosity)
        };
        if raw.is_null() {
            return None;
        }
        Some(PageKite { inner: raw })
    }

    pub fn init_pagekitenet(app_id: Option<&str>,
                            max_kites: i32,
                            max_conns: i32,
                            flags: &[InitFlags],
                            verbosity: &[VerbosityFlags])
                            -> Option<Self> {

        build_flag!(c_flags, flags);
        build_flag!(c_verbosity, verbosity);

        let c_app_id = match app_id {
            Some(value) => str_cstring!(value),
            None => ptr::null(),
        };

        let raw = unsafe {
            pagekite_init_pagekitenet(c_app_id, max_kites, max_conns, c_flags, c_verbosity)
        };
        if raw.is_null() {
            return None;
        }
        Some(PageKite { inner: raw })
    }

    pub fn init_whitelabel(app_id: Option<&str>,
                           max_kites: i32,
                           max_conns: i32,
                           flags: &[InitFlags],
                           verbosity: &[VerbosityFlags],
                           whitelabel_tld: Option<&str>)
                           -> Option<Self> {

        build_flag!(c_flags, flags);
        build_flag!(c_verbosity, verbosity);

        let c_app_id = match app_id {
            Some(value) => str_cstring!(value),
            None => ptr::null(),
        };

        let c_tld = match whitelabel_tld {
            Some(value) => str_cstring!(value),
            None => ptr::null(),
        };

        let raw = unsafe {
            pagekite_init_whitelabel(c_app_id, max_kites, max_conns, c_flags, c_verbosity, c_tld)
        };
        if raw.is_null() {
            return None;
        }
        Some(PageKite { inner: raw })
    }

    pub fn add_kite(&self,
                    proto: &str,
                    kitename: &str,
                    public_port: i32,
                    secret: &str,
                    backend: &str,
                    local_port: i32)
                    -> bool {

        return unsafe {
            pagekite_add_kite(self.inner,
                              str_cstring!(proto),
                              str_cstring!(kitename),
                              public_port,
                              str_cstring!(secret),
                              str_cstring!(backend),
                              local_port)
        } == 0;
    }

    /// Useful flags are WithDefaults, WithIpv4, WithIpv6, WithDynamicFeList
    /// Returns the number of frontend ips, or an empty error.
    pub fn add_service_frontends(&self, flags: &[InitFlags]) -> Result<usize, ()> {
        build_flag!(c_flags, flags);
        let ret = unsafe { pagekite_add_service_frontends(self.inner, c_flags) };
        if ret == -1 { Err(()) } else { Ok(ret as usize) }
    }

    pub fn add_whitelabel_frontends(&self,
                                    flags: &[InitFlags],
                                    whitelabel_tld: Option<&str>)
                                    -> Result<usize, ()> {
        build_flag!(c_flags, flags);
        let c_tld = match whitelabel_tld {
            Some(value) => str_cstring!(value),
            None => ptr::null(),
        };
        let ret = unsafe { pagekite_add_whitelabel_frontends(self.inner, c_flags, c_tld) };
        if ret == -1 { Err(()) } else { Ok(ret as usize) }
    }

    pub fn lookup_and_add_frontend(&self,
                                   domain: &str,
                                   port: i32,
                                   update_from_dns: bool)
                                   -> Option<i32> {
        let count = unsafe {
            pagekite_lookup_and_add_frontend(self.inner,
                                             str_cstring!(domain),
                                             port,
                                             if update_from_dns { 1 } else { 0 })
        };
        if count == -1 { None } else { Some(count) }
    }

    pub fn add_frontend(&self, domain: &str, port: i32) -> Option<i32> {
        let count = unsafe { pagekite_add_frontend(self.inner, str_cstring!(domain), port) };
        if count == -1 { None } else { Some(count) }
    }

    pub fn set_log_mask(&self, flags: &[VerbosityFlags]) {
        build_flag!(c_verbosity, flags);
        unsafe {
            pagekite_set_log_mask(self.inner, c_verbosity);
        }
    }

    pub fn set_housekeeping_min_interval(&self, interval: Duration) -> Duration {
        let ret = unsafe {
            pagekite_set_housekeeping_min_interval(self.inner, interval.as_secs() as i32)
        };
        Duration::new(ret as u64, 0)
    }

    pub fn set_housekeeping_max_interval(&self, interval: Duration) -> Duration {
        let ret = unsafe {
            pagekite_set_housekeeping_max_interval(self.inner, interval.as_secs() as i32)
        };
        Duration::new(ret as u64, 0)
    }

    pub fn enable_http_forwarding_headers(&self, enable: bool) -> &Self {
        unsafe {
            pagekite_enable_http_forwarding_headers(self.inner, bool2int(enable));
        }
        self
    }

    pub fn enable_fake_ping(&self, enable: bool) -> &Self {
        unsafe {
            pagekite_enable_fake_ping(self.inner, bool2int(enable));
        }
        self
    }

    pub fn enable_watchdog(&self, enable: bool) -> &Self {
        unsafe {
            pagekite_enable_watchdog(self.inner, bool2int(enable));
        }
        self
    }

    pub fn enable_tick_timer(&self, enable: bool) -> &Self {
        unsafe {
            pagekite_enable_tick_timer(self.inner, bool2int(enable));
        }
        self
    }

    pub fn set_conn_eviction_idle_s(&self, seconds: Duration) -> &Self {
        unsafe {
            pagekite_set_conn_eviction_idle_s(self.inner, seconds.as_secs() as i32);
        }
        self
    }

    pub fn set_openssl_ciphers(&self, ciphers: &str) -> &Self {
        unsafe {
            pagekite_set_openssl_ciphers(self.inner, str_cstring!(ciphers));
        }
        self
    }

    pub fn want_spare_frontends(&self, spares: i32) -> &Self {
        unsafe {
            pagekite_want_spare_frontends(self.inner, spares);
        }
        self
    }

    pub fn thread_start(&self) -> bool {
        return unsafe { pagekite_thread_start(self.inner) } == 0;
    }

    pub fn thread_wait(&self) -> bool {
        return unsafe { pagekite_thread_wait(self.inner) } == 0;
    }

    pub fn thread_stop(&self) -> bool {
        return unsafe { pagekite_thread_stop(self.inner) } == 0;
    }

    pub fn get_status(&self) -> Status {
        return unsafe { pagekite_get_status(self.inner) }.into();
    }

    pub fn get_log(&self) -> String {
        unsafe {
            CStr::from_ptr(pagekite_get_log(self.inner))
                .to_string_lossy()
                .into_owned()
        }
    }

    pub fn dump_state_to_log(&self) -> &Self {
        unsafe {
            pagekite_dump_state_to_log(self.inner);
        }
        self
    }

    pub fn poll(&self, timeout: Duration) -> bool {
        return unsafe { pagekite_poll(self.inner, timeout.as_secs() as i32) } == 0;
    }

    pub fn tick(&self) -> bool {
        return unsafe { pagekite_tick(self.inner) } == 0;
    }
}

impl Drop for PageKite {
    fn drop(&mut self) {
        unsafe {
            pagekite_thread_stop(self.inner);
            pagekite_free(self.inner);
        }
    }
}
