/* Copyright (c) 2024 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/. */

//! C FFI bindings for adblock-rust.
//!
//! This module provides C-compatible FFI functions that can be called from
//! any language that supports C FFI (Zig, Python via ctypes, Rust, etc.).
//!
//! Unlike the C++ FFI (lib.rs), this does not require cxx or Chromium's
//! domain resolver. A domain resolver can be set via `c_adblock_set_domain_resolver`.

use adblock::lists::FilterSet as InnerFilterSet;
use adblock::url_parser::ResolvesDomain;
use adblock::Engine as InnerEngine;
use std::ffi::{c_char, c_void};
use std::ptr;
use std::sync::OnceLock;

mod c_convert;

pub use c_convert::*;

// ============================================================================
// Types
// ============================================================================

/// Result of a blocking operation - C compatible layout
#[repr(C)]
pub struct CBlockerResult {
    pub matched: bool,
    pub important: bool,
    pub has_exception: bool,
    pub redirect: *mut c_char,
    pub rewritten_url: *mut c_char,
}

impl Default for CBlockerResult {
    fn default() -> Self {
        Self {
            matched: false,
            important: false,
            has_exception: false,
            redirect: ptr::null_mut(),
            rewritten_url: ptr::null_mut(),
        }
    }
}

/// Callback type for domain resolution.
/// Takes a hostname and returns (start, end) indices of the domain part.
/// If the callback returns (0, 0), the domain is the entire hostname.
type DomainResolverCallback =
    extern "C" fn(host: *const c_char, start: *mut u32, end: *mut u32);

static DOMAIN_RESOLVER: OnceLock<DomainResolverCallback> = OnceLock::new();
static DOMAIN_RESOLVER_SET: OnceLock<bool> = OnceLock::new();

fn cstring_len(s: *const c_char) -> usize {
    if s.is_null() {
        return 0;
    }
    unsafe {
        let mut len = 0;
        let mut p = s;
        while *p != 0 {
            len += 1;
            p = p.offset(1);
        }
        len
    }
}

extern "C" fn default_domain_resolver(host: *const c_char, start: *mut u32, end: *mut u32) {
    let len = cstring_len(host);
    if len == 0 {
        unsafe {
            *start = 0;
            *end = 0;
        }
        return;
    }

    let hostname = unsafe {
        let slice = std::slice::from_raw_parts(host as *const u8, len);
        std::str::from_utf8(slice).unwrap_or("")
    };

    if let Some(pos) = hostname.find('.') {
        unsafe {
            *start = 0;
            *end = pos as u32;
        }
    } else {
        unsafe {
            *start = 0;
            *end = hostname.len() as u32;
        }
    }
}

struct CallbackDomainResolver;

impl ResolvesDomain for CallbackDomainResolver {
    fn get_host_domain(&self, host: &str) -> (usize, usize) {
        let resolver = DOMAIN_RESOLVER.get().copied().unwrap_or(default_domain_resolver);

        let mut start: u32 = 0;
        let mut end: u32 = 0;

        let c_host = std::ffi::CString::new(host).unwrap_or_default();
        resolver(c_host.as_ptr(), &mut start, &mut end);

        (start as usize, end as usize)
    }
}

fn init_domain_resolver() {
    let already_set = DOMAIN_RESOLVER_SET.get_or_init(|| {
        if DOMAIN_RESOLVER.get().is_none() {
            let _ = DOMAIN_RESOLVER.set(default_domain_resolver);
        }
        adblock::url_parser::set_domain_resolver(Box::new(CallbackDomainResolver)).is_ok()
    });
    let _ = already_set;
}

// ============================================================================
// Domain Resolver API
// ============================================================================

/// Sets the domain resolver callback.
/// The callback will be called to resolve domain positions from hostnames.
/// This must be called before any engine operations.
/// Returns true if the resolver was set successfully.
#[no_mangle]
pub extern "C" fn c_adblock_set_domain_resolver(resolver: DomainResolverCallback) -> bool {
    let _ = DOMAIN_RESOLVER.set(resolver);
    let _ = DOMAIN_RESOLVER_SET.set(true);
    adblock::url_parser::set_domain_resolver(Box::new(CallbackDomainResolver)).is_ok()
}

/// Checks if a domain resolver has been set.
#[no_mangle]
pub extern "C" fn c_adblock_has_domain_resolver() -> bool {
    DOMAIN_RESOLVER_SET.get() == Some(&true)
}

// ============================================================================
// Engine Management
// ============================================================================

/// Opaque engine handle
pub type CEngine = InnerEngine;

/// Creates a new engine with no rules.
#[no_mangle]
pub extern "C" fn c_adblock_create_engine() -> *mut c_void {
    init_domain_resolver();
    let engine = InnerEngine::default();
    Box::into_raw(Box::new(engine)) as *mut c_void
}

/// Creates a new engine with rules from a filter list.
/// Returns null on error.
#[no_mangle]
pub extern "C" fn c_adblock_create_engine_with_rules(
    rules: *const c_char,
    rules_len: usize,
) -> *mut c_void {
    if rules.is_null() || rules_len == 0 {
        return ptr::null_mut();
    }

    let rules_slice = unsafe { std::slice::from_raw_parts(rules as *const u8, rules_len) };
    let rules_str = match std::str::from_utf8(rules_slice) {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    init_domain_resolver();

    let mut filter_set = InnerFilterSet::new(false);
    let _ = filter_set.add_filter_list(rules_str, Default::default());
    let engine = InnerEngine::from_filter_set(filter_set, true);
    Box::into_raw(Box::new(engine)) as *mut c_void
}

/// Adds a filter list to an existing engine.
/// The engine is rebuilt with the new filter list.
#[no_mangle]
pub extern "C" fn c_adblock_add_filter_list(
    engine: *mut c_void,
    rules: *const c_char,
    rules_len: usize,
) -> bool {
    if engine.is_null() || rules.is_null() || rules_len == 0 {
        return false;
    }

    init_domain_resolver();

    let rules_slice = unsafe { std::slice::from_raw_parts(rules as *const u8, rules_len) };
    let rules_str = match std::str::from_utf8(rules_slice) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let old_engine = unsafe { &mut *(engine as *mut InnerEngine) };

    let mut filter_set = InnerFilterSet::new(false);
    let _ = filter_set.add_filter_list(rules_str, Default::default());

    let new_engine = InnerEngine::from_filter_set(filter_set, true);
    *old_engine = new_engine;
    true
}

/// Checks if a request should be blocked.
#[no_mangle]
pub extern "C" fn c_adblock_matches(
    engine: *const c_void,
    url: *const c_char,
    hostname: *const c_char,
    source_hostname: *const c_char,
    request_type: *const c_char,
    third_party: bool,
) -> CBlockerResult {
    if engine.is_null() || url.is_null() || hostname.is_null() || request_type.is_null() {
        return CBlockerResult::default();
    }

    let url_str = match ptr_to_string(url) {
        Some(s) => s,
        None => return CBlockerResult::default(),
    };
    let hostname_str = match ptr_to_string(hostname) {
        Some(s) => s,
        None => return CBlockerResult::default(),
    };
    let source_hostname_str = if source_hostname.is_null() {
        String::new()
    } else {
        ptr_to_string(source_hostname).unwrap_or_default()
    };
    let request_type_str = match ptr_to_string(request_type) {
        Some(s) => s,
        None => return CBlockerResult::default(),
    };

    let engine_ref = unsafe { &*(engine as *const InnerEngine) };

    let request = adblock::request::Request::preparsed(
        &url_str,
        &hostname_str,
        &source_hostname_str,
        &request_type_str,
        third_party,
    );

    let result = engine_ref.check_network_request_subset(&request, false, false);

    let mut blocker_result = CBlockerResult::default();
    blocker_result.matched = result.matched;
    blocker_result.important = result.important;
    blocker_result.has_exception = result.exception.is_some();

    if let Some(redirect) = result.redirect {
        blocker_result.redirect = alloc_c_string(&redirect);
    }
    if let Some(rewritten) = result.rewritten_url {
        blocker_result.rewritten_url = alloc_c_string(&rewritten);
    }

    blocker_result
}

/// Returns JSON-serialized cosmetic filter resources for a URL.
#[no_mangle]
pub extern "C" fn c_adblock_get_cosmetic_filters(
    engine: *const c_void,
    url: *const c_char,
) -> *mut c_char {
    if engine.is_null() || url.is_null() {
        return ptr::null_mut();
    }

    let url_str = match ptr_to_string(url) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };

    let engine_ref = unsafe { &*(engine as *const InnerEngine) };
    let cosmetic_resources = engine_ref.url_cosmetic_resources(&url_str);
    let cosmetic_json = serde_json::to_string(&cosmetic_resources).unwrap_or_default();

    alloc_c_string(&cosmetic_json)
}

/// Destroys an engine and frees memory.
#[no_mangle]
pub extern "C" fn c_adblock_destroy_engine(engine: *mut c_void) {
    if !engine.is_null() {
        unsafe {
            drop(Box::from_raw(engine as *mut InnerEngine));
        }
    }
}

/// Frees a string allocated by the library.
#[no_mangle]
pub extern "C" fn c_adblock_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let len = cstring_len(s);
            let slice = std::slice::from_raw_parts_mut(s as *mut u8, len + 1);
            let _ = Vec::from_raw_parts(slice.as_mut_ptr(), len, len + 1);
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn ptr_to_string(ptr: *const c_char) -> Option<String> {
    let len = cstring_len(ptr);
    if len == 0 {
        return Some(String::new());
    }
    unsafe {
        let slice = std::slice::from_raw_parts(ptr as *const u8, len);
        std::str::from_utf8(slice).ok().map(|s| s.to_string())
    }
}

fn alloc_c_string(s: &str) -> *mut c_char {
    let mut vec = s.as_bytes().to_vec();
    vec.push(0);
    let ptr = vec.as_mut_ptr();
    std::mem::forget(vec);
    ptr as *mut c_char
}