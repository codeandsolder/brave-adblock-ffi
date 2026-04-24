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
use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr;
use std::sync::OnceLock;

mod c_convert;
pub use c_convert::*;

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

#[repr(C)]
pub struct CFilterList {
    pub data: *const u8,
    pub len: usize,
}

/// Callback type for domain resolution.
/// Takes a hostname and returns (start, end) indices of the domain part.
/// If the callback returns (0, 0), the domain is the entire hostname.
type DomainResolverCallback = extern "C" fn(host: *const c_char, start: *mut u32, end: *mut u32);

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
        let resolver = DOMAIN_RESOLVER
            .get()
            .copied()
            .unwrap_or(default_domain_resolver);
        let mut start: u32 = 0;
        let mut end: u32 = 0;
        let c_host = CString::new(host).unwrap_or_default();
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

#[no_mangle]
pub extern "C" fn c_adblock_has_domain_resolver() -> bool {
    DOMAIN_RESOLVER_SET.get() == Some(&true)
}

// ============================================================================
// Engine Management
// ============================================================================

/// Opaque engine handle
pub struct CEngine {
    engine: InnerEngine,
    lists: Vec<String>,
}

fn engine_from_lists(lists: &[String]) -> InnerEngine {
    let mut filter_set = InnerFilterSet::new(false);
    for filter_list in lists {
        let _ = filter_set.add_filter_list(filter_list, Default::default());
    }
    InnerEngine::from_filter_set(filter_set, true)
}

fn lists_from_parts(rules_array: *const CFilterList, rules_count: usize) -> Option<Vec<String>> {
    let mut lists = Vec::with_capacity(rules_count);
    if rules_array.is_null() || rules_count == 0 {
        return Some(lists);
    }

    let slice = unsafe { std::slice::from_raw_parts(rules_array, rules_count) };
    for rules in slice {
        if rules.data.is_null() || rules.len == 0 {
            continue;
        }

        let bytes = unsafe { std::slice::from_raw_parts(rules.data, rules.len) };
        let Ok(filter_list) = std::str::from_utf8(bytes) else {
            return None;
        };
        lists.push(filter_list.to_owned());
    }

    Some(lists)
}

/// Creates a new engine with no rules.
#[no_mangle]
pub extern "C" fn c_adblock_create_engine() -> *mut c_void {
    init_domain_resolver();
    let handle = CEngine {
        engine: InnerEngine::default(),
        lists: Vec::new(),
    };
    Box::into_raw(Box::new(handle)) as *mut c_void
}

/// Creates a new engine from an array of filter-list byte slices.
#[no_mangle]
pub extern "C" fn c_adblock_create_engine_from_lists(
    rules_array: *const CFilterList,
    rules_count: usize,
) -> *mut c_void {
    init_domain_resolver();
    let Some(lists) = lists_from_parts(rules_array, rules_count) else {
        return ptr::null_mut();
    };

    let handle = CEngine {
        engine: engine_from_lists(&lists),
        lists,
    };
    Box::into_raw(Box::new(handle)) as *mut c_void
}

#[no_mangle]
pub extern "C" fn c_adblock_replace_filter_lists(
    engine: *mut c_void,
    rules_array: *const CFilterList,
    rules_count: usize,
) -> bool {
    if engine.is_null() {
        return false;
    }

    let Some(lists) = lists_from_parts(rules_array, rules_count) else {
        return false;
    };
    let next_engine = engine_from_lists(&lists);
    let handle = unsafe { &mut *(engine as *mut CEngine) };
    handle.engine = next_engine;
    handle.lists = lists;
    true
}

#[no_mangle]
pub extern "C" fn c_adblock_matches(
    engine: *const c_void,
    url: *const c_char,
    request_type: *const c_char,
    source_url: *const c_char,
) -> CBlockerResult {
    if engine.is_null() || url.is_null() || request_type.is_null() {
        return CBlockerResult::default();
    }

    let url_str = unsafe { ptr_to_str(url) };
    let request_type_str = unsafe { ptr_to_str(request_type) };
    let source_url_str = unsafe { ptr_to_str(source_url) };

    let handle = unsafe { &*(engine as *const CEngine) };
    let Ok(request) = adblock::request::Request::new(url_str, source_url_str, request_type_str)
    else {
        return CBlockerResult::default();
    };

    let result = handle.engine.check_network_request(&request);

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

#[no_mangle]
pub extern "C" fn c_adblock_get_cosmetic_filters(
    engine: *const c_void,
    url: *const c_char,
) -> *mut c_char {
    if engine.is_null() || url.is_null() {
        return ptr::null_mut();
    }

    let url_str = unsafe { ptr_to_str(url) };
    let handle = unsafe { &*(engine as *const CEngine) };
    let cosmetic_resources = handle.engine.url_cosmetic_resources(url_str);
    let cosmetic_json = serde_json::to_string(&cosmetic_resources).unwrap_or_default();

    alloc_c_string(&cosmetic_json)
}

#[no_mangle]
pub extern "C" fn c_adblock_destroy_engine(engine: *mut c_void) {
    if !engine.is_null() {
        unsafe {
            drop(Box::from_raw(engine as *mut CEngine));
        }
    }
}

/// Safely frees a string using standard CString semantics.
#[no_mangle]
pub extern "C" fn c_adblock_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Returns a zero-copy string slice bound to the lifetime of the pointer.
unsafe fn ptr_to_str<'a>(ptr: *const c_char) -> &'a str {
    if ptr.is_null() {
        return "";
    }
    CStr::from_ptr(ptr).to_str().unwrap_or("")
}

/// Safely allocates an owned C string for the FFI boundary.
fn alloc_c_string(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}
