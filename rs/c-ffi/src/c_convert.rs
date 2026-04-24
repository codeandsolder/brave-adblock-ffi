/* Copyright (c) 2024 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Conversion utilities for C FFI.

use adblock::engine::EngineDebugInfo as InnerEngineDebugInfo;

/// Debug info for regex manager
#[repr(C)]
pub struct CDebugInfo {
    pub compiled_regex_count: usize,
    pub flatbuffer_size: usize,
}

impl From<InnerEngineDebugInfo> for CDebugInfo {
    fn from(info: InnerEngineDebugInfo) -> Self {
        Self {
            compiled_regex_count: info.regex_debug_info.compiled_regex_count,
            flatbuffer_size: info.flatbuffer_size,
        }
    }
}
