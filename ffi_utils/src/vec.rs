// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::mem;
use std::ptr;
use std::slice;

/// Provides FFI-safe pointers, as opposed to raw `as_ptr()` in
/// `Vec` and `String` which can return values such as `0x01` that
/// can cause segmentation faults with the automatic pointer
/// dereferencing on the front-end side (e.g. in Node.js).
pub trait SafePtr {
    /// Resulting pointer type
    type Ptr;

    /// Returns a pointer that guarantees safe dereferencing
    /// on the front-end side.
    fn as_safe_ptr(&self) -> *const Self::Ptr;
}

impl<T> SafePtr for Vec<T> {
    type Ptr = T;

    fn as_safe_ptr(&self) -> *const T {
        if self.is_empty() {
            ptr::null()
        } else {
            self.as_ptr()
        }
    }
}

/// Converts a pointer and lengts to Vec<T> by cloning the contents.
pub unsafe fn vec_clone_from_raw_parts<T: Clone>(ptr: *const T, len: usize) -> Vec<T> {
    slice::from_raw_parts(ptr, len).to_vec()
}

/// Converts a Vec<T> to (pointer, size, capacity)
pub fn vec_into_raw_parts<T>(mut v: Vec<T>) -> (*mut T, usize, usize) {
    v.shrink_to_fit();
    if v.is_empty() {
        return (ptr::null_mut(), 0, 0);
    }
    let ptr = v.as_mut_ptr();
    let len = v.len();
    let cap = v.capacity();
    mem::forget(v);
    (ptr, len, cap)
}
