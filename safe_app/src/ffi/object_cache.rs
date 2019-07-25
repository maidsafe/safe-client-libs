// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Types for handles of objects stored in the `ObjectCache`.

/// Value of handles which should receive special handling.
pub const NULL_OBJECT_HANDLE: u64 = 0;

/// Object handle associated with objects. In normal C API one would expect rust
/// code to pass pointers to opaque object to C. C code would then need to pass
/// these pointers back each time they needed rust code to execute something on
/// those objects. However our code base deals with communication over Web
/// framework (like webservers for instance). Hence it is not possible to pass
/// pointers to remote apps interfacing with us. Pointers represent handle to
/// actual object.  Using similar concept, we instead pass `ObjectHandle` type
/// over Web interface and manage the objects ourselves. This leads to extra
/// type and memory safety and no chance of Undefined Behaviour.  Passing of
/// pointer handles to C is replaced by passing of `ObjectHandle` to remote apps
/// which they will use to do RPC's.
pub type ObjectHandle = u64;

/// Disambiguating `ObjectHandle`
pub type CipherOptHandle = ObjectHandle;
/// Disambiguating `ObjectHandle`
pub type EncryptPubKeyHandle = ObjectHandle;
/// Disambiguating `ObjectHandle`
pub type EncryptSecKeyHandle = ObjectHandle;
/// Disambiguating `ObjectHandle`
pub type MDataEntriesHandle = ObjectHandle;
/// Disambiguating `ObjectHandle`
pub type MDataEntryActionsHandle = ObjectHandle;
/// Disambiguating `ObjectHandle`
pub type MDataPermissionsHandle = ObjectHandle;
/// Disambiguating `ObjectHandle`
pub type SelfEncryptorReaderHandle = ObjectHandle;
/// Disambiguating `ObjectHandle`
pub type SelfEncryptorWriterHandle = ObjectHandle;
/// Disambiguating `ObjectHandle`
pub type SignPubKeyHandle = ObjectHandle;
/// Disambiguating `ObjectHandle`
pub type PubKeyHandle = ObjectHandle;
/// Disambiguating `ObjectHandle`
pub type SignSecKeyHandle = ObjectHandle;
/// Disambiguating `ObjectHandle`
pub type FileContextHandle = ObjectHandle;
