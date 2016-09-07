// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! Low Level APIs

/// Low level manipulation of Pub/PrivAppendableData
// pub mod appendable_data;
/// Cipher Options
pub mod cipher_opt;
/// DataIdentifier constructions and freeing
pub mod data_id;
/// Low level manipulation of ImmutableData
pub mod immut_data;
/// Low level manipulation of StructuredData
pub mod struct_data;
/// Low level manipulation of {Pub|Priv}AppendableData
pub mod appendable_data;

/// Object handle associated with objects. In normal C API one would expect rust code to pass
/// pointers to opaque object to C. C code would then need to pass these pointers back each time
/// they needed rust code to execute something on those objects. However our code base deals with
/// communication over Web framework (like WebServers for instance). Hence it is not possible to
/// pass pointers to remote apps interfacing with us. Pointers represent handle to actual object.
/// Using similar concept, we instead pass ObjectHandle type over Web interface and manage the
/// objects ourselves. This leads to extra type and memory safety and no chance of Undefined
/// Behaviour. Passing of pointer handles to C is replaced by passing of ObjectHandle to remote
/// apps which they will use to do RPC's.
pub type ObjectHandle = u64;

/// Disambiguating ObjectHandle
pub type AppendableDataHandle = ObjectHandle;
/// Disambiguating ObjectHandle
pub type StructDataHandle = ObjectHandle;
/// Disambiguating ObjectHandle
pub type DataIdHandle = ObjectHandle;
/// Disambiguating ObjectHandle
pub type SelfEncryptorReaderHandle = ObjectHandle;
/// Disambiguating ObjectHandle
pub type SelfEncryptorWriterHandle = ObjectHandle;
/// Disambiguating ObjectHandle
pub type CipherOptHandle = ObjectHandle;
/// Disambiguating ObjectHandle
pub type EncryptKeyHandle = ObjectHandle;
/// Disambiguating ObjectHandle
pub type SignKeyHandle = ObjectHandle;

mod object_cache;
