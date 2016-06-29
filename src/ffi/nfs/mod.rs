// Copyright 2015 MaidSafe.net limited.
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
use std::fmt;

use ffi::{Action, ParameterPacket, ResponseType};
use ffi::errors::FfiError;
use rustc_serialize::{Decodable, Decoder};

mod create_dir;
mod create_file;
mod delete_dir;
mod delete_file;
mod get_dir;
mod get_file;
mod get_file_metadata;
mod move_dir;
mod move_file;
mod modify_dir;
mod modify_file;
pub mod directory_response;
pub mod file_response;

pub fn action_dispatcher<D>(action: String,
                            params: ParameterPacket,
                            decoder: &mut D)
                            -> ResponseType
    where D: Decoder,
          D::Error: fmt::Debug
{
    let mut action = try!(get_action(action, decoder));
    action.execute(params)
}

fn get_action<D>(action: String, decoder: &mut D) -> Result<Box<Action>, FfiError>
    where D: Decoder,
          D::Error: fmt::Debug
{
    Ok(match &action[..] {
        "create-dir" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            create_dir::CreateDir::decode(d)
                                        }),
                                        "")))
        }
        "create-file" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            create_file::CreateFile::decode(d)
                                        }),
                                        "")))
        }
        "delete-dir" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            delete_dir::DeleteDir::decode(d)
                                        }),
                                        "")))
        }
        "delete-file" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            delete_file::DeleteFile::decode(d)
                                        }),
                                        "")))
        }
        "get-dir" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data",
                                                                  0,
                                                                  |d| get_dir::GetDir::decode(d)),
                                        "")))
        }
        "get-file" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            get_file::GetFile::decode(d)
                                        }),
                                        "")))
        }
        "modify-dir" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            modify_dir::ModifyDir::decode(d)
                                        }),
                                        "")))
        }
        "modify-file" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            modify_file::ModifyFile::decode(d)
                                        }),
                                        "")))
        }
        "move-dir" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            move_dir::MoveDirectory::decode(d)
                                        }),
                                        "")))
        }
        "move-file" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            move_file::MoveFile::decode(d)
                                        }),
                                        "")))
        }
        "get-file-metadata" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            get_file_metadata::GetFileMetadata::decode(d)
                                        }),
                                        "")))
        }
        _ => {
            return Err(FfiError::SpecificParseError(format!("Unsupported action {:?} for this \
                                                             endpoint.",
                                                            action)))
        }
    })
}
