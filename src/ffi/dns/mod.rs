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

use ffi::errors::FfiError;
use ffi::{Action, ParameterPacket, ResponseType};
use rustc_serialize::{Decodable, Decoder};

mod add_service;
mod delete_service;
mod delete_dns;
mod register_dns;
mod get_file;
mod get_file_metadata;
mod get_long_names;
mod get_service_directory;
mod get_services;
mod register_public_id;

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
        "register-public-id" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            register_public_id::RegisterPublicId::decode(d)
                                        }),
                                        "")))
        }
        "register-dns" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            register_dns::RegisterDns::decode(d)
                                        }),
                                        "")))
        }
        "add-service" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            add_service::AddService::decode(d)
                                        }),
                                        "")))
        }
        "get-home-dir" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            get_service_directory::GetServiceDirectory::decode(d)
                                        }),
                                        "")))
        }
        "get-file" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            get_file::GetFile::decode(d)
                                        }),
                                        "")))
        }
        "get-long-names" => Box::new(get_long_names::GetLongNames),
        "get-services" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            get_services::GetServices::decode(d)
                                        }),
                                        "")))
        }
        "delete-dns" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            delete_dns::DeleteDns::decode(d)
                                        }),
                                        "")))
        }
        "delete-service" => {
            Box::new(try!(parse_result!(decoder.read_struct_field("data", 0, |d| {
                                            delete_service::DeleteService::decode(d)
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
