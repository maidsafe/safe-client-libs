// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// Helper macro to receive a routing event and assert it's a response
/// success.
#[macro_export]
macro_rules! expect_success {
    ($rx:expr, $msg_id:expr, $res:path) => {
        match unwrap!($rx.recv_timeout(Duration::from_secs(10))) {
            Event::Response {
                response: $res { res, msg_id },
                ..
            } => {
                assert_eq!(msg_id, $msg_id);

                match res {
                    Ok(value) => value,
                    Err(err) => panic!("Unexpected error {:?}", err),
                }
            }
            event => panic!("Unexpected event {:?}", event),
        }
    };
}

// impl Drop for Routing {
//     fn drop(&mut self) {
//         let _ = self.sender.send(Event::Terminate);
//     }
// }
