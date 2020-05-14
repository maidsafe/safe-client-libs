// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use futures::sync::oneshot::Sender;
use log::trace;

use safe_nd::{MessageId, Response};

use std::collections::HashMap;
use threshold_crypto::{SignatureShare, PublicKeySet};
type ResponseRequiredCount = usize;
type VoteCount = usize;

// enum VoteMap {
//     Response(HashMap<Response, VoteCount>),
//     PkSet(HashMap<PublicKeySet, VoteCount>)
// }

type VoteMap = HashMap<Response, VoteCount>;

pub struct ResponseManager {
    /// MessageId to send_future channel map
    requests: HashMap<MessageId, (Sender<Response>, VoteMap, ResponseRequiredCount)>,
    /// Number of responses to aggregate before returning to a client
    response_threshold: usize,
    /// Signature shared for a given message id
    pending_transfer_validation_signatures: HashMap<MessageId, Vec<SignatureShare> >
}

/// Manage requests and their responses
impl ResponseManager {
    pub fn new(response_threshold: ResponseRequiredCount) -> Self {
        Self {
            requests: Default::default(),
            pending_transfer_validation_signatures: HashMap::new(),
            response_threshold,
        }
    }

    pub fn await_responses(
        &mut self,
        msg_id: MessageId,
        value: (Sender<Response>, ResponseRequiredCount),
    ) -> Result<(), String> {
        let (sender, count) = value;
        let the_request = (sender, VoteMap::default(), count);
        let _ = self.requests.insert(msg_id, the_request);
        Ok(())
    }

    /// default response handling. Will store responses and compare against newer responses,
    /// returning the most common response once threshold was reached, or most popular response
    /// if no response has reached quorum.
    /// TODO: do we need to distinguish non-quorum'd responses?
    fn get_quorum_responses( &mut self, msg_id: MessageId, response: Response, sender: Sender<Response>, mut vote_map: VoteMap, current_count: ResponseRequiredCount ) -> Option<Response> {

        // let vote_response_comparator = match response {
        //     Response::TransferValidation(Ok(TransferValidation {
        //         pk_set,
        //         ..
        //     })) => { pk_set },
        //     _ => response
        // };


        // get our tally for this response
        let cast_votes = vote_map.remove(&vote_response_comparator);

        // if we already have this response, lets vote for it
        if let Some(votes) = cast_votes {
            trace!("Increasing vote count to {:?}", votes + 1);
            let _ = vote_map.insert(vote_response_comparator, votes + 1);
        } else {
            // otherwise we add this as a candidate with one vote
            let _ = vote_map.insert(vote_response_comparator, 1);
        }

        trace!("Response vote map looks like: {:?}", &vote_map);

        // if 50+% successfull responses, we roll with it.
        if current_count <= self.response_threshold {
            let mut vote_met_threshold = false;

            for (_response_key, votes) in vote_map.iter() {
                if votes >= &self.response_threshold {
                    trace!("Response request, votes met the required threshold.");
                    vote_met_threshold = true;
                }
            }

            // we met the threshold OR it's the last response... so we work with whatever we have
            if vote_met_threshold || current_count == 0 {
                let mut new_voter_threshold = 0;
                let mut our_most_popular_response = &response;

                // find the most popular of our responses.
                for (response_key, votes) in vote_map.iter() {
                    if votes > &new_voter_threshold {
                        // this means we'll always go with whatever we hit here in first.
                        new_voter_threshold = *votes;
                        our_most_popular_response = response_key;
                    }
                }

                // let _ = sender.send(our_most_popular_response.clone());
                return Some(our_most_popular_response.clone());
            }
        }
        let _ = self
            .requests
            .insert(msg_id, (sender, vote_map, current_count));
        
        None
    }

    /// Handle a response from one of the elders.
    pub fn handle_response(&mut self, msg_id: MessageId, response: Response) -> Result<(), String> {
        trace!(
            "Handling response for msg_id: {:?}, resp: {:?}",
            msg_id,
            response
        );

        // response initially added in await_responses
        let _ = self
            // first remove the response and see how we deal with it (we re-add later if needed)
            .requests
            .remove(&msg_id)
            .map(|(sender, mut vote_map, count)| {

                // drop the count as we have this new response.
                let current_count = count - 1;

                // TODO:
                // 1. If we have a GetTransferValidation response we store ALL responses.
                // 2. Return when we have quorum, and return full signed repsonse to client... ??

                if let Response::TransferValidation(Ok(TransferValidation{
                    // pub transfer_cmd: ValidateTransfer,
                    /// Elder signature over the transfer cmd.
                    elder_signature,
                    /// The PK Set of the section
                    pk_set,
                    ..
                })) = response.clone() {
                    // do we assume here, that msg_id == the same message... 
                    // what happens with bogus signatures? How much to _try_...
                    println!("!!!!!!!!!!!!!!!!!!!Signature share receivedddd!! {:?}", response);

                    // TODO: track the PKSets incoming. and vote for them.

                    // get our tally for this response
                    let current_sigs = self.pending_transfer_validation_signatures.remove(&msg_id);

                    // if we already have this response, lets vote for it
                    if let Some(signature_vec) = current_sigs {
                       
                        
                        if signature_vec.len() > 4 {
                            // TODO: attempt to aggregate the sig against a known pk_set. Where/when would we get this?
                            // let( )
                            
                            // sender.send(Response::TransferValidated(Ok(signature_vec)));
                            return;
                        }
                        signature_vec.push(elder_signature);
                        trace!("Adding a signature to our pending sigs");
                        let _ = self.pending_transfer_validation_signatures.insert(msg_id, signature_vec);
                       
                    } else {
                        // otherwise we add this as a candidate
                        let _ = self.pending_transfer_validation_signatures.insert(msg_id, vec![elder_signature]);

                    }

                    let _ = self
                        .requests
                        .insert(msg_id, (sender, vote_map, current_count));
                    return;
                }

                match self.get_quorum_responses( msg_id, response, sender, vote_map, current_count ) {
                    Some(response) => {
                        let _ = sender.send(response);

                    },
                    None => {
                        // do nothing
                    }
                }
                // match self.get_quorum_responses( msg_id, response, sender, vote_map, current_count ) {
                //     PublicKeySet(pk_set) => {
                //         sender.send(pk_set)
                //     },
                //     response => { sender.send(response); }
                // }


            }
        )
            .or_else(|| {
                trace!("No request found for message ID {:?}", msg_id);
                None
            });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use futures::{sync::oneshot, Future};
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    use super::*;

    #[test]
    fn response_manager_get_response_ok() -> Result<(), String> {
        let response_threshold = 1;

        let mut response_manager = ResponseManager::new(response_threshold);

        // set up a message
        let message_id = safe_nd::MessageId::new();

        let (sender_future, response_future) = oneshot::channel();
        let expected_responses = 1; // for IData

        // our pseudo data
        let immutable_data = safe_nd::PubImmutableData::new(vec![6]);

        let response = safe_nd::Response::GetIData(Ok(safe_nd::IData::from(immutable_data)));

        response_manager.await_responses(message_id, (sender_future, expected_responses))?;
        response_manager.handle_response(message_id, response.clone())?;

        let _ = response_future
            .map(move |i| {
                assert_eq!(&i, &response);
            })
            .wait();
        Ok(())
    }

    // basic test to ensure future response is being properly evaluated and our test fails for bad responses
    #[test]
    fn response_manager_get_response_fail_with_bad_data() -> Result<(), String> {
        let response_threshold = 1;

        let mut response_manager = ResponseManager::new(response_threshold);

        // set up a message
        let message_id = safe_nd::MessageId::new();

        let (sender_future, response_future) = oneshot::channel();
        let expected_responses = 1; // for IData

        // our expected data
        let immutable_data = safe_nd::PubImmutableData::new(vec![6]);

        // our nonsense response we receive
        let immutable_data_bad = safe_nd::PubImmutableData::new(vec![7]);

        let response = safe_nd::Response::GetIData(Ok(safe_nd::IData::from(immutable_data)));
        let bad_response =
            safe_nd::Response::GetIData(Ok(safe_nd::IData::from(immutable_data_bad)));

        response_manager.await_responses(message_id, (sender_future, expected_responses))?;
        response_manager.handle_response(message_id, bad_response)?;

        let _ = response_future
            .map(move |i| {
                assert_ne!(&i, &response);
            })
            .wait();
        Ok(())
    }

    #[test]
    fn response_manager_get_success_even_with_some_failed_responses() -> Result<(), String> {
        let response_threshold = 4;

        let mut response_manager = ResponseManager::new(response_threshold);

        // set up a message
        let message_id = safe_nd::MessageId::new();

        let (sender_future, response_future) = oneshot::channel();

        // TODO: can we drop expected responses now...?
        let expected_responses = 7;

        // our expected data
        let data = safe_nd::MDataValue::from(vec![6]);

        let response = safe_nd::Response::GetMDataValue(Ok(data));

        let error = safe_nd::Error::NoSuchData;
        let bad_response = safe_nd::Response::GetIData(Err(error));

        let mut responses_to_handle = vec![
            response.clone(),
            response.clone(),
            response.clone(),
            response.clone(),
            bad_response.clone(),
            bad_response.clone(),
            bad_response,
        ];

        let mut rng = thread_rng();

        // lets shuffle the array to ensure order is not important
        responses_to_handle.shuffle(&mut rng);

        response_manager.await_responses(message_id, (sender_future, expected_responses))?;

        for resp in responses_to_handle {
            response_manager.handle_response(message_id, resp)?;
        }

        let _ = response_future
            .map(move |i| {
                assert_eq!(&i, &response);
            })
            .wait();
        Ok(())
    }

    #[test]
    fn response_manager_get_fails_even_with_some_success_responses() -> Result<(), String> {
        let response_threshold = 4;

        let mut response_manager = ResponseManager::new(response_threshold);

        // set up a message
        let message_id = safe_nd::MessageId::new();

        let (sender_future, response_future) = oneshot::channel();

        let expected_responses = 7;

        // our expected data
        let data = safe_nd::MDataValue::from(vec![6]);

        let response = safe_nd::Response::GetMDataValue(Ok(data));

        let error = safe_nd::Error::NoSuchData;
        let bad_response = safe_nd::Response::GetIData(Err(error));

        let mut responses_to_handle = vec![
            response.clone(),
            response.clone(),
            response,
            bad_response.clone(),
            bad_response.clone(),
            bad_response.clone(),
            bad_response.clone(),
        ];

        let mut rng = thread_rng();

        // lets shuffle the array to ensure order is not important
        responses_to_handle.shuffle(&mut rng);

        response_manager.await_responses(message_id, (sender_future, expected_responses))?;

        for resp in responses_to_handle {
            response_manager.handle_response(message_id, resp)?;
        }

        // last response should be bad to ensure we dont just default to it
        response_manager.handle_response(message_id, bad_response.clone())?;

        let _ = response_future
            .map(move |i| {
                assert_eq!(&i, &bad_response);
            })
            .wait();
        Ok(())
    }

    #[test]
    fn response_manager_get_with_most_responses_when_nothing_meets_threshold() -> Result<(), String>
    {
        let response_threshold = 4;

        let mut response_manager = ResponseManager::new(response_threshold);

        // set up a message
        let message_id = safe_nd::MessageId::new();

        let (sender_future, response_future) = oneshot::channel();

        let expected_responses = 7;

        // our expected data
        let data = safe_nd::MDataValue::from(vec![6]);

        let response = safe_nd::Response::GetMDataValue(Ok(data));

        let bad_response = safe_nd::Response::GetIData(Err(safe_nd::Error::NoSuchData));
        let another_bad_response = safe_nd::Response::GetIData(Err(safe_nd::Error::NoSuchEntry));

        let mut responses_to_handle = vec![
            // todo, back to 3 responses
            response.clone(),
            response.clone(),
            response.clone(),
            bad_response.clone(),
            bad_response,
            another_bad_response.clone(),
            another_bad_response,
        ];

        let mut rng = thread_rng();

        // lets shuffle the array to ensure order is not important
        responses_to_handle.shuffle(&mut rng);

        response_manager.await_responses(message_id, (sender_future, expected_responses))?;

        for resp in responses_to_handle {
            response_manager.handle_response(message_id, resp)?;
        }

        let _ = response_future
            .map(move |i| {
                assert_eq!(&i, &response);
            })
            .wait();
        Ok(())
    }

    #[test]
    fn response_manager_get_with_most_responses_when_divergent_success() -> Result<(), String> {
        let response_threshold = 4;

        let mut response_manager = ResponseManager::new(response_threshold);

        // set up a message
        let message_id = safe_nd::MessageId::new();

        let (sender_future, response_future) = oneshot::channel();

        let expected_responses = 7;

        // our expected data
        let data = safe_nd::MDataValue::from(vec![6]);
        let other_data = safe_nd::MDataValue::from(vec![77]);

        let response = safe_nd::Response::GetMDataValue(Ok(data));
        let other_response = safe_nd::Response::GetMDataValue(Ok(other_data));

        let mut responses_to_handle = vec![
            response.clone(),
            response.clone(),
            response,
            other_response.clone(),
            other_response.clone(),
            other_response.clone(),
            other_response.clone(),
        ];

        let mut rng = thread_rng();

        // lets shuffle the array to ensure order is not important
        responses_to_handle.shuffle(&mut rng);

        response_manager.await_responses(message_id, (sender_future, expected_responses))?;

        for resp in responses_to_handle {
            response_manager.handle_response(message_id, resp)?;
        }

        let _ = response_future
            .map(move |i| {
                assert_eq!(&i, &other_response);
            })
            .wait();
        Ok(())
    }
  
    #[test]
    fn response_manager_return_complete_signed_transfervalidation() -> Result<(), String> {
        let response_threshold = 4;

        let mut response_manager = ResponseManager::new(response_threshold);

        // set up a message
        let message_id = safe_nd::MessageId::new();

        let (sender_future, response_future) = oneshot::channel();

        let expected_responses = 7;

        // our sig shares
        use threshold_crypto::{SecretKeySet};
        let threshold = 3; // 3 + 1 needed to sign. 
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(threshold, &mut rng);

        // this should be retrieved from Elder node
        let sk_share = sk_set.secret_key_share(0);

        let mut responses_to_handle = vec![
            safe_nd::Response::GetTransferValidation(Ok(sk_set.secret_key_share(0).sign([1,2,3]) )),
        safe_nd::Response::GetTransferValidation(Ok(sk_set.secret_key_share(1).sign([1,2,3]) )),
         safe_nd::Response::GetTransferValidation(Ok(sk_set.secret_key_share(2).sign([1,2,3]) )),
         safe_nd::Response::GetTransferValidation(Ok(sk_set.secret_key_share(3).sign([1,2,3]) )),
         safe_nd::Response::GetTransferValidation(Ok(sk_set.secret_key_share(4).sign([1,2,3]) )),
         safe_nd::Response::GetTransferValidation(Ok(sk_set.secret_key_share(6).sign([1,2,3]) )),
         safe_nd::Response::GetTransferValidation(Ok(sk_set.secret_key_share(6).sign([1,2,3]) )),
        ];

        let mut rng = thread_rng();

        // lets shuffle the array to ensure order is not important
        responses_to_handle.shuffle(&mut rng);

        response_manager.await_responses(message_id, (sender_future, expected_responses))?;

        for resp in responses_to_handle {
            response_manager.handle_response(message_id, resp)?;
        }

        let _ = response_future
            .map(move |i| {

                println!("response receivedd of elngth {:?}", i);
                // assert!(i.len() >= response_threshold );
            })
            .wait();
        Ok(())
    }
}
