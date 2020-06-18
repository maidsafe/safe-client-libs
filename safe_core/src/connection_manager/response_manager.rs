// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use futures::channel::mpsc;
use log::{debug, trace};
use safe_nd::{MessageId, Response};
use std::collections::HashMap;

type ResponseRequiredCount = usize;
type VoteCount = usize;
type VoteMap = HashMap<Response, VoteCount>;
type IsValidationRequest = bool;

pub struct ResponseManager {
    /// MessageId to send_future channel map
    requests: HashMap<
        MessageId,
        (
            mpsc::UnboundedSender<(Response, MessageId)>,
            VoteMap,
            ResponseRequiredCount,
            IsValidationRequest,
        ),
    >,
    /// Number of responses to aggregate before returning to a client
    response_threshold: usize,
}

/// Manage requests and their responses
impl ResponseManager {
    pub fn new(response_threshold: ResponseRequiredCount) -> Self {
        Self {
            requests: Default::default(),
            response_threshold,
        }
    }

    pub fn await_responses(
        &mut self,
        msg_id: MessageId,
        value: (
            mpsc::UnboundedSender<(Response, MessageId)>,
            ResponseRequiredCount,
            bool,
        ),
    ) -> Result<(), String> {
        let (sender, count, is_validation_request) = value;
        let the_request = (sender, VoteMap::default(), count, is_validation_request);
        let _ = self.requests.insert(msg_id, the_request);
        Ok(())
    }

    /// Handle a response from one of the elders.
    pub fn handle_response(&mut self, msg_id: MessageId, response: Response) -> Result<(), String> {
        debug!(
            "Handling response for msg_id: {:?}, resp: {:?}",
            msg_id, response
        );

        let _ = self
            // first remove the response and see how we deal with it (we re-add later if needed)
            .requests
            .remove(&msg_id)
            .map(|(sender, mut vote_map, count, is_validation_request)| {
                let vote_response = response.clone();

                // Handle validation requests separately...
                // TODO: add tests here
                if is_validation_request {
                    // here we send _each_ req back to be validated and processed.
                    // Once a proof has bene found, the sender will be disconnected.
                    // This error is not important
                    let _ = sender.unbounded_send((response.clone(), msg_id));
                }

                // drop the count as we have this new response.
                let current_count = count - 1;

                // get our tally for this response
                let cast_votes = vote_map.remove(&vote_response);

                // if we already have this response, lets vote for it
                if let Some(votes) = cast_votes {
                    trace!("Increasing vote count to {:?}", votes + 1);
                    let _ = vote_map.insert(vote_response, votes + 1);
                } else {
                    // otherwise we add this as a candidate with one vote
                    let _ = vote_map.insert(vote_response, 1);
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

                        let _ = sender.unbounded_send((our_most_popular_response.clone(), msg_id));
                        return;
                    }
                }

                let _ = self.requests.insert(
                    msg_id,
                    (sender, vote_map, current_count, is_validation_request),
                );
            })
            .or_else(|| {
                trace!("No request found for message ID {:?}", msg_id);
                None
            });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // use futures::channel::oneshot;
    use super::*;
    use futures::channel::mpsc;
    use futures::stream::StreamExt;
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    #[tokio::test]
    async fn response_manager_get_response_ok() {
        let response_threshold = 1;

        let mut response_manager = ResponseManager::new(response_threshold);

        // set up a message
        let message_id = safe_nd::MessageId::new();

        let (sender_future, mut response_future) = mpsc::unbounded();
        let expected_responses = 1; // for IData

        // our pseudo data
        let immutable_data = safe_nd::PubImmutableData::new(vec![6]);

        let response = safe_nd::Response::GetIData(Ok(safe_nd::IData::from(immutable_data)));

        response_manager
            .await_responses(message_id, (sender_future, expected_responses, false))
            .unwrap();
        response_manager
            .handle_response(message_id, response.clone())
            .unwrap();

        let (returned_response, _msg_id) = match response_future.next().await {
            Some(res) => Ok(res),
            None => Err("Unexpected error in response handling."),
        }
        .unwrap();

        assert_eq!(&returned_response, &response);
    }

    // basic test to ensure future response is being properly evaluated and our test fails for bad responses
    #[tokio::test]
    async fn response_manager_get_response_fail_with_bad_data() {
        let response_threshold = 1;

        let mut response_manager = ResponseManager::new(response_threshold);

        // set up a message
        let message_id = safe_nd::MessageId::new();

        let (sender_future, mut response_future) = mpsc::unbounded();
        let expected_responses = 1; // for IData

        // our expected data
        let immutable_data = safe_nd::PubImmutableData::new(vec![6]);

        // our nonsense response we receive
        let immutable_data_bad = safe_nd::PubImmutableData::new(vec![7]);

        let response = safe_nd::Response::GetIData(Ok(safe_nd::IData::from(immutable_data)));
        let bad_response =
            safe_nd::Response::GetIData(Ok(safe_nd::IData::from(immutable_data_bad)));

        response_manager
            .await_responses(message_id, (sender_future, expected_responses, false))
            .unwrap();
        response_manager
            .handle_response(message_id, bad_response)
            .unwrap();

        let (returned_response, _msg_id) = match response_future.next().await {
            Some(res) => Ok(res),
            None => Err("Unexpected error in response handling."),
        }
        .unwrap();

        assert_ne!(&returned_response, &response);
    }

    #[tokio::test]
    async fn response_manager_get_success_even_with_some_failed_responses() {
        let response_threshold = 4;

        let mut response_manager = ResponseManager::new(response_threshold);

        // set up a message
        let message_id = safe_nd::MessageId::new();

        let (sender_future, mut response_future) = mpsc::unbounded();

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

        response_manager
            .await_responses(message_id, (sender_future, expected_responses, false))
            .unwrap();

        for resp in responses_to_handle {
            response_manager.handle_response(message_id, resp).unwrap();
        }

        let (returned_response, _msg_id) = match response_future.next().await {
            Some(res) => Ok(res),
            None => Err("Unexpected error in response handling."),
        }
        .unwrap();

        assert_eq!(&returned_response, &response);
    }

    #[tokio::test]
    async fn response_manager_get_fails_even_with_some_success_responses() {
        let response_threshold = 4;

        let mut response_manager = ResponseManager::new(response_threshold);

        // set up a message
        let message_id = safe_nd::MessageId::new();

        let (sender_future, mut response_future) = mpsc::unbounded();

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

        response_manager
            .await_responses(message_id, (sender_future, expected_responses, false))
            .unwrap();

        for resp in responses_to_handle {
            response_manager.handle_response(message_id, resp).unwrap();
        }

        // last response should be bad to ensure we dont just default to it
        response_manager
            .handle_response(message_id, bad_response.clone())
            .unwrap();

        let (returned_response, _msg_id) = match response_future.next().await {
            Some(res) => Ok(res),
            None => Err("Unexpected error in response handling."),
        }
        .unwrap();

        assert_eq!(&returned_response, &bad_response);
    }

    #[tokio::test]
    async fn response_manager_get_with_most_responses_when_nothing_meets_threshold() {
        let response_threshold = 4;

        let mut response_manager = ResponseManager::new(response_threshold);

        // set up a message
        let message_id = safe_nd::MessageId::new();

        let (sender_future, mut response_future) = mpsc::unbounded();

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

        response_manager
            .await_responses(message_id, (sender_future, expected_responses, false))
            .unwrap();

        for resp in responses_to_handle {
            response_manager.handle_response(message_id, resp).unwrap();
        }

        let (returned_response, _msg_id) = match response_future.next().await {
            Some(res) => Ok(res),
            None => Err("Unexpected error in response handling."),
        }
        .unwrap();

        assert_eq!(&returned_response, &response);
    }

    #[tokio::test]
    async fn response_manager_get_with_most_responses_when_divergent_success() {
        let response_threshold = 4;

        let mut response_manager = ResponseManager::new(response_threshold);

        // set up a message
        let message_id = safe_nd::MessageId::new();

        let (sender_future, mut response_future) = mpsc::unbounded();

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

        response_manager
            .await_responses(message_id, (sender_future, expected_responses, false))
            .unwrap();

        for resp in responses_to_handle {
            response_manager.handle_response(message_id, resp).unwrap();
        }

        let (returned_response, _msg_id) = match response_future.next().await {
            Some(res) => Ok(res),
            None => Err("Unexpected error in response handling."),
        }
        .unwrap();

        assert_eq!(&returned_response, &other_response);
    }
}
