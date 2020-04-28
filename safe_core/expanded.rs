/// Trait providing an interface for self-authentication client implementations, so they can
/// interface all requests from high-level APIs to the actual routing layer and manage all
/// interactions with it. Clients are non-blocking, with an asynchronous API using the futures
/// abstraction from the futures-rs crate.
pub trait Client: Clone + 'static + std::marker::Send + std::marker::Sync {
    /// Associated message type.
    type Context;
    /// Return the client's ID.
    fn full_id(&self) -> SafeKey;
    /// Return the client's public ID.
    fn public_id(&self) -> PublicId {
        self.full_id().public_id()
    }
    /// Returns the client's public key.
    fn public_key(&self) -> PublicKey {
        self.full_id().public_key()
    }
    /// Returns the client's owner key.
    fn owner_key(&self) -> PublicKey;
    /// Return a `crust::Config` if the `Client` was initialized with one.
    fn config(&self) -> Option<BootstrapConfig>;
    /// Return an associated `ClientInner` type which is expected to contain fields associated with
    /// the implementing type.
    fn inner(&self) -> Arc<Mutex<Inner<Client, Client::Context>>>
    where
        Client::Context: Send;
    /// Return the public encryption key.
    fn public_encryption_key(&self) -> threshold_crypto::PublicKey;
    /// Return the secret encryption key.
    fn secret_encryption_key(&self) -> shared_box::SecretKey;
    /// Return the public and secret encryption keys.
    fn encryption_keypair(&self) -> (threshold_crypto::PublicKey, shared_box::SecretKey) {
        (self.public_encryption_key(), self.secret_encryption_key())
    }
    /// Return the symmetric encryption key.
    fn secret_symmetric_key(&self) -> shared_secretbox::Key;
    /// Create a `Message` from the given request.
    /// This function adds the requester signature and message ID.
    fn compose_message(&self, request: Request, sign: bool) -> Message {
        let message_id = MessageId::new();
        let signature = if sign {
            Some(
                self.full_id()
                    .sign(&::unwrap::VerboseUnwrap::verbose_unwrap(
                        bincode::serialize(&(&request, message_id)),
                        None,
                        "safe_core::client",
                        "safe_core/src/client/mod.rs",
                        182u32,
                        28u32,
                    )),
            )
        } else {
            None
        };
        Message::Request {
            request,
            message_id,
            signature,
        }
    }
    /// Set request timeout.
    fn set_timeout(&self, duration: Duration) {
        let inner = self.inner();
        inner.lock().unwrap().timeout = duration;
    }
    /// Restart the client and reconnect to the network.
    fn restart_network(&self) -> Result<(), CoreError> {
        {
            let lvl = ::log::Level::Trace;
            if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                ::log::__private_api_log(
                    ::core::fmt::Arguments::new_v1(
                        &["Restarting the network connection"],
                        &match () {
                            () => [],
                        },
                    ),
                    lvl,
                    &(
                        "safe_core::client",
                        "safe_core::client",
                        "safe_core/src/client/mod.rs",
                        203u32,
                    ),
                );
            }
        };
        let inner = self.inner();
        let mut inner = inner.lock().unwrap();
        inner.connection_manager.restart_network();
        inner.net_tx.unbounded_send(NetworkEvent::Connected)?;
        Ok(())
    }
    /// Put unsequenced mutable data to the network
    #[must_use]
    fn put_unseq_mutable_data<'life0, 'async_trait>(
        &'life0 self,
        data: UnseqMutableData,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<(), CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __put_unseq_mutable_data<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            data: UnseqMutableData,
        ) -> Result<(), CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Put Unsequenced MData at "],
                            &match (&data.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            217u32,
                        ),
                    );
                }
            };
            send_mutation(_self, Request::PutMData(MData::Unseq(data))).await?;
            Ok(())
        }
        Box::pin(__put_unseq_mutable_data::<Self>(self, data))
    }
    /// Transfer coin balance
    #[must_use]
    fn transfer_coins<'life0, 'life1, 'async_trait>(
        &'life0 self,
        client_id: Option<&'life1 ClientFullId>,
        destination: XorName,
        amount: Coins,
        transaction_id: Option<u64>,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<Transaction, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __transfer_coins<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            client_id: Option<&ClientFullId>,
            destination: XorName,
            amount: Coins,
            transaction_id: Option<u64>,
        ) -> Result<Transaction, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Transfer ", " coins to "],
                            &match (&amount, &destination) {
                                (arg0, arg1) => [
                                    ::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Display::fmt),
                                    ::core::fmt::ArgumentV1::new(arg1, ::core::fmt::Debug::fmt),
                                ],
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            230u32,
                        ),
                    );
                }
            };
            match send_as_helper(
                _self,
                Request::TransferCoins {
                    destination,
                    amount,
                    transaction_id: transaction_id.unwrap_or_else(rand::random),
                },
                client_id,
            )
            .await
            {
                Ok(Response::Transaction(result)) => match result {
                    Ok(transaction) => Ok(transaction),
                    Err(error) => Err(CoreError::from(error)),
                },
                Err(error) => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__transfer_coins::<Self>(
            self,
            client_id,
            destination,
            amount,
            transaction_id,
        ))
    }
    /// Creates a new balance on the network.
    #[must_use]
    fn create_balance<'life0, 'life1, 'async_trait>(
        &'life0 self,
        client_id: Option<&'life1 ClientFullId>,
        new_balance_owner: PublicKey,
        amount: Coins,
        transaction_id: Option<u64>,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<Transaction, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __create_balance<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            client_id: Option<&ClientFullId>,
            new_balance_owner: PublicKey,
            amount: Coins,
            transaction_id: Option<u64>,
        ) -> Result<Transaction, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Create a new balance for ", " with ", " coins."],
                            &match (&new_balance_owner, &amount) {
                                (arg0, arg1) => [
                                    ::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt),
                                    ::core::fmt::ArgumentV1::new(arg1, ::core::fmt::Display::fmt),
                                ],
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            259u32,
                        ),
                    );
                }
            };
            match send_as_helper(
                _self,
                Request::CreateBalance {
                    new_balance_owner,
                    amount,
                    transaction_id: transaction_id.unwrap_or_else(rand::random),
                },
                client_id,
            )
            .await
            {
                Ok(res) => match res {
                    Response::Transaction(result) => match result {
                        Ok(transaction) => Ok(transaction),
                        Err(error) => Err(CoreError::from(error)),
                    },
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                },
                Err(error) => Err(CoreError::from(error)),
            }
        }
        Box::pin(__create_balance::<Self>(
            self,
            client_id,
            new_balance_owner,
            amount,
            transaction_id,
        ))
    }
    /// Insert a given login packet at the specified destination
    #[must_use]
    fn insert_login_packet_for<'life0, 'life1, 'async_trait>(
        &'life0 self,
        client_id: Option<&'life1 ClientFullId>,
        new_owner: PublicKey,
        amount: Coins,
        transaction_id: Option<u64>,
        new_login_packet: LoginPacket,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<Transaction, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __insert_login_packet_for<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            client_id: Option<&ClientFullId>,
            new_owner: PublicKey,
            amount: Coins,
            transaction_id: Option<u64>,
            new_login_packet: LoginPacket,
        ) -> Result<Transaction, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &[
                                "Insert a login packet for ",
                                " preloading the wallet with ",
                                " coins.",
                            ],
                            &match (&new_owner, &amount) {
                                (arg0, arg1) => [
                                    ::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt),
                                    ::core::fmt::ArgumentV1::new(arg1, ::core::fmt::Display::fmt),
                                ],
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            300u32,
                        ),
                    );
                }
            };
            let transaction_id = transaction_id.unwrap_or_else(rand::random);
            match send_as_helper(
                _self,
                Request::CreateLoginPacketFor {
                    new_owner,
                    amount,
                    transaction_id,
                    new_login_packet,
                },
                client_id,
            )
            .await
            {
                Ok(res) => match res {
                    Response::Transaction(result) => match result {
                        Ok(transaction) => Ok(transaction),
                        Err(error) => Err(CoreError::from(error)),
                    },
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                },
                Err(error) => Err(CoreError::from(error)),
            }
        }
        Box::pin(__insert_login_packet_for::<Self>(
            self,
            client_id,
            new_owner,
            amount,
            transaction_id,
            new_login_packet,
        ))
    }
    /// Get the current coin balance.
    #[must_use]
    fn get_balance<'life0, 'life1, 'async_trait>(
        &'life0 self,
        client_id: Option<&'life1 ClientFullId>,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<Coins, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_balance<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            client_id: Option<&ClientFullId>,
        ) -> Result<Coins, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Get balance for "],
                            &match (&client_id,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            337u32,
                        ),
                    );
                }
            };
            match send_as_helper(_self, Request::GetBalance, client_id).await {
                Ok(res) => match res {
                    Response::GetBalance(result) => match result {
                        Ok(coins) => Ok(coins),
                        Err(error) => Err(CoreError::from(error)),
                    },
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                },
                Err(error) => Err(CoreError::from(error)),
            }
        }
        Box::pin(__get_balance::<Self>(self, client_id))
    }
    /// Put immutable data to the network.
    #[must_use]
    fn put_idata<'life0, 'async_trait>(
        &'life0 self,
        data: impl Into<IData>,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<(), CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __put_idata<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            data: impl Into<IData>,
        ) -> Result<(), CoreError> {
            let idata: IData = data.into();
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Put IData at "],
                            &match (&idata.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            364u32,
                        ),
                    );
                }
            };
            send_mutation(_self, Request::PutIData(idata)).await
        }
        Box::pin(__put_idata::<Self>(self, data))
    }
    /// Get immutable data from the network. If the data exists locally in the cache then it will be
    /// immediately returned without making an actual network request.
    #[must_use]
    fn get_idata<'life0, 'async_trait>(
        &'life0 self,
        address: IDataAddress,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<IData, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_idata<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: IDataAddress,
        ) -> Result<IData, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Fetch Immutable Data"],
                            &match () {
                                () => [],
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            371u32,
                        ),
                    );
                }
            };
            let inner = _self.inner();
            if let Some(data) = inner.lock().unwrap().cache.get_mut(&address) {
                {
                    let lvl = ::log::Level::Trace;
                    if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                        ::log::__private_api_log(
                            ::core::fmt::Arguments::new_v1(
                                &["ImmutableData found in cache."],
                                &match () {
                                    () => [],
                                },
                            ),
                            lvl,
                            &(
                                "safe_core::client",
                                "safe_core::client",
                                "safe_core/src/client/mod.rs",
                                375u32,
                            ),
                        );
                    }
                };
                return Ok(data.clone());
            }
            let inner = Arc::downgrade(&_self.inner());
            let res = send(_self, Request::GetIData(address)).await?;
            let data = match res {
                Response::GetIData(res) => res.map_err(CoreError::from),
                _ => return Err(CoreError::ReceivedUnexpectedEvent),
            }?;
            if let Some(inner) = inner.upgrade() {
                let _ = inner
                    .lock()
                    .unwrap()
                    .cache
                    .insert(*data.address(), data.clone());
            };
            Ok(data)
        }
        Box::pin(__get_idata::<Self>(self, address))
    }
    /// Delete unpublished immutable data from the network.
    #[must_use]
    fn del_unpub_idata<'life0, 'async_trait>(
        &'life0 self,
        name: XorName,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<(), CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __del_unpub_idata<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            name: XorName,
        ) -> Result<(), CoreError> {
            let inner = _self.inner();
            if inner
                .lock()
                .unwrap()
                .cache
                .remove(&IDataAddress::Unpub(name))
                .is_some()
            {
                {
                    let lvl = ::log::Level::Trace;
                    if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                        ::log::__private_api_log(
                            ::core::fmt::Arguments::new_v1(
                                &["Deleted UnpubImmutableData from cache."],
                                &match () {
                                    () => [],
                                },
                            ),
                            lvl,
                            &(
                                "safe_core::client",
                                "safe_core::client",
                                "safe_core/src/client/mod.rs",
                                405u32,
                            ),
                        );
                    }
                };
            }
            let _ = Arc::downgrade(&_self.inner());
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Delete Unpublished IData at "],
                            &match (&name,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            409u32,
                        ),
                    );
                }
            };
            send_mutation(_self, Request::DeleteUnpubIData(IDataAddress::Unpub(name))).await
        }
        Box::pin(__del_unpub_idata::<Self>(self, name))
    }
    /// Put sequenced mutable data to the network
    #[must_use]
    fn put_seq_mutable_data<'life0, 'async_trait>(
        &'life0 self,
        data: SeqMutableData,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<(), CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __put_seq_mutable_data<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            data: SeqMutableData,
        ) -> Result<(), CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Put Sequenced MData at "],
                            &match (&data.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            415u32,
                        ),
                    );
                }
            };
            send_mutation(_self, Request::PutMData(MData::Seq(data))).await
        }
        Box::pin(__put_seq_mutable_data::<Self>(self, data))
    }
    /// Fetch unpublished mutable data from the network
    #[must_use]
    fn get_unseq_mdata<'life0, 'async_trait>(
        &'life0 self,
        name: XorName,
        tag: u64,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<UnseqMutableData, CoreError>> + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_unseq_mdata<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            name: XorName,
            tag: u64,
        ) -> Result<UnseqMutableData, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Fetch Unsequenced Mutable Data"],
                            &match () {
                                () => [],
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            421u32,
                        ),
                    );
                }
            };
            match send(_self, Request::GetMData(MDataAddress::Unseq { name, tag })).await? {
                Response::GetMData(res) => {
                    res.map_err(CoreError::from).and_then(|mdata| match mdata {
                        MData::Unseq(data) => Ok(data),
                        MData::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_unseq_mdata::<Self>(self, name, tag))
    }
    /// Fetch the value for a given key in a sequenced mutable data
    #[must_use]
    fn get_seq_mdata_value<'life0, 'async_trait>(
        &'life0 self,
        name: XorName,
        tag: u64,
        key: Vec<u8>,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<MDataSeqValue, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_seq_mdata_value<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            name: XorName,
            tag: u64,
            key: Vec<u8>,
        ) -> Result<MDataSeqValue, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Fetch MDataValue for "],
                            &match (&name,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            443u32,
                        ),
                    );
                }
            };
            match send(
                _self,
                Request::GetMDataValue {
                    address: MDataAddress::Seq { name, tag },
                    key,
                },
            )
            .await?
            {
                Response::GetMDataValue(res) => {
                    res.map_err(CoreError::from).and_then(|value| match value {
                        MDataValue::Seq(val) => Ok(val),
                        MDataValue::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_seq_mdata_value::<Self>(self, name, tag, key))
    }
    /// Fetch the value for a given key in a sequenced mutable data
    #[must_use]
    fn get_unseq_mdata_value<'life0, 'async_trait>(
        &'life0 self,
        name: XorName,
        tag: u64,
        key: Vec<u8>,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<Vec<u8>, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_unseq_mdata_value<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            name: XorName,
            tag: u64,
            key: Vec<u8>,
        ) -> Result<Vec<u8>, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Fetch MDataValue for "],
                            &match (&name,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            471u32,
                        ),
                    );
                }
            };
            match send(
                _self,
                Request::GetMDataValue {
                    address: MDataAddress::Unseq { name, tag },
                    key,
                },
            )
            .await?
            {
                Response::GetMDataValue(res) => {
                    res.map_err(CoreError::from).and_then(|value| match value {
                        MDataValue::Unseq(val) => Ok(val),
                        MDataValue::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_unseq_mdata_value::<Self>(self, name, tag, key))
    }
    /// Fetch sequenced mutable data from the network
    #[must_use]
    fn get_seq_mdata<'life0, 'async_trait>(
        &'life0 self,
        name: XorName,
        tag: u64,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<SeqMutableData, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_seq_mdata<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            name: XorName,
            tag: u64,
        ) -> Result<SeqMutableData, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Fetch Sequenced Mutable Data"],
                            &match () {
                                () => [],
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            494u32,
                        ),
                    );
                }
            };
            match send(_self, Request::GetMData(MDataAddress::Seq { name, tag })).await? {
                Response::GetMData(res) => {
                    res.map_err(CoreError::from).and_then(|mdata| match mdata {
                        MData::Seq(data) => Ok(data),
                        MData::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_seq_mdata::<Self>(self, name, tag))
    }
    /// Mutates sequenced `MutableData` entries in bulk
    #[must_use]
    fn mutate_seq_mdata_entries<'life0, 'async_trait>(
        &'life0 self,
        name: XorName,
        tag: u64,
        actions: MDataSeqEntryActions,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<(), CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __mutate_seq_mdata_entries<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            name: XorName,
            tag: u64,
            actions: MDataSeqEntryActions,
        ) -> Result<(), CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Mutate MData for "],
                            &match (&name,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            516u32,
                        ),
                    );
                }
            };
            send_mutation(
                _self,
                Request::MutateMDataEntries {
                    address: MDataAddress::Seq { name, tag },
                    actions: MDataEntryActions::Seq(actions),
                },
            )
            .await
        }
        Box::pin(__mutate_seq_mdata_entries::<Self>(self, name, tag, actions))
    }
    /// Mutates unsequenced `MutableData` entries in bulk
    fn mutate_unseq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
        actions: MDataUnseqEntryActions,
    ) -> Result<(), CoreError> {
        {
            let lvl = ::log::Level::Trace;
            if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                ::log::__private_api_log(
                    ::core::fmt::Arguments::new_v1(
                        &["Mutate MData for "],
                        &match (&name,) {
                            (arg0,) => {
                                [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                            }
                        },
                    ),
                    lvl,
                    &(
                        "safe_core::client",
                        "safe_core::client",
                        "safe_core/src/client/mod.rs",
                        534u32,
                    ),
                );
            }
        };
        send_mutation(
            self,
            Request::MutateMDataEntries {
                address: MDataAddress::Unseq { name, tag },
                actions: MDataEntryActions::Unseq(actions),
            },
        )
    }
    /// Get a shell (bare bones) version of `MutableData` from the network.
    #[must_use]
    fn get_seq_mdata_shell<'life0, 'async_trait>(
        &'life0 self,
        name: XorName,
        tag: u64,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<SeqMutableData, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_seq_mdata_shell<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            name: XorName,
            tag: u64,
        ) -> Result<SeqMutableData, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["GetMDataShell for "],
                            &match (&name,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            547u32,
                        ),
                    );
                }
            };
            match send(
                _self,
                Request::GetMDataShell(MDataAddress::Seq { name, tag }),
            )
            .await?
            {
                Response::GetMDataShell(res) => {
                    res.map_err(CoreError::from).and_then(|mdata| match mdata {
                        MData::Seq(data) => Ok(data),
                        _ => Err(CoreError::ReceivedUnexpectedData),
                    })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_seq_mdata_shell::<Self>(self, name, tag))
    }
    /// Get a shell (bare bones) version of `MutableData` from the network.
    #[must_use]
    fn get_unseq_mdata_shell<'life0, 'async_trait>(
        &'life0 self,
        name: XorName,
        tag: u64,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<UnseqMutableData, CoreError>> + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_unseq_mdata_shell<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            name: XorName,
            tag: u64,
        ) -> Result<UnseqMutableData, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["GetMDataShell for "],
                            &match (&name,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            565u32,
                        ),
                    );
                }
            };
            match send(
                _self,
                Request::GetMDataShell(MDataAddress::Unseq { name, tag }),
            )
            .await?
            {
                Response::GetMDataShell(res) => {
                    res.map_err(CoreError::from).and_then(|mdata| match mdata {
                        MData::Unseq(data) => Ok(data),
                        _ => Err(CoreError::ReceivedUnexpectedData),
                    })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_unseq_mdata_shell::<Self>(self, name, tag))
    }
    /// Get a current version of `MutableData` from the network.
    #[must_use]
    fn get_mdata_version<'life0, 'async_trait>(
        &'life0 self,
        address: MDataAddress,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<u64, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_mdata_version<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: MDataAddress,
        ) -> Result<u64, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["GetMDataVersion for "],
                            &match (&address,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            583u32,
                        ),
                    );
                }
            };
            match send(_self, Request::GetMDataVersion(address)).await? {
                Response::GetMDataVersion(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_mdata_version::<Self>(self, address))
    }
    /// Return a complete list of entries in `MutableData`.
    #[must_use]
    fn list_unseq_mdata_entries<'life0, 'async_trait>(
        &'life0 self,
        name: XorName,
        tag: u64,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<BTreeMap<Vec<u8>, Vec<u8>>, CoreError>>
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __list_unseq_mdata_entries<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            name: XorName,
            tag: u64,
        ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["ListMDataEntries for "],
                            &match (&name,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            597u32,
                        ),
                    );
                }
            };
            match send(
                _self,
                Request::ListMDataEntries(MDataAddress::Unseq { name, tag }),
            )
            .await?
            {
                Response::ListMDataEntries(res) => {
                    res.map_err(CoreError::from)
                        .and_then(|entries| match entries {
                            MDataEntries::Unseq(data) => Ok(data),
                            MDataEntries::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                        })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__list_unseq_mdata_entries::<Self>(self, name, tag))
    }
    /// Return a complete list of entries in `MutableData`.
    #[must_use]
    fn list_seq_mdata_entries<'life0, 'async_trait>(
        &'life0 self,
        name: XorName,
        tag: u64,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<MDataSeqEntries, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __list_seq_mdata_entries<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            name: XorName,
            tag: u64,
        ) -> Result<MDataSeqEntries, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["ListSeqMDataEntries for "],
                            &match (&name,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            616u32,
                        ),
                    );
                }
            };
            match send(
                _self,
                Request::ListMDataEntries(MDataAddress::Seq { name, tag }),
            )
            .await?
            {
                Response::ListMDataEntries(res) => {
                    res.map_err(CoreError::from)
                        .and_then(|entries| match entries {
                            MDataEntries::Seq(data) => Ok(data),
                            MDataEntries::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                        })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__list_seq_mdata_entries::<Self>(self, name, tag))
    }
    /// Return a list of keys in `MutableData` stored on the network.
    #[must_use]
    fn list_mdata_keys<'life0, 'async_trait>(
        &'life0 self,
        address: MDataAddress,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<BTreeSet<Vec<u8>>, CoreError>>
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __list_mdata_keys<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: MDataAddress,
        ) -> Result<BTreeSet<Vec<u8>>, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["ListMDataKeys for "],
                            &match (&address,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            637u32,
                        ),
                    );
                }
            };
            match send(_self, Request::ListMDataKeys(address)).await? {
                Response::ListMDataKeys(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__list_mdata_keys::<Self>(self, address))
    }
    /// Return a list of values in a Sequenced Mutable Data
    #[must_use]
    fn list_seq_mdata_values<'life0, 'async_trait>(
        &'life0 self,
        name: XorName,
        tag: u64,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<Vec<MDataSeqValue>, CoreError>>
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __list_seq_mdata_values<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            name: XorName,
            tag: u64,
        ) -> Result<Vec<MDataSeqValue>, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["List MDataValues for "],
                            &match (&name,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            651u32,
                        ),
                    );
                }
            };
            match send(
                _self,
                Request::ListMDataValues(MDataAddress::Seq { name, tag }),
            )
            .await?
            {
                Response::ListMDataValues(res) => {
                    res.map_err(CoreError::from)
                        .and_then(|values| match values {
                            MDataValues::Seq(data) => Ok(data),
                            MDataValues::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                        })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__list_seq_mdata_values::<Self>(self, name, tag))
    }
    /// Return the permissions set for a particular user
    #[must_use]
    fn list_mdata_user_permissions<'life0, 'async_trait>(
        &'life0 self,
        address: MDataAddress,
        user: PublicKey,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<MDataPermissionSet, CoreError>>
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __list_mdata_user_permissions<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: MDataAddress,
            user: PublicKey,
        ) -> Result<MDataPermissionSet, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["GetMDataUserPermissions for "],
                            &match (&address,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            674u32,
                        ),
                    );
                }
            };
            match send(_self, Request::ListMDataUserPermissions { address, user }).await? {
                Response::ListMDataUserPermissions(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__list_mdata_user_permissions::<Self>(self, address, user))
    }
    /// Returns a list of values in an Unsequenced Mutable Data
    #[must_use]
    fn list_unseq_mdata_values<'life0, 'async_trait>(
        &'life0 self,
        name: XorName,
        tag: u64,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<Vec<Vec<u8>>, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __list_unseq_mdata_values<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            name: XorName,
            tag: u64,
        ) -> Result<Vec<Vec<u8>>, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["List MDataValues for "],
                            &match (&name,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            684u32,
                        ),
                    );
                }
            };
            match send(
                _self,
                Request::ListMDataValues(MDataAddress::Unseq { name, tag }),
            )
            .await?
            {
                Response::ListMDataValues(res) => {
                    res.map_err(CoreError::from)
                        .and_then(|values| match values {
                            MDataValues::Unseq(data) => Ok(data),
                            MDataValues::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                        })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__list_unseq_mdata_values::<Self>(self, name, tag))
    }
    /// Put AppendOnly Data into the Network
    #[must_use]
    fn put_adata<'life0, 'async_trait>(
        &'life0 self,
        data: AData,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<(), CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __put_adata<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            data: AData,
        ) -> Result<(), CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Put AppendOnly Data "],
                            &match (&data.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            704u32,
                        ),
                    );
                }
            };
            send_mutation(_self, Request::PutAData(data)).await
        }
        Box::pin(__put_adata::<Self>(self, data))
    }
    /// Get AppendOnly Data from the Network
    #[must_use]
    fn get_adata<'life0, 'async_trait>(
        &'life0 self,
        address: ADataAddress,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<AData, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_adata<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: ADataAddress,
        ) -> Result<AData, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Get AppendOnly Data at "],
                            &match (&address.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            710u32,
                        ),
                    );
                }
            };
            match send(_self, Request::GetAData(address)).await? {
                Response::GetAData(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_adata::<Self>(self, address))
    }
    /// Get AppendOnly Data Shell from the Network
    #[must_use]
    fn get_adata_shell<'life0, 'async_trait>(
        &'life0 self,
        data_index: ADataIndex,
        address: ADataAddress,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<AData, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_adata_shell<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            data_index: ADataIndex,
            address: ADataAddress,
        ) -> Result<AData, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Get AppendOnly Data at "],
                            &match (&address.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            724u32,
                        ),
                    );
                }
            };
            match send(
                _self,
                Request::GetADataShell {
                    address,
                    data_index,
                },
            )
            .await?
            {
                Response::GetADataShell(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_adata_shell::<Self>(self, data_index, address))
    }
    /// Fetch Value for the provided key from AppendOnly Data at {:?}
    #[must_use]
    fn get_adata_value<'life0, 'async_trait>(
        &'life0 self,
        address: ADataAddress,
        key: Vec<u8>,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<Vec<u8>, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_adata_value<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: ADataAddress,
            key: Vec<u8>,
        ) -> Result<Vec<u8>, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Fetch Value for the provided key from AppendOnly Data at "],
                            &match (&address.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            740u32,
                        ),
                    );
                }
            };
            match send(_self, Request::GetADataValue { address, key }).await? {
                Response::GetADataValue(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_adata_value::<Self>(self, address, key))
    }
    /// Get a Set of Entries for the requested range from an AData.
    #[must_use]
    fn get_adata_range<'life0, 'async_trait>(
        &'life0 self,
        address: ADataAddress,
        range: (ADataIndex, ADataIndex),
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<ADataEntries, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_adata_range<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: ADataAddress,
            range: (ADataIndex, ADataIndex),
        ) -> Result<ADataEntries, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Get Range of entries from AppendOnly Data at "],
                            &match (&address.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            757u32,
                        ),
                    );
                }
            };
            match send(_self, Request::GetADataRange { address, range }).await? {
                Response::GetADataRange(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_adata_range::<Self>(self, address, range))
    }
    /// Get latest indices from an AppendOnly Data.
    #[must_use]
    fn get_adata_indices<'life0, 'async_trait>(
        &'life0 self,
        address: ADataAddress,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<ADataIndices, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_adata_indices<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: ADataAddress,
        ) -> Result<ADataIndices, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Get latest indices from AppendOnly Data at "],
                            &match (&address.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            770u32,
                        ),
                    );
                }
            };
            match send(_self, Request::GetADataIndices(address)).await? {
                Response::GetADataIndices(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_adata_indices::<Self>(self, address))
    }
    /// Get the last data entry from an AppendOnly Data.
    #[must_use]
    fn get_adata_last_entry<'life0, 'async_trait>(
        &'life0 self,
        address: ADataAddress,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<ADataEntry, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_adata_last_entry<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: ADataAddress,
        ) -> Result<ADataEntry, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Get latest indices from AppendOnly Data at "],
                            &match (&address.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            783u32,
                        ),
                    );
                }
            };
            match send(_self, Request::GetADataLastEntry(address)).await? {
                Response::GetADataLastEntry(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_adata_last_entry::<Self>(self, address))
    }
    /// Get permissions at the provided index.
    #[must_use]
    fn get_unpub_adata_permissions_at_index<'life0, 'async_trait>(
        &'life0 self,
        address: ADataAddress,
        permissions_index: ADataIndex,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<ADataUnpubPermissions, CoreError>>
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_unpub_adata_permissions_at_index<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: ADataAddress,
            permissions_index: ADataIndex,
        ) -> Result<ADataUnpubPermissions, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Get latest indices from AppendOnly Data at "],
                            &match (&address.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            805u32,
                        ),
                    );
                }
            };
            match send(
                _self,
                Request::GetADataPermissions {
                    address,
                    permissions_index,
                },
            )
            .await?
            {
                Response::GetADataPermissions(res) => {
                    res.map_err(CoreError::from)
                        .and_then(|permissions| match permissions {
                            ADataPermissions::Unpub(data) => Ok(data),
                            ADataPermissions::Pub(_) => Err(CoreError::ReceivedUnexpectedData),
                        })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_unpub_adata_permissions_at_index::<Self>(
            self,
            address,
            permissions_index,
        ))
    }
    /// Get permissions at the provided index.
    #[must_use]
    fn get_pub_adata_permissions_at_index<'life0, 'async_trait>(
        &'life0 self,
        address: ADataAddress,
        permissions_index: ADataIndex,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<ADataPubPermissions, CoreError>>
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_pub_adata_permissions_at_index<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: ADataAddress,
            permissions_index: ADataIndex,
        ) -> Result<ADataPubPermissions, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Get latest indices from AppendOnly Data at "],
                            &match (&address.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            836u32,
                        ),
                    );
                }
            };
            match send(
                _self,
                Request::GetADataPermissions {
                    address,
                    permissions_index,
                },
            )
            .await?
            {
                Response::GetADataPermissions(res) => {
                    res.map_err(CoreError::from)
                        .and_then(|permissions| match permissions {
                            ADataPermissions::Pub(data) => Ok(data),
                            ADataPermissions::Unpub(_) => Err(CoreError::ReceivedUnexpectedData),
                        })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_pub_adata_permissions_at_index::<Self>(
            self,
            address,
            permissions_index,
        ))
    }
    /// Get permissions for a specified user(s).
    #[must_use]
    fn get_pub_adata_user_permissions<'life0, 'async_trait>(
        &'life0 self,
        address: ADataAddress,
        permissions_index: ADataIndex,
        user: ADataUser,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<ADataPubPermissionSet, CoreError>>
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_pub_adata_user_permissions<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: ADataAddress,
            permissions_index: ADataIndex,
            user: ADataUser,
        ) -> Result<ADataPubPermissionSet, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Get permissions for a specified user(s) from AppendOnly Data at "],
                            &match (&address.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            866u32,
                        ),
                    );
                }
            };
            match send(
                _self,
                Request::GetPubADataUserPermissions {
                    address,
                    permissions_index,
                    user,
                },
            )
            .await?
            {
                Response::GetPubADataUserPermissions(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_pub_adata_user_permissions::<Self>(
            self,
            address,
            permissions_index,
            user,
        ))
    }
    /// Get permissions for a specified user(s).
    #[must_use]
    fn get_unpub_adata_user_permissions<'life0, 'async_trait>(
        &'life0 self,
        address: ADataAddress,
        permissions_index: ADataIndex,
        public_key: PublicKey,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<ADataUnpubPermissionSet, CoreError>>
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_unpub_adata_user_permissions<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: ADataAddress,
            permissions_index: ADataIndex,
            public_key: PublicKey,
        ) -> Result<ADataUnpubPermissionSet, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Get permissions for a specified user(s) from AppendOnly Data at "],
                            &match (&address.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            891u32,
                        ),
                    );
                }
            };
            match send(
                _self,
                Request::GetUnpubADataUserPermissions {
                    address,
                    permissions_index,
                    public_key,
                },
            )
            .await?
            {
                Response::GetUnpubADataUserPermissions(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_unpub_adata_user_permissions::<Self>(
            self,
            address,
            permissions_index,
            public_key,
        ))
    }
    /// Add AData Permissions
    #[must_use]
    fn add_unpub_adata_permissions<'life0, 'async_trait>(
        &'life0 self,
        address: ADataAddress,
        permissions: ADataUnpubPermissions,
        permissions_index: u64,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<(), CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __add_unpub_adata_permissions<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: ADataAddress,
            permissions: ADataUnpubPermissions,
            permissions_index: u64,
        ) -> Result<(), CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Add Permissions to UnPub AppendOnly Data "],
                            &match (&address.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            916u32,
                        ),
                    );
                }
            };
            send_mutation(
                _self,
                Request::AddUnpubADataPermissions {
                    address,
                    permissions,
                    permissions_index,
                },
            )
            .await
        }
        Box::pin(__add_unpub_adata_permissions::<Self>(
            self,
            address,
            permissions,
            permissions_index,
        ))
    }
    /// Add Pub AData Permissions
    #[must_use]
    fn add_pub_adata_permissions<'life0, 'async_trait>(
        &'life0 self,
        address: ADataAddress,
        permissions: ADataPubPermissions,
        permissions_index: u64,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<(), CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __add_pub_adata_permissions<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: ADataAddress,
            permissions: ADataPubPermissions,
            permissions_index: u64,
        ) -> Result<(), CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Add Permissions to AppendOnly Data "],
                            &match (&address.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            938u32,
                        ),
                    );
                }
            };
            send_mutation(
                _self,
                Request::AddPubADataPermissions {
                    address,
                    permissions,
                    permissions_index,
                },
            )
            .await
        }
        Box::pin(__add_pub_adata_permissions::<Self>(
            self,
            address,
            permissions,
            permissions_index,
        ))
    }
    /// Set new Owners to AData
    #[must_use]
    fn set_adata_owners<'life0, 'async_trait>(
        &'life0 self,
        address: ADataAddress,
        owner: ADataOwner,
        owners_index: u64,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<(), CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __set_adata_owners<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: ADataAddress,
            owner: ADataOwner,
            owners_index: u64,
        ) -> Result<(), CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Set Owners to AppendOnly Data "],
                            &match (&address.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            957u32,
                        ),
                    );
                }
            };
            send_mutation(
                _self,
                Request::SetADataOwner {
                    address,
                    owner,
                    owners_index,
                },
            )
            .await
        }
        Box::pin(__set_adata_owners::<Self>(
            self,
            address,
            owner,
            owners_index,
        ))
    }
    /// Set new Owners to AData
    #[must_use]
    fn get_adata_owners<'life0, 'async_trait>(
        &'life0 self,
        address: ADataAddress,
        owners_index: ADataIndex,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<ADataOwner, CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __get_adata_owners<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: ADataAddress,
            owners_index: ADataIndex,
        ) -> Result<ADataOwner, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["Get Owners from AppendOnly Data at "],
                            &match (&address.name(),) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            975u32,
                        ),
                    );
                }
            };
            match send(
                _self,
                Request::GetADataOwners {
                    address,
                    owners_index,
                },
            )
            .await?
            {
                Response::GetADataOwners(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__get_adata_owners::<Self>(self, address, owners_index))
    }
    /// Append to Published Seq AppendOnly Data
    #[must_use]
    fn append_seq_adata<'life0, 'async_trait>(
        &'life0 self,
        append: ADataAppendOperation,
        index: u64,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<(), CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __append_seq_adata<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            append: ADataAppendOperation,
            index: u64,
        ) -> Result<(), CoreError> {
            send_mutation(_self, Request::AppendSeq { append, index }).await
        }
        Box::pin(__append_seq_adata::<Self>(self, append, index))
    }
    /// Append to Unpublished Unseq AppendOnly Data
    #[must_use]
    fn append_unseq_adata<'life0, 'async_trait>(
        &'life0 self,
        append: ADataAppendOperation,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<(), CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __append_unseq_adata<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            append: ADataAppendOperation,
        ) -> Result<(), CoreError> {
            send_mutation(_self, Request::AppendUnseq(append)).await
        }
        Box::pin(__append_unseq_adata::<Self>(self, append))
    }
    /// Return a list of permissions in `MutableData` stored on the network.
    #[must_use]
    fn list_mdata_permissions<'life0, 'async_trait>(
        &'life0 self,
        address: MDataAddress,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<
                    Output = Result<BTreeMap<PublicKey, MDataPermissionSet>, CoreError>,
                > + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __list_mdata_permissions<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: MDataAddress,
        ) -> Result<BTreeMap<PublicKey, MDataPermissionSet>, CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["List MDataPermissions for "],
                            &match (&address,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            1004u32,
                        ),
                    );
                }
            };
            match send(_self, Request::ListMDataPermissions(address)).await? {
                Response::ListMDataPermissions(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        }
        Box::pin(__list_mdata_permissions::<Self>(self, address))
    }
    /// Updates or inserts a permissions set for a user
    #[must_use]
    fn set_mdata_user_permissions<'life0, 'async_trait>(
        &'life0 self,
        address: MDataAddress,
        user: PublicKey,
        permissions: MDataPermissionSet,
        version: u64,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<(), CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __set_mdata_user_permissions<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: MDataAddress,
            user: PublicKey,
            permissions: MDataPermissionSet,
            version: u64,
        ) -> Result<(), CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["SetMDataUserPermissions for "],
                            &match (&address,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            1021u32,
                        ),
                    );
                }
            };
            send_mutation(
                _self,
                Request::SetMDataUserPermissions {
                    address,
                    user,
                    permissions,
                    version,
                },
            )
            .await
        }
        Box::pin(__set_mdata_user_permissions::<Self>(
            self,
            address,
            user,
            permissions,
            version,
        ))
    }
    /// Updates or inserts a permissions set for a user
    #[must_use]
    fn del_mdata_user_permissions<'life0, 'async_trait>(
        &'life0 self,
        address: MDataAddress,
        user: PublicKey,
        version: u64,
    ) -> ::core::pin::Pin<
        Box<dyn ::core::future::Future<Output = Result<(), CoreError>> + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        #[allow(
            clippy::missing_docs_in_private_items,
            clippy::type_repetition_in_bounds,
            clippy::used_underscore_binding
        )]
        async fn __del_mdata_user_permissions<AsyncTrait: ?Sized + Client>(
            _self: &AsyncTrait,
            address: MDataAddress,
            user: PublicKey,
            version: u64,
        ) -> Result<(), CoreError> {
            {
                let lvl = ::log::Level::Trace;
                if lvl <= ::log::STATIC_MAX_LEVEL && lvl <= ::log::max_level() {
                    ::log::__private_api_log(
                        ::core::fmt::Arguments::new_v1(
                            &["DelMDataUserPermissions for "],
                            &match (&address,) {
                                (arg0,) => {
                                    [::core::fmt::ArgumentV1::new(arg0, ::core::fmt::Debug::fmt)]
                                }
                            },
                        ),
                        lvl,
                        &(
                            "safe_core::client",
                            "safe_core::client",
                            "safe_core/src/client/mod.rs",
                            1041u32,
                        ),
                    );
                }
            };
            send_mutation(
                _self,
                Request::DelMDataUserPermissions {
                    address,
                    user,
                    version,
                },
            )
            .await
        }
        Box::pin(__del_mdata_user_permissions::<Self>(
            self, address, user, version,
        ))
    }
    /// Sends an ownership transfer request.
    #[allow(unused)]
    fn change_mdata_owner(
        &self,
        name: XorName,
        tag: u64,
        new_owner: PublicKey,
        version: u64,
    ) -> Result<(), CoreError> {
        {
            ::std::rt::begin_panic("not implemented")
        };
    }
}
