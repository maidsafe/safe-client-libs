// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! SAFE client example.

// For explanation of lint checks, run `rustc -W help`.
#![deny(unsafe_code)]
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

use clap::{value_t, App, Arg};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use safe_app::{AppError, Client, PubImmutableData};
use safe_authenticator::{AuthClient, Authenticator};
use safe_core::btree_map;
use safe_core::utils;
use safe_nd::{ClientFullId, IData, PublicKey, SeqMutableData, XorName};
use unwrap::unwrap;

fn random_mutable_data<R: Rng>(
    type_tag: u64,
    public_key: &PublicKey,
    rng: &mut R,
) -> SeqMutableData {
    SeqMutableData::new_with_data(
        XorName(rng.gen()),
        type_tag,
        btree_map![],
        btree_map![],
        *public_key,
    )
}

enum Data {
    Mutable(SeqMutableData),
    Immutable(IData),
}

#[tokio::main]
async fn main() {
    unwrap!(safe_core::utils::logging::init(true));

    let matches = App::new("client_stress_test")
        .about(
            "A stress test involving putting and getting immutable and mutable data chunks to the \
             network",
        )
        .arg(
            Arg::with_name("immutable")
                .short("i")
                .long("immutable")
                .takes_value(true)
                .default_value("100")
                .help("Number of PubImmutableData chunks to Put and Get."),
        )
        .arg(
            Arg::with_name("mutable")
                .short("m")
                .long("mutable")
                .takes_value(true)
                .default_value("100")
                .help("Number of MutableData chunks to Put and Get."),
        )
        .arg(
            Arg::with_name("seed")
                .long("seed")
                .takes_value(true)
                .help("Seed for a pseudo-random number generator."),
        )
        .arg(
            Arg::with_name("get-only")
                .long("get-only")
                .requires("seed")
                .help("Only Get the data, don't Put it. Logs in to an existing account."),
        )
        .arg(
            Arg::with_name("locator")
                .short("l")
                .long("locator")
                .takes_value(true)
                .requires("password")
                .help("Use the given Locator for login."),
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .takes_value(true)
                .requires("locator")
                .help("Use the given Password for login."),
        )
        .get_matches();

    let immutable_data_count = unwrap!(value_t!(matches, "immutable", usize));
    let mutable_data_count = unwrap!(value_t!(matches, "mutable", usize));

    let seed = if matches.is_present("seed") {
        unwrap!(value_t!(matches, "seed", u64))
    } else {
        rand::random()
    };
    let mut rng = StdRng::seed_from_u64(seed);

    let get_only = matches.is_present("get-only");

    // Create account
    let (locator, password) = if let (Some(locator), Some(password)) =
        (matches.value_of("locator"), matches.value_of("password"))
    {
        (locator.to_string(), password.to_string())
    } else {
        let new_locator = utils::generate_readable_string_rng(&mut rng, 20);
        let new_password = utils::generate_readable_string_rng(&mut rng, 20);
        println!(
            "A new account will be created.\nLocator: {}\nPassword: {}",
            new_locator, new_password
        );
        (new_locator, new_password)
    };

    let try_login = matches.is_present("locator") && matches.is_present("password");
    let auth = if get_only || try_login {
        println!("\n\tAccount Login");
        println!("\t================");
        println!("\nTrying to login to an account ...");

        unwrap!(Authenticator::login(locator, password, || ()).await)
    } else {
        println!("\n\tAccount Creation");
        println!("\t================");
        println!("\nTrying to create an account ...");

        // FIXME - pass the secret key of the wallet as a parameter
        let client_id = ClientFullId::new_bls(&mut rng);

        let auth = unwrap!(
            Authenticator::create_client_with_acc(
                locator.as_str(),
                password.as_str(),
                client_id,
                || ()
            )
            .await
        );

        println!("Account created!");

        auth
    };

    println!("\nLogged in successfully!");
    println!("Seed: {}", seed);

    let mut stored_data = Vec::with_capacity(mutable_data_count + immutable_data_count);

    for _ in 0..immutable_data_count {
        // Construct data
        let data = PubImmutableData::new(utils::generate_random_vector_rng(&mut rng, 1024));
        println!("{:?}", data.name());
        stored_data.push(Data::Immutable(data.into()));
    }

    let public_key = auth.client.public_key().await;

    for _ in immutable_data_count..(immutable_data_count + mutable_data_count) {
        // Construct data
        let mutable_data = random_mutable_data(100_000, &public_key, &mut rng);
        stored_data.push(Data::Mutable(mutable_data));
    }

    let message = format!(
        "Generated {} items ({} immutable, {} mutable)",
        stored_data.len(),
        immutable_data_count,
        mutable_data_count
    );
    let underline = (0..message.len()).map(|_| "=").collect::<String>();

    println!("\n\t{}\n\t{}", message, underline);

    for (i, data) in stored_data.into_iter().enumerate() {
        let client = auth.client.clone();
        match data {
            Data::Immutable(data) => {
                if !get_only {
                    // Put the data to the network.
                    put_idata(&client, data.clone(), i).await;
                };
                // Get all the chunks again.
                let retrieved_data = unwrap!(client.get_idata(*data.address()).await);
                println!("Retrieved chunk #{}: {:?}", i, data.name());
                assert_eq!(data, retrieved_data);
            }
            Data::Mutable(data) => {
                if !get_only {
                    // Put the data to the network.
                    unwrap!(put_mdata(&client, data.clone(), i).await);
                };

                // TODO(nbaksalyar): stress test mutate_mdata and get_mdata_value here
                // Get all the chunks again.
                let retrieved_data = unwrap!(
                    client
                        .get_seq_mdata_shell(data.name().clone(), data.tag())
                        .await
                );
                assert_eq!(data, retrieved_data);
                println!("Retrieved chunk #{}: {:?}", i, data.name());
            }
        }
    }

    println!("Done");
}

async fn put_idata(client: &AuthClient, data: IData, i: usize) {
    unwrap!(client.put_idata(data.clone()).await);
    println!("Put PubImmutableData chunk #{}: {:?}", i, data.name());

    // Get the data
    let retrieved_data = unwrap!(client.get_idata(*data.address()).await);
    assert_eq!(data, retrieved_data);
    println!(
        "Retrieved PubImmutableData chunk #{}: {:?}",
        i,
        retrieved_data.name()
    );
}

async fn put_mdata(client: &AuthClient, data: SeqMutableData, i: usize) -> Result<(), AppError> {
    client.put_seq_mutable_data(data.clone()).await?;
    println!("Put MutableData chunk #{}: {:?}", i, data.name());

    // Get the data.
    let retrieved_data = client.get_seq_mdata_shell(*data.name(), data.tag()).await?;
    assert_eq!(data, retrieved_data);
    println!(
        "Retrieved MutableData chunk #{}: {:?}",
        i,
        retrieved_data.name()
    );

    Ok(())
}
