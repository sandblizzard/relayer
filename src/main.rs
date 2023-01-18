pub mod bounty;
pub mod domains;
pub mod external;
pub mod jobs;
use std::{thread, time};

use actix_web::{rt::spawn, *};
use anchor_client::anchor_lang::Result;
use domains::{utils::get_key_from_env, *};
pub use jobs::verification;
use jobs::verification::verify_users;

use tokio;

/// try_fetch_indexable_domains
///
/// get all domains that are to be indexed
/// FIXME: get the domains from the bounty contract
pub fn try_fetch_indexable_domains() -> Result<Vec<Domain>> {
    let test_domain = Domain {
        name: "github".to_string(),
        owner: "sandblizzard".to_string(),
        sub_domain_name: "rewards-v1".to_string(),
        bounty_type: "issue".to_string(),
        num_fails: 0,
    };
    let search_domains: Vec<Domain> = [test_domain].to_vec();
    Ok(search_domains)
}

/// sign_create_bounty
///
/// returns a web page for signing a create_bounty tx
#[get("/create_bounty")]
async fn sign_create_bounty() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    spawn(async move {
        loop {
            // index domains for bounties
            let search_domains = try_fetch_indexable_domains().unwrap();
            for domain in &search_domains {
                log::info!("[relayer] try index: {}", domain.name);
                let domain_type = domain.get_type().unwrap();
                match domain_type.handle().await {
                    Ok(_) => log::info!(
                        "[relayer] successfully handled domain={}",
                        domain_type.name()
                    ),
                    Err(err) => log::warn!(
                        "[relayer] failed to handle domain {} with error={}",
                        domain_type.name(),
                        err
                    ),
                }
            }

            // Verify users based on verification file
            match verify_users().await {
                Ok(_) => (),
                Err(err) => {
                    log::warn!("[relayer] failed to verify users with error={}", err)
                }
            };

            // sleep for 5s after each loop
            thread::sleep(time::Duration::from_secs(5));
        }
    });

    HttpServer::new(|| App::new().service(sign_create_bounty))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await?;
    Ok(())
}
