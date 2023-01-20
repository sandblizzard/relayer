use crate::{
    domains::utils::{get_key_from_env, SBError},
    external::UnderdogCollection,
    load_keypair,
};
use anchor_client::{
    anchor_lang::{system_program, InstructionData, ToAccountMetas},
    solana_sdk::{
        commitment_config::CommitmentConfig,
        genesis_config::ClusterType,
        pubkey::*,
        signature::{read_keypair, read_keypair_file, Keypair},
        signer::Signer,
    },
    *,
};
use anchor_spl::*;
use regex::Regex;
use spl_associated_token_account::{instruction::create_associated_token_account, *};

use bounty::{self, state::Bounty};
use spl_associated_token_account::get_associated_token_address;
/// Bounty is the SDK for the bounty program
use std::{rc::Rc, result::Result, str::FromStr, sync::Arc};
pub struct BountyWrapped {
    pub amount: Option<f64>,
    pub token_name: Option<String>,
    pub creator: String,
    pub id: u64,
    pub solvers: Option<Vec<Pubkey>>,
    pub state: String,
}

pub fn is_bounty_created(
    domain: &str,
    sub_domain: &str,
    issue_id: &u64,
) -> Result<bounty::state::Bounty, SBError> {
    let (program, cluster) = get_bounty_client()?;
    let bounty_pda = anchor_client::solana_sdk::pubkey::Pubkey::find_program_address(
        &[
            bounty::utils::BOUNTY_SEED.as_bytes().as_ref(),
            domain.as_bytes(),
            sub_domain.as_bytes(),
            issue_id.to_string().as_bytes(),
        ],
        &bounty::ID,
    );

    let bounty = match program.account::<bounty::state::Bounty>(bounty_pda.0) {
        Ok(bounty) => bounty,
        Err(err) => {
            return Err(SBError::BountyDoesNotExistInState(
                bounty_pda.0.to_string(),
                err.to_string(),
            ))
        }
    };

    if bounty.id.eq("") {
        return Err(SBError::BountyDoesNotExistInState(
            bounty_pda.0.to_string(),
            format!(
            "Id of bounty with address {} on cluster={} by program_id={} is empty. Bounty: {:?}",
            bounty_pda.0.to_string(),
            cluster.clone().url().to_string(),
            bounty::id().to_string(),
            bounty
        ),
        ));
    }
    Ok(bounty)
}

pub fn get_bounty_client() -> Result<(Program, Cluster), SBError> {
    let cluster_name = get_key_from_env("CLUSTER").unwrap();

    let payer = load_keypair().unwrap();
    let payer_rc = Rc::new(payer);
    let cluster = match Cluster::from_str(&cluster_name) {
        Ok(res) => res,
        Err(err) => {
            return Err(SBError::CouldNotGetEnvKey(
                "get_program_client".to_string(),
                "CLUSTER".to_string(),
                err.to_string(),
            ))
        }
    };

    let client = anchor_client::Client::new_with_options(
        cluster.clone(),
        payer_rc,
        CommitmentConfig::processed(),
    );
    let program = client.program(bounty::id());
    Ok((program, cluster))
}

impl BountyWrapped {
    /// try_create_bounty will try to store the
    /// bounty in the program
    pub fn try_create_bounty(&self) -> Result<(), SBError> {
        log::info!("[bounty] Try create bounty with id={}", self.id);

        // if bounty is new then
        Ok(())
    }

    /// is_bounty_created
    /// checks if the bounty is created

    /// try_complete_bounty will complete a bounty if solvers
    /// were specified, if not it is deemed cancelled
    pub async fn try_complete_bounty(
        &self,
        domain: &str,
        sub_domain: &str,
        issue_id: &u64,
        bounty_mint: &Pubkey,
    ) -> Result<(), SBError> {
        log::info!(
            "[bounty] Try to complete bounty with id={}, for solvers: {:?}",
            self.id,
            self.solvers.as_ref().unwrap()
        );
        let payer = load_keypair().unwrap();
        let (program, cluster) = get_bounty_client()?;
        // get string of usernames
        let solvers = self.solvers.as_ref().unwrap();
        // get the owner of the nft

        // get pdas

        let protocol =
            Pubkey::find_program_address(&[bounty::utils::BOUNTY_SEED.as_bytes()], &bounty::id());
        let relayer = Pubkey::find_program_address(
            &[
                bounty::utils::BOUNTY_SEED.as_bytes(),
                payer.pubkey().to_bytes().as_ref(),
            ],
            &bounty::id(),
        );

        let bounty_pda = anchor_client::solana_sdk::pubkey::Pubkey::find_program_address(
            &[
                bounty::utils::BOUNTY_SEED.as_bytes().as_ref(),
                domain.as_bytes(),
                sub_domain.as_bytes(),
                issue_id.to_string().as_bytes(),
            ],
            &bounty::ID,
        );

        let escrow = anchor_client::solana_sdk::pubkey::Pubkey::find_program_address(
            &[bounty_pda.0.to_bytes().as_ref()],
            &bounty::id(),
        );

        let fee_collector = associated_token::get_associated_token_address(
            &Pubkey::from_str("CNY467c6XURCPjiXiKRLCvxdRf3bpunagYTJpr685gPv").unwrap(),
            bounty_mint,
        );

        let compelete_bounty_accounts = bounty::accounts::CompleteBounty {
            payer: payer.pubkey(),
            protocol: protocol.0,
            fee_collector,
            relayer: relayer.0,
            bounty: bounty_pda.0,
            escrow: escrow.0,
            solver1: *solvers.get(0).unwrap(),
            solver2: None,
            solver3: None,
            solver4: None,
            system_program: system_program::ID,
            token_program: anchor_spl::token::ID,
        };

        let complete_bounty_data = bounty::instruction::CompleteBounty {};

        let complete_bounty_ix = solana_sdk::instruction::Instruction {
            program_id: bounty::id(),
            accounts: compelete_bounty_accounts.to_account_metas(None),
            data: complete_bounty_data.data(),
        };

        match program.request().instruction(complete_bounty_ix).send() {
            Ok(bounty) => bounty,
            Err(err) => {
                log::info!("Failed to complete bounty: {:?}", err);
                return Err(SBError::FailedToCompleteBounty(
                    "try complete bounty".to_string(),
                    err.to_string(),
                ));
            }
        };

        Ok(())
    }
}

/// get_solvers takes the issue close text and finds the mentioned users
pub async fn get_solvers(
    creator: &str,
    text: &str,
    id: &u64,
    bounty_mint: &Pubkey,
) -> Result<BountyWrapped, SBError> {
    // find user names
    let re = Regex::new(r"@[.^\S]+").unwrap();
    let captures = match re.captures(text) {
        Some(bounty) => bounty,
        None => {
            return Err(SBError::CouldNotGetBountyCapture(
                "could not get text capture".to_string(),
            ))
        }
    };

    let usernames: Vec<String> = captures
        .iter()
        .filter(|x| x.is_some())
        .map(|username| username.unwrap().as_str().replace("@", ""))
        .collect();

    let mut solvers_ata = Vec::new();
    let collection_mint = get_key_from_env("SANDBLIZZARD_COLLECTION_ADDRESS")?;
    let underdog_api = UnderdogCollection::new(&collection_mint);
    for solver in usernames {
        let nft = underdog_api.find_nft_from_name(&solver).await.unwrap();
        let owner = Pubkey::from_str(&nft.owner_address).unwrap();

        // associated token address
        let solver_ata = get_associated_token_address(&owner, &bounty_mint);
        solvers_ata.push(solver_ata);
        // create_associated_token_account(
        //     funding_address,
        //     wallet_address,
        //     token_mint_address,
        //     token_program_id,
        // )
    }
    Ok(BountyWrapped {
        amount: None,
        token_name: None,
        creator: creator.to_string(),
        id: *id,
        solvers: Some(solvers_ata),
        state: "not_started".to_string(),
    })
}

/// get_bounty tries to extract the bounty from
/// the body of a potential bounty item
///
/// Assume bounty in the form $bonk:10.10$
pub fn get_bounty(creator: &str, text: &str, id: &u64) -> Result<BountyWrapped, SBError> {
    let re = Regex::new(r"\$(.+)\$").unwrap();
    let captures = match re.captures(text) {
        Some(bounty) => bounty,
        None => {
            return Err(SBError::CouldNotGetBountyCapture(
                "could not get text capture".to_string(),
            ))
        }
    };

    let first_capture = match captures.get(1) {
        Some(capture) => capture,
        None => {
            return Err(SBError::CouldNotGetBountyCapture(
                "capture was not found".to_string(),
            ))
        }
    };

    let inner_capture: String = first_capture.as_str().replace("$", "");
    let captured_items: Vec<&str> = inner_capture.split(":").collect();
    if captured_items.len() != 2 {
        return Err(SBError::CouldNotFindInnerCapture(format!(
            "expected to capture 2 entitites. Instead captured {:?}",
            captured_items
        )));
    } else {
        // convert amount in floating like 10.10 to 10.10x10^decimals u64
        let amount = match captured_items[1].to_string().parse::<f64>() {
            Ok(amount) => amount,
            Err(err) => {
                return Err(SBError::FailedToConvertStringToNumber(format!(
                    "string={}. Cause: {}",
                    captured_items[0].to_string(),
                    err
                )))
            }
        };
        // return Bounty
        Ok(BountyWrapped {
            amount: Some(amount),
            token_name: Some(captured_items[0].to_string()),
            creator: creator.to_string(),
            id: *id,
            solvers: None,
            state: "not_started".to_string(),
        })
    }
}

#[cfg(test)]
mod test {

    use crate::bounty_wrapper::get_solvers;

    use super::get_bounty;

    #[test]
    pub fn test_get_bounty() {
        let text = "## About
        A bounty contract is needed to reward users for their bounty completion
        
        rewards
        $bonk:10$";

        let owner = "123";
        let id = 1;
        let bounty = get_bounty(owner, text, &id).unwrap();
        assert_eq!(bounty.amount.unwrap(), 10.);
        assert_eq!(bounty.creator, owner);
    }
}
