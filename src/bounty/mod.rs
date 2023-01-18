/// Bounty is the SDK for the bounty program
use std::result::Result;

use crate::domains::utils::SBError;
pub struct Bounty {
    pub amount: Option<u64>,
    pub token_name: Option<String>,
    pub creator: String,
    pub id: u64,
    pub solvers: Option<Vec<String>>,
    pub state: String,
}

impl Bounty {
    /// try_create_bounty will try to store the
    /// bounty in the program
    pub fn try_create_bounty(&self) -> Result<(), SBError> {
        log::info!("[bounty] Try create bounty with id={}", self.id);

        // if bounty is new then
        Ok(())
    }

    /// is_bounty_created
    /// checks if the bounty is created
    pub fn is_bounty_created(&self) -> Result<(), SBError> {
        Err(SBError::BountyDoesNotExistInState)
    }

    /// try_complete_bounty will complete a bounty if solvers
    /// were specified, if not it is deemed cancelled
    pub fn try_complete_bounty(&self) -> Result<(), SBError> {
        log::info!(
            "[bounty] Try to complete bounty with id={}, for solvers: {:?}",
            self.id,
            self.solvers.as_ref().unwrap()
        );
        Ok(())
    }
}
