use std::{fmt::format, rc::Rc, result::Result, sync::Arc};

use super::{
    utils::{get_key_from_env, SBError},
    Domain, DomainHandler,
};
use crate::bounty_wrapper::{get_bounty, get_bounty_wrapper, get_solvers, BountyWrapped};
use anchor_client::{Client, Program};
use async_trait::async_trait;
use bounty;
use octocrab::{
    issues::IssueHandler,
    models::{
        issues::{Comment, Issue},
        IssueId, IssueState,
    },
    params::apps::CreateInstallationAccessToken,
    *,
};
use tokio::sync::Mutex;
pub struct Github {
    pub domain: Domain,
}

#[async_trait]
impl DomainHandler for Github {
    async fn handle(&self) -> Result<(), SBError> {
        match self.domain.bounty_type.as_str() {
            "issue" => self.issues().await,
            _ => Err(SBError::UndefinedBountyType(format!(
                "could not find {} type",
                self.domain.bounty_type.as_str()
            ))),
        }
    }

    fn name(&self) -> String {
        return "github".to_string();
    }
}

pub fn is_relayer_login(login: &str) -> Result<bool, SBError> {
    let app_login = get_key_from_env("GITHUB_APP_LOGIN")?;
    Ok(login.eq(&app_login))
}

/// get_connection establish a connection with github
pub async fn get_connection() -> Result<Octocrab, SBError> {
    let github_key = get_key_from_env("GITHUB_KEY")?;
    let github_id = get_key_from_env("GITHUB_ID")?;

    let app_id = github_id.parse::<u64>().unwrap().into();
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(github_key.as_bytes()).unwrap();
    let token = octocrab::auth::create_jwt(app_id, &key).unwrap();
    let gh = Octocrab::builder().personal_token(token).build().unwrap();
    let installations = match gh.apps().installations().send().await {
        Ok(mut res) => res.take_items(),
        Err(err) => return Err(SBError::FailedToGetGithubInstallations(err.to_string())),
    };
    let access_token = CreateInstallationAccessToken::default();

    let access: models::InstallationToken = gh
        .post(
            installations[0].access_tokens_url.as_ref().unwrap(),
            Some(&access_token),
        )
        .await
        .unwrap();
    Ok(octocrab::OctocrabBuilder::new()
        .personal_token(access.token)
        .build()
        .unwrap())
}

impl Github {
    async fn try_get_bounty_from_issue(&self, issue: &Issue) -> Result<BountyWrapped, SBError> {
        let issue_body = match issue.body.as_ref() {
            Some(body) => body,
            None => {
                return Err(SBError::FailedToFindBounty(
                    "No body found on issue".to_string(),
                ))
            }
        };

        // index the bounty information
        let bounty = match get_bounty_wrapper(&issue.user.id.to_string(), issue_body, &issue.id.0) {
            Ok(bounty) => bounty,
            Err(err) => return Err(SBError::FailedToFindBounty(err.to_string())),
        };

        Ok(bounty)
    }

    /// try_get_sandblizzard confirmation
    ///
    /// when an issue is closed and the app has completed the
    /// bounty then a message is emitted

    /// try_get_closing_comment
    ///
    /// will try to get the comments associated with the closing of
    /// an issue
    async fn try_get_closing_comment<'a>(
        &self,
        issue: &Issue,
        comments: Vec<Comment>,
    ) -> Result<String, SBError> {
        // get comments on issue

        let issue_closed_at = match issue.closed_at {
            Some(timestamp) => timestamp,
            None => return Err(SBError::IssueNotClosed),
        };
        // filter comments at closing
        let comments: Vec<&Comment> = comments
            .iter()
            .filter(|comment| comment.created_at.eq(&issue_closed_at))
            .collect();

        // take first closed comment
        let first_close_issue_comment = match comments.first() {
            Some(comment) => comment,
            None => {
                return Err(SBError::CommentNotFound(
                    "closed issue".to_string(),
                    "".to_string(),
                ))
            }
        };

        let comment_body = match first_close_issue_comment.body.as_ref() {
            Some(comment) => comment,
            None => {
                return Err(SBError::CommentNotFound(
                    "closed body issue".to_string(),
                    "Comment body not found".to_string(),
                ))
            }
        };
        Ok(comment_body.clone())
    }

    /// comment_contains_signing_link
    ///
    /// checks if a comment contains the sandblizzard domain
    pub fn comment_contains_signing_link(&self, comment: &Comment) -> Result<bool, SBError> {
        let comment_body = match &comment.body {
            Some(body) => body,
            None => return Ok(false),
        };
        let sb_bounty_domain = get_key_from_env("SANDBLIZZARD_URL")?;
        Ok(comment_body.contains(&sb_bounty_domain))
    }

    pub fn get_signing_link(
        &self,
        issue_id: &u64,
        issue_number: &i64,
        bounty_amount: &f64,
    ) -> Result<String, SBError> {
        let sb_bounty_domain = get_key_from_env("SANDBLIZZARD_URL")?;

        let referrer = format!(
            "https://github.com/{}/{}/issues/{}",
            self.domain.owner, self.domain.sub_domain_name, issue_number
        );
        Ok(format!(
            "Create bounty by signing: [Transaction]({}/create_bounty?referrer={}&domain={}&subDomain={}&id={}&bountyAmount={})",
            sb_bounty_domain,referrer, self.domain.owner, self.domain.sub_domain_name, issue_id,bounty_amount
        ))
    }

    ///FIXME: don't post twice
    pub fn contains_bounty_status(&self, comment: &Comment, bounty_status: &str) -> bool {
        let comment_body = match &comment.body {
            Some(body) => body,
            None => return false,
        };
        bounty_status.contains(comment_body)
    }

    pub fn create_bounty_status_text(
        &self,
        bounty: &bounty::state::Bounty,
    ) -> Result<String, SBError> {
        Ok(format!(
            "Bounty status: **{}**",
            bounty.state.to_uppercase()
        ))
    }

    pub async fn try_post_bounty_status(
        &self,
        gh: &Octocrab,
        issue_number: &i64,
        issue_id: &u64,
        bounty: &bounty::state::Bounty,
        comments: &Vec<&Comment>,
    ) -> Result<(), SBError> {
        let bounty_status = self.create_bounty_status_text(bounty)?;

        if comments
            .iter()
            .any(|comment| self.contains_bounty_status(comment, &bounty_status))
        {
            return Ok(());
        } else {
            log::info!("Post bounty status {} for {}", bounty_status, issue_number);
            self.post_bounty_status(gh, issue_number, issue_id, bounty)
                .await
        }
    }

    pub async fn post_bounty_status(
        &self,
        gh: &Octocrab,
        issue_number: &i64,
        issue_id: &u64,
        bounty: &bounty::state::Bounty,
    ) -> Result<(), SBError> {
        log::info!(
            "[relayer] try to post bounty statu for issue_id: {} ",
            issue_id
        );

        let bounty_status = self.create_bounty_status_text(bounty)?;
        return match gh
            .issues(&self.domain.owner, &self.domain.sub_domain_name)
            .create_comment(*issue_number, bounty_status)
            .await
        {
            Ok(comment) => {
                log::info!(
                    "[relayer] successfully created comment {}",
                    comment.issue_url.unwrap()
                );
                Ok(())
            }
            Err(err) => Err(SBError::FailedToComment(
                "post_bounty_status".to_string(),
                err.to_string(),
            )),
        };
    }

    /// create_signing_link
    ///
    /// creates a link with enough query params to create a `create_bounty` tx
    async fn post_signing_link(
        &self,
        gh: &Octocrab,
        issue_number: &i64,
        issue_id: &u64,
        bounty_amount: &f64,
    ) -> Result<(), SBError> {
        log::info!(
            "[relayer] try to create signing link for issue id: {} ",
            issue_id
        );
        return match gh
            .issues(&self.domain.owner, &self.domain.sub_domain_name)
            .create_comment(
                *issue_number,
                self.get_signing_link(issue_id, issue_number, bounty_amount)?,
            )
            .await
        {
            Ok(comment) => {
                log::info!(
                    "[relayer] successfully created comment {}",
                    comment.issue_url.unwrap()
                );
                Ok(())
            }
            Err(err) => Err(SBError::FailedToComment(
                "create_signing_link".to_string(),
                err.to_string(),
            )),
        };
    }

    /// issues
    ///
    /// Handles the github issues
    async fn issues(&self) -> Result<(), SBError> {
        log::info!(
            "[relayer] Index github issue for domain={}, repo={} ",
            self.domain.owner,
            self.domain.sub_domain_name
        );

        let gh = get_connection().await?;
        let issue_handler = gh.issues(&self.domain.owner, &self.domain.sub_domain_name);
        let mut issues = match issue_handler
            .list()
            .state(params::State::All)
            .per_page(100)
            .send()
            .await
        {
            Ok(val) => val,
            Err(err) => return Err(SBError::FailedToGetIssue(err.to_string())),
        };
        log::info!(
            "issues: {:?}",
            issues
                .clone()
                .into_iter()
                .map(|iss| iss.id)
                .collect::<Vec<IssueId>>()
        );

        loop {
            for issue in &issues.take_items() {
                // get Status of Issue
                // 1. Open - try create bounty
                // 2. Closed -
                //  - pay out bounty if mentioned users
                //  - close bounty if no one mentioned
                log::info!("[relayer] issue {}, issue state {}", issue.id, issue.state,);
                if issue.state.eq("open") {
                    log::info!(
                        "[relayer] found issue id={}, isOpen= {}",
                        issue.id,
                        issue.state.eq("open"),
                    );

                    // get bounty if proposed in issue
                    let bounty_proposed_in_issue = self.try_get_bounty_from_issue(&issue).await?;

                    // Check the status of the bounty
                    // -> If there is no signing link -> look for bounty -> post signing link
                    // get the top 150 comments on the issue
                    let comments: Vec<Comment> = issue_handler
                        .list_comments(issue.number as u64)
                        .per_page(150)
                        .send()
                        .await
                        .map_err(|err| {
                            SBError::CommentsNotFound("open issues".to_string(), err.to_string())
                        })?
                        .take_items();

                    let mut relayer_comments_iter = comments
                        .iter()
                        .filter(|comment| is_relayer_login(&comment.user.login).unwrap());

                    match get_bounty(
                        &self.domain.owner,
                        &self.domain.sub_domain_name,
                        &issue.id.0,
                    ) {
                        Ok(bounty) => {
                            // Bounty exists
                            // check if posted status
                            log::info!("Issues: found created bounty: {:?}", bounty);

                            // don't do anything if bounty is closed
                            if (bounty.state.eq("completed")) {
                                log::info!("Issues: bounty created bounty: {:?}", bounty);
                            }
                        }
                        Err(err) => {
                            log::info!(
                                "issue {} not created. Cause {}",
                                issue.id.0,
                                err.to_string()
                            );
                            let has_posted_signing_link = &relayer_comments_iter.any(|comment| {
                                self.comment_contains_signing_link(&comment).unwrap()
                            });
                            // bounty don't exist
                            if !has_posted_signing_link {
                                // if bounty is new then generate signing link
                                self.post_signing_link(
                                    &gh,
                                    &issue.number,
                                    &issue.id,
                                    &bounty_proposed_in_issue.amount.unwrap(),
                                )
                                .await?;
                            }
                            log::debug!("issues: bounty for issue={} does not exists and signing link has been posted={} ",issue.id.0,has_posted_signing_link);
                        }
                    };
                } else {
                    // -> If closed -> try to complete bounty
                    log::info!(
                        "Issues: issue closed, try to complete bounty for {}",
                        issue.url
                    );

                    let bounty = match get_bounty(
                        &self.domain.owner,
                        &self.domain.sub_domain_name,
                        &issue.id.0,
                    ) {
                        Ok(bounty) => bounty,
                        Err(err) => {
                            log::info!(
                                "Could not get issue for {} with id {}. Cause {}. Continuing to next issue...",
                                issue.url,
                                issue.id.0,
                                err.to_string()
                            );
                            break;
                        }
                    };

                    // get the top 150 comments on the issue
                    let page_comments = issue_handler
                        .list_comments(issue.number as u64)
                        .per_page(150)
                        .send()
                        .await
                        .map_err(|err| {
                            SBError::CommentsNotFound("closed issues".to_string(), err.to_string())
                        })?
                        .take_items();

                    // try to get the comment body. If no closing comment -> return
                    let comment_body = match self
                        .try_get_closing_comment(issue, page_comments)
                        .await
                    {
                        Ok(body) => body,
                        Err(err) => {
                            log::warn!("Could not get closing comment. Cause: {}", err.to_string());
                            break;
                        }
                    };

                    // FIXME: don't throw error, match and log
                    let bounty_wrapped = match get_solvers(
                        &issue.user.id.to_string(),
                        &comment_body,
                        &issue.id,
                        &bounty.mint,
                    )
                    .await
                    {
                        Ok(wrapped_bounty) => wrapped_bounty,
                        Err(err) => {
                            log::info!("{}", err.to_string());
                            break;
                        }
                    };

                    match bounty_wrapped
                        .try_complete_bounty(
                            &self.domain.owner,
                            &self.domain.sub_domain_name,
                            &issue.id.0,
                            &bounty.mint,
                        )
                        .await
                    {
                        Ok(res) => (),
                        Err(err) => log::info!("{}", err.to_string()),
                    };
                }

                let bounty = match get_bounty(
                    &self.domain.owner,
                    &self.domain.sub_domain_name,
                    &issue.id.0,
                ) {
                    Ok(bounty) => bounty,
                    Err(err) => {
                        log::info!(
                            "Could not get issue for {} with id {}. Cause {}. Continuing to next issue...",
                            issue.url,
                            issue.id.0,
                            err.to_string()
                        );
                        break;
                    }
                };
                let comments: Vec<Comment> = issue_handler
                    .list_comments(issue.number as u64)
                    .per_page(150)
                    .send()
                    .await
                    .map_err(|err| {
                        SBError::CommentsNotFound("open issues".to_string(), err.to_string())
                    })?
                    .take_items();

                let relayer_comments_iter = comments
                    .iter()
                    .filter(|comment| is_relayer_login(&comment.user.login).unwrap());

                log::info!("[relayer] Try to post comments to issue {}", issue.url);

                self.try_post_bounty_status(
                    &gh,
                    &issue.number,
                    &issue.id.0,
                    &bounty,
                    &relayer_comments_iter.collect::<Vec<&Comment>>(),
                )
                .await?;
            }

            // move to next issue
            issues = match gh
                .get_page::<models::issues::Issue>(&issues.next)
                .await
                .unwrap()
            {
                Some(next_page) => next_page,
                None => break,
            }
        }
        Ok(())
    }
}
