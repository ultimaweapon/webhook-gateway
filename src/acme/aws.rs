use super::Dns01;
use aws_sdk_route53::error::SdkError;
use aws_sdk_route53::operation::change_resource_record_sets::ChangeResourceRecordSetsError;
use aws_sdk_route53::operation::get_change::GetChangeError;
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ChangeStatus, ResourceRecord, ResourceRecordSet, RrType,
};
use instant_acme::{AuthorizedIdentifier, RetryPolicy};
use std::rc::Rc;
use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;

/// Implementation of [Dns01] for AWS route 53.
pub struct Route53 {
    client: aws_sdk_route53::Client,
    hosted_zone: Rc<str>,
}

impl Route53 {
    #[inline(always)]
    pub fn new(client: aws_sdk_route53::Client, hosted_zone: Rc<str>) -> Self {
        Self {
            client,
            hosted_zone,
        }
    }
}

impl Dns01 for &Route53 {
    type Err = Route53Error;

    async fn set_auth(
        self,
        domain: &AuthorizedIdentifier<'_>,
        mut data: String,
    ) -> Result<RetryPolicy, Self::Err> {
        // Quote the value.
        data.insert(0, '"');
        data.push('"');

        // Create update for record.
        let record = ResourceRecordSet::builder()
            .name(format!("_acme-challenge.{domain}."))
            .r#type(RrType::Txt)
            .ttl(60)
            .resource_records(ResourceRecord::builder().value(data).build().unwrap())
            .build()
            .unwrap();

        // Update.
        let change = Change::builder()
            .action(ChangeAction::Upsert)
            .resource_record_set(record)
            .build()
            .unwrap();
        let change = self
            .client
            .change_resource_record_sets()
            .hosted_zone_id(self.hosted_zone.as_ref())
            .change_batch(ChangeBatch::builder().changes(change).build().unwrap())
            .send()
            .await
            .map_err(Route53Error::CreateRecord)?;

        // Wait for changes to propagate.
        let change = change
            .change_info()
            .ok_or(Route53Error::MissingChangeInfoFromCreateRecord)?;
        let id = change.id();

        loop {
            sleep(Duration::from_secs(30)).await;

            // Check if change propagated.
            let r = self
                .client
                .get_change()
                .id(id)
                .send()
                .await
                .map_err(Route53Error::GetChange)?;
            let i = r
                .change_info()
                .ok_or(Route53Error::MissingChangeInfoFromGetChange)?;

            if i.status == ChangeStatus::Insync {
                break;
            }
        }

        // Wait for previous record to expire.
        sleep(Duration::from_mins(5)).await;

        Ok(RetryPolicy::new().timeout(Duration::from_mins(3)))
    }
}

/// Implementation of [Dns01::Err] for [Route53].
#[derive(Debug, Error)]
pub enum Route53Error {
    #[error("couldn't create TXT record")]
    CreateRecord(#[source] SdkError<ChangeResourceRecordSetsError>),

    #[error("missing ChangeInfo from ChangeResourceRecordSets")]
    MissingChangeInfoFromCreateRecord,

    #[error("couldn't fetch change's status")]
    GetChange(#[source] SdkError<GetChangeError>),

    #[error("missing ChangeInfo from GetChange")]
    MissingChangeInfoFromGetChange,
}
