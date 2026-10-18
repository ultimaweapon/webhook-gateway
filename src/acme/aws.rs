use super::Dns01;
use aws_sdk_route53::error::SdkError;
use aws_sdk_route53::operation::change_resource_record_sets::ChangeResourceRecordSetsError;
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType,
};
use instant_acme::AuthorizedIdentifier;
use std::rc::Rc;

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
    type Err = SdkError<ChangeResourceRecordSetsError>;

    async fn set_auth(
        self,
        domain: &AuthorizedIdentifier<'_>,
        mut data: String,
    ) -> Result<(), Self::Err> {
        // Quote the value.
        data.insert(0, '"');
        data.push('"');

        // Create update for record.
        let record = ResourceRecordSet::builder()
            .name(format!("_acme-challenge.{domain}"))
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

        self.client
            .change_resource_record_sets()
            .hosted_zone_id(self.hosted_zone.as_ref())
            .change_batch(ChangeBatch::builder().changes(change).build().unwrap())
            .send()
            .await?;

        Ok(())
    }
}
