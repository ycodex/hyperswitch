use std::marker::PhantomData;

use api_models::payments;
use async_trait::async_trait;
use error_stack::{IntoReport, ResultExt};
use masking::ExposeInterface;
use router_derive::PaymentOperation;
use router_env::{instrument, tracing};

use super::{BoxedOperation, Domain, GetTracker, Operation, UpdateTracker, ValidateRequest};
use crate::{
    core::{
        errors::{self, CustomResult, RouterResult, StorageErrorExt},
        payments::{helpers, operations, CustomerDetails, PaymentAddress, PaymentData},
    },
    db::StorageInterface,
    routes::AppState,
    types::{
        api::{self, PaymentIdTypeExt},
        storage::{self, enums as storage_enums},
        transformers::ForeignInto,
    },
    utils::OptionExt,
};

#[derive(Debug, Clone, Copy, PaymentOperation)]
#[operation(ops = "all", flow = "start")]
pub struct PaymentStart;

#[async_trait]
impl<F: Send + Clone> GetTracker<F, PaymentData<F>, api::PaymentsStartRequest> for PaymentStart {
    #[instrument(skip_all)]
    async fn get_trackers<'a>(
        &'a self,
        state: &'a AppState,
        payment_id: &api::PaymentIdType,
        _request: &api::PaymentsStartRequest,
        _mandate_type: Option<api::MandateTxnType>,
        merchant_account: &storage::MerchantAccount,
    ) -> RouterResult<(
        BoxedOperation<'a, F, api::PaymentsStartRequest>,
        PaymentData<F>,
        Option<CustomerDetails>,
    )> {
        let (mut payment_intent, payment_attempt, currency, amount);
        let db = &*state.store;

        let merchant_id = &merchant_account.merchant_id;
        let storage_scheme = merchant_account.storage_scheme;
        let payment_id = payment_id
            .get_payment_intent_id()
            .change_context(errors::ApiErrorResponse::PaymentNotFound)?;

        payment_intent = db
            .find_payment_intent_by_payment_id_merchant_id(&payment_id, merchant_id, storage_scheme)
            .await
            .to_not_found_response(errors::ApiErrorResponse::PaymentNotFound)?;

        helpers::validate_payment_status_against_not_allowed_statuses(
            &payment_intent.status,
            &[
                storage_enums::IntentStatus::Failed,
                storage_enums::IntentStatus::Succeeded,
            ],
            "update",
        )?;

        payment_attempt = db
            .find_payment_attempt_by_payment_id_merchant_id_attempt_id(
                payment_intent.payment_id.as_str(),
                merchant_id,
                payment_intent.active_attempt_id.as_str(),
                storage_scheme,
            )
            .await
            .to_not_found_response(errors::ApiErrorResponse::PaymentNotFound)?;

        //If payment intent is associated with a mandate_id then fetch payment_method_data from
        //mandate metadata (Card data is not stored in db)
        let mandate_metadata = match payment_attempt.mandate_id.clone() {
            Some(mandate_id) => {
                db.find_mandate_by_merchant_id_mandate_id(merchant_id, &mandate_id[..])
                    .await
                    .to_not_found_response(errors::ApiErrorResponse::MandateNotFound)?
                    .metadata
            }
            None => None,
        };

        let payment_method_data = match mandate_metadata {
            Some(value) => {
                let payment_data: payments::PaymentMethodData =
                    serde_json::from_value::<payments::PaymentMethodData>(value.expose())
                        .into_report()
                        .change_context(errors::ApiErrorResponse::PaymentMethodNotFound)?;
                Some(payment_data)
            }
            None => None,
        };

        currency = payment_attempt.currency.get_required_value("currency")?;
        amount = payment_attempt.amount.into();

        let shipping_address = helpers::get_address_for_payment_request(
            db,
            None,
            payment_intent.shipping_address_id.as_deref(),
            merchant_id,
            &payment_intent.customer_id,
        )
        .await?;
        let billing_address = helpers::get_address_for_payment_request(
            db,
            None,
            payment_intent.billing_address_id.as_deref(),
            merchant_id,
            &payment_intent.customer_id,
        )
        .await?;

        payment_intent.shipping_address_id = shipping_address.clone().map(|i| i.address_id);
        payment_intent.billing_address_id = billing_address.clone().map(|i| i.address_id);

        let customer_details = CustomerDetails {
            customer_id: payment_intent.customer_id.clone(),
            ..CustomerDetails::default()
        };

        let connector_response = db
            .find_connector_response_by_payment_id_merchant_id_attempt_id(
                &payment_intent.payment_id,
                &payment_intent.merchant_id,
                &payment_attempt.attempt_id,
                storage_scheme,
            )
            .await
            .map_err(|error| {
                error
                    .change_context(errors::ApiErrorResponse::InternalServerError)
                    .attach_printable("Database error when finding connector response")
            })?;

        Ok((
            Box::new(self),
            PaymentData {
                flow: PhantomData,
                payment_intent,
                currency,
                amount,
                email: None,
                mandate_id: None,
                connector_response,
                setup_mandate: None,
                token: payment_attempt.payment_token.clone(),
                address: PaymentAddress {
                    shipping: shipping_address.as_ref().map(|a| a.foreign_into()),
                    billing: billing_address.as_ref().map(|a| a.foreign_into()),
                },
                confirm: Some(payment_attempt.confirm),
                payment_attempt,
                payment_method_data,
                force_sync: None,
                refunds: vec![],
                disputes: vec![],
                sessions_token: vec![],
                card_cvc: None,
                creds_identifier: None,
                pm_token: None,
                connector_customer_id: None,
                mandate_metadata: None,
                ephemeral_key: None,
            },
            Some(customer_details),
        ))
    }
}

#[async_trait]
impl<F: Clone> UpdateTracker<F, PaymentData<F>, api::PaymentsStartRequest> for PaymentStart {
    #[instrument(skip_all)]
    async fn update_trackers<'b>(
        &'b self,
        _db: &dyn StorageInterface,
        _payment_id: &api::PaymentIdType,
        payment_data: PaymentData<F>,
        _customer: Option<storage::Customer>,
        _storage_scheme: storage_enums::MerchantStorageScheme,
        _updated_customer: Option<storage::CustomerUpdate>,
    ) -> RouterResult<(
        BoxedOperation<'b, F, api::PaymentsStartRequest>,
        PaymentData<F>,
    )>
    where
        F: 'b + Send,
    {
        Ok((Box::new(self), payment_data))
    }
}

impl<F: Send + Clone> ValidateRequest<F, api::PaymentsStartRequest> for PaymentStart {
    #[instrument(skip_all)]
    fn validate_request<'a, 'b>(
        &'b self,
        request: &api::PaymentsStartRequest,
        merchant_account: &'a storage::MerchantAccount,
    ) -> RouterResult<(
        BoxedOperation<'b, F, api::PaymentsStartRequest>,
        operations::ValidateResult<'a>,
    )> {
        let request_merchant_id = Some(&request.merchant_id[..]);
        helpers::validate_merchant_id(&merchant_account.merchant_id, request_merchant_id)
            .change_context(errors::ApiErrorResponse::InvalidDataFormat {
                field_name: "merchant_id".to_string(),
                expected_format: "merchant_id from merchant account".to_string(),
            })?;
        // let mandate_type = validate_mandate(request)?;
        let payment_id = request.payment_id.clone();

        Ok((
            Box::new(self),
            operations::ValidateResult {
                merchant_id: &merchant_account.merchant_id,
                payment_id: api::PaymentIdType::PaymentIntentId(payment_id),
                mandate_type: None,
                storage_scheme: merchant_account.storage_scheme,
            },
        ))
    }
}

#[async_trait]
impl<F: Clone + Send, Op: Send + Sync + Operation<F, api::PaymentsStartRequest>>
    Domain<F, api::PaymentsStartRequest> for Op
where
    for<'a> &'a Op: Operation<F, api::PaymentsStartRequest>,
{
    #[instrument(skip_all)]
    async fn get_or_create_customer_details<'a>(
        &'a self,
        db: &dyn StorageInterface,
        payment_data: &mut PaymentData<F>,
        request: Option<CustomerDetails>,
        merchant_id: &str,
    ) -> CustomResult<
        (
            BoxedOperation<'a, F, api::PaymentsStartRequest>,
            Option<storage::Customer>,
        ),
        errors::StorageError,
    > {
        helpers::create_customer_if_not_exist(
            Box::new(self),
            db,
            payment_data,
            request,
            merchant_id,
        )
        .await
    }

    #[instrument(skip_all)]
    async fn make_pm_data<'a>(
        &'a self,
        state: &'a AppState,
        payment_data: &mut PaymentData<F>,
        _storage_scheme: storage_enums::MerchantStorageScheme,
    ) -> RouterResult<(
        BoxedOperation<'a, F, api::PaymentsStartRequest>,
        Option<api::PaymentMethodData>,
    )> {
        helpers::make_pm_data(Box::new(self), state, payment_data).await
    }

    async fn get_connector<'a>(
        &'a self,
        _merchant_account: &storage::MerchantAccount,
        state: &AppState,
        _request: &api::PaymentsStartRequest,
        _payment_intent: &storage::payment_intent::PaymentIntent,
    ) -> CustomResult<api::ConnectorChoice, errors::ApiErrorResponse> {
        helpers::get_connector_default(state, None).await
    }
}
