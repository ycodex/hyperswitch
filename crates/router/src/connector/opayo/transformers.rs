

use masking::Secret;
use serde::{Deserialize, Serialize};


use crate::{
    connector::utils::{
         AddressDetailsData, CardData,

    },
    core::errors,

    types::{self, api, storage::enums as storage_enums,},
};


#[derive(Default, Debug, Serialize)]
pub struct OpayoSessionRequest {
    pub vendor_name: String
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardItem {
    pub merchant_session_key: String,
    pub card_identifier: String
}

#[derive(Default, Debug, Serialize)]
pub struct PaymentMethodItem {
    pub card: CardItem,
}

#[derive(Default, Debug, Serialize)]
pub struct BillingAddressItem {
    pub address1: Secret<String>,
    pub city: String,
    pub postal_code : Secret<String>,
    pub country : api_models::enums::CountryCode,
}

#[derive(Default, Debug, Serialize,)]
#[serde(rename_all = "camelCase")]
pub struct OpayoPaymentsRequest {
    pub payment_method: PaymentMethodItem,
    pub vendor_tx_code : String,
    pub amount : i64,
    pub currency : storage_enums::Currency,
    pub customer_first_name : String,
    pub customer_last_name : String,
    pub billing_address : BillingAddressItem,
    pub description : String
    
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpayoCardIdentifierRequest {
    cardholder_name: Secret<String>,
    card_number: Secret<String, common_utils::pii::CardNumber>,
    expiry_date: Secret<String>,
    security_code: Secret<String>,
}

fn get_address_info(
    payment_address: Option<&api_models::payments::Address>,
) -> Result<Option<BillingAddressItem>, error_stack::Report<errors::ConnectorError>> {
    let address = payment_address.and_then(|payment_address| payment_address.address.as_ref());
    let address = match address {
        Some(address) => Some(BillingAddressItem {
            country: address.get_country()?.to_owned(),
            address1: address.line1.clone().unwrap(),
            city: address.city.clone().unwrap(),
            postal_code: address.zip.clone().unwrap(),
        }),
        None => None,
    };
    Ok(address)
}


impl TryFrom<&types::PaymentsAuthorizeRouterData> for OpayoPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::PaymentsAuthorizeRouterData) -> Result<Self, Self::Error> {
        match item.request.payment_method_data.clone() {
            api::PaymentMethodData::Card(_) => {
                let payment_method = PaymentMethodItem{
                    card: CardItem{
                        merchant_session_key: item.session_token.clone().unwrap(),
                        card_identifier: item.payment_method_token.clone().unwrap(),
                    },
                };
                let address =  get_address_info(item.address.billing.as_ref())?;
                Ok(Self {
                    amount: item.request.amount,
                    payment_method,
                    vendor_tx_code: item.attempt_id.clone(),
                    currency: item.request.currency,
                    customer_first_name: "test".to_string(),
                    customer_last_name: "account".to_string(),
                    billing_address: address.unwrap(),
                    description: "Testing".to_string(),
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented("Payment methods".to_string()).into()),
        }
    }
}


// Auth Struct
pub struct OpayoAuthType {
    pub(super) api_key: String,
    pub(super) key1: String
}

impl TryFrom<&types::ConnectorAuthType> for OpayoAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &types::ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            types::ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: api_key.to_string(),
                key1: key1.to_string(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType)?,
        }
    }
}
// PaymentsResponse
//TODO: Append the remaining status flags
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OpayoPaymentStatus {
    Succeeded,
    Failed,
    #[default]
    Processing,
}

impl From<OpayoPaymentStatus> for storage_enums::AttemptStatus {
    fn from(item: OpayoPaymentStatus) -> Self {
        match item {
            OpayoPaymentStatus::Succeeded => Self::Charged,
            OpayoPaymentStatus::Failed => Self::Failure,
            OpayoPaymentStatus::Processing => Self::Authorizing,
        }
    }
}

//TODO: Fill the struct with respective fields
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpayoPaymentsResponse {
    status: OpayoPaymentStatus,
    id: String,
}

impl TryFrom<&types::PaymentsAuthorizeSessionTokenRouterData> for OpayoSessionRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        _item: &types::PaymentsAuthorizeSessionTokenRouterData,
    ) -> Result<Self, Self::Error> {
        
        Ok(Self {
            vendor_name: "sandbox".to_string(),
        })
    }
}

impl TryFrom<&types::TokenizationRouterData> for OpayoCardIdentifierRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &types::TokenizationRouterData,
    ) -> Result<Self, Self::Error> {
        match item.request.payment_method_data.clone(){
            api::PaymentMethodData::Card( ccard) => {
                let cardholder_name = ccard.card_holder_name.clone();
                let card_number = ccard.card_number.clone();
                let expiry_date = ccard.get_expiry_date_as_mmyy(); 
                let security_code = ccard.card_cvc;

                Ok(Self {
                    cardholder_name,
                    card_number,
                    expiry_date,
                    security_code,
                })

            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment Method".to_string(),
            ))?,

        }
        
        
    }
}


#[derive(Default, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpayoSessionResponse {
    merchant_session_key: String,
}


impl<F, T>
    TryFrom<types::ResponseRouterData<F, OpayoSessionResponse, T, types::PaymentsResponseData>>
    for types::RouterData<F, T, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<F, OpayoSessionResponse, T, types::PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status: storage_enums::AttemptStatus::Pending,
            session_token: Some(item.response.merchant_session_key.clone()),
            response: Ok(types::PaymentsResponseData::SessionTokenResponse {
                session_token: item.response.merchant_session_key,
            }),
            ..item.data
        })
    }
}


#[derive(Default, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpayoCardIdentifierResponse {
    card_identifier: String,
}


impl<F, T>
    TryFrom<types::ResponseRouterData<F, OpayoCardIdentifierResponse, T, types::PaymentsResponseData>>
    for types::RouterData<F, T, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<F, OpayoCardIdentifierResponse, T, types::PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status: storage_enums::AttemptStatus::Pending,
            session_token: Some(item.response.card_identifier.clone()),
            response: Ok(types::PaymentsResponseData::SessionTokenResponse {
                session_token: item.response.card_identifier,
            }),
            ..item.data
        })
    }
}

impl<F, T>
    TryFrom<types::ResponseRouterData<F, OpayoPaymentsResponse, T, types::PaymentsResponseData>>
    for types::RouterData<F, T, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<F, OpayoPaymentsResponse, T, types::PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status: storage_enums::AttemptStatus::from(item.response.status),
            response: Ok(types::PaymentsResponseData::TransactionResponse {
                resource_id: types::ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
            }),
            ..item.data
        })
    }
}

//TODO: Fill the struct with respective fields
// REFUND :
// Type definition for RefundRequest
#[derive(Default, Debug, Serialize)]
pub struct OpayoRefundRequest {
    pub amount: i64,
}

impl<F> TryFrom<&types::RefundsRouterData<F>> for OpayoRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::RefundsRouterData<F>) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.request.amount,
        })
    }
}

// Type definition for Refund Response

#[allow(dead_code)]
#[derive(Debug, Serialize, Default, Deserialize, Clone)]
pub enum RefundStatus {
    Succeeded,
    Failed,
    #[default]
    Processing,
}

impl From<RefundStatus> for storage_enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Succeeded => Self::Success,
            RefundStatus::Failed => Self::Failure,
            RefundStatus::Processing => Self::Pending,
            //TODO: Review mapping
        }
    }
}

//TODO: Fill the struct with respective fields
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    id: String,
    status: RefundStatus,
}

impl TryFrom<types::RefundsResponseRouterData<api::Execute, RefundResponse>>
    for types::RefundsRouterData<api::Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::RefundsResponseRouterData<api::Execute, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(types::RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: storage_enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
    }
}

impl TryFrom<types::RefundsResponseRouterData<api::RSync, RefundResponse>>
    for types::RefundsRouterData<api::RSync>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::RefundsResponseRouterData<api::RSync, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(types::RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: storage_enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
    }
}

//TODO: Fill the struct with respective fields
#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct OpayoErrorResponse {
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
}
