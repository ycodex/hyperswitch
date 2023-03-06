#![allow(dead_code)]

mod transformers;

use std::fmt::Debug;

use error_stack::{IntoReport, ResultExt};

use self::transformers as checkout;
use super::utils::RefundsRequestData;
use crate::{
    configs::settings,
    connector::utils as conn_utils,
    consts,
    core::{
        errors::{self, CustomResult},
        payments,
    },
    db::StorageInterface,
    headers, logger, services,
    types::{
        self,
        api::{self, ConnectorCommon},
    },
    utils::{self, crypto, ByteSliceExt, BytesExt},
};

#[derive(Debug, Clone)]
pub struct Checkout;

impl ConnectorCommon for Checkout {
    fn id(&self) -> &'static str {
        "checkout"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_auth_header(
        &self,
        auth_type: &types::ConnectorAuthType,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        let auth: checkout::CheckoutAuthType = auth_type
            .try_into()
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", auth.api_key),
        )])
    }

    fn base_url<'a>(&self, connectors: &'a settings::Connectors) -> &'a str {
        connectors.checkout.base_url.as_ref()
    }
}

impl api::Payment for Checkout {}

impl api::PaymentAuthorize for Checkout {}
impl api::PaymentSync for Checkout {}
impl api::PaymentVoid for Checkout {}
impl api::PaymentCapture for Checkout {}
impl api::PaymentSession for Checkout {}
impl api::ConnectorAccessToken for Checkout {}

impl
    services::ConnectorIntegration<
        api::Session,
        types::PaymentsSessionData,
        types::PaymentsResponseData,
    > for Checkout
{
    // Not Implemented (R)
}

impl
    services::ConnectorIntegration<
        api::AccessTokenAuth,
        types::AccessTokenRequestData,
        types::AccessToken,
    > for Checkout
{
    // Not Implemented (R)
}

impl api::PreVerify for Checkout {}

impl
    services::ConnectorIntegration<
        api::Verify,
        types::VerifyRequestData,
        types::PaymentsResponseData,
    > for Checkout
{
    // Issue: #173
}

impl
    services::ConnectorIntegration<
        api::Capture,
        types::PaymentsCaptureData,
        types::PaymentsResponseData,
    > for Checkout
{
    fn get_headers(
        &self,
        req: &types::PaymentsCaptureRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        let mut header = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string(),
            ),
            (headers::X_ROUTER.to_string(), "test".to_string()),
        ];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &types::PaymentsCaptureRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let id = req.request.connector_transaction_id.as_str();
        Ok(format!(
            "{}payments/{id}/captures",
            self.base_url(connectors)
        ))
    }
    fn get_request_body(
        &self,
        req: &types::PaymentsCaptureRouterData,
    ) -> CustomResult<Option<String>, errors::ConnectorError> {
        let connector_req = checkout::PaymentCaptureRequest::try_from(req)?;
        let checkout_req =
            utils::Encode::<checkout::PaymentCaptureRequest>::encode_to_string_of_json(
                &connector_req,
            )
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(Some(checkout_req))
    }

    fn build_request(
        &self,
        req: &types::PaymentsCaptureRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        Ok(Some(
            services::RequestBuilder::new()
                .method(services::Method::Post)
                .url(&types::PaymentsCaptureType::get_url(self, req, connectors)?)
                .headers(types::PaymentsCaptureType::get_headers(
                    self, req, connectors,
                )?)
                .body(types::PaymentsCaptureType::get_request_body(self, req)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &types::PaymentsCaptureRouterData,
        res: types::Response,
    ) -> CustomResult<types::PaymentsCaptureRouterData, errors::ConnectorError> {
        let response: checkout::PaymentCaptureResponse = res
            .response
            .parse_struct("CaptureResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        types::RouterData::try_from(types::ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: types::Response,
    ) -> CustomResult<types::ErrorResponse, errors::ConnectorError> {
        let response: checkout::ErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        Ok(types::ErrorResponse {
            status_code: res.status_code,
            code: response
                .error_codes
                .unwrap_or_else(|| vec![consts::NO_ERROR_CODE.to_string()])
                .join(" & "),
            message: response
                .error_type
                .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
            reason: None,
        })
    }
}

impl
    services::ConnectorIntegration<api::PSync, types::PaymentsSyncData, types::PaymentsResponseData>
    for Checkout
{
    fn get_headers(
        &self,
        req: &types::PaymentsSyncRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        let mut header = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                types::PaymentsAuthorizeType::get_content_type(self).to_string(),
            ),
            (headers::X_ROUTER.to_string(), "test".to_string()),
        ];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &types::PaymentsSyncRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}{}{}",
            self.base_url(connectors),
            "payments/",
            req.request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?
        ))
    }

    fn build_request(
        &self,
        req: &types::PaymentsSyncRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        Ok(Some(
            services::RequestBuilder::new()
                .method(services::Method::Get)
                .url(&types::PaymentsSyncType::get_url(self, req, connectors)?)
                .headers(types::PaymentsSyncType::get_headers(self, req, connectors)?)
                .header(headers::X_ROUTER, "test")
                .body(types::PaymentsSyncType::get_request_body(self, req)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &types::PaymentsSyncRouterData,
        res: types::Response,
    ) -> CustomResult<types::PaymentsSyncRouterData, errors::ConnectorError>
    where
        api::PSync: Clone,
        types::PaymentsSyncData: Clone,
        types::PaymentsResponseData: Clone,
    {
        logger::debug!(raw_response=?res);
        println!("Checkout PSync Response:---->{:?}", res.response);
        let response: checkout::PaymentsResponse = res
            .response
            .parse_struct("PaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        logger::debug!(payment_sync_response=?response);
        types::RouterData::try_from(types::ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: types::Response,
    ) -> CustomResult<types::ErrorResponse, errors::ConnectorError> {
        logger::debug!(raw_response=?res);
        let response: checkout::ErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        Ok(types::ErrorResponse {
            status_code: res.status_code,
            code: response
                .error_codes
                .unwrap_or_else(|| vec![consts::NO_ERROR_CODE.to_string()])
                .join(" &"),
            message: response
                .error_type
                .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
            reason: None,
        })
    }
}

impl
    services::ConnectorIntegration<
        api::Authorize,
        types::PaymentsAuthorizeData,
        types::PaymentsResponseData,
    > for Checkout
{
    fn get_headers(
        &self,
        req: &types::PaymentsAuthorizeRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        let mut header = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                types::PaymentsAuthorizeType::get_content_type(self).to_string(),
            ),
            (headers::X_ROUTER.to_string(), "test".to_string()),
        ];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        _req: &types::PaymentsAuthorizeRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}{}", self.base_url(connectors), "payments"))
    }

    fn get_request_body(
        &self,
        req: &types::PaymentsAuthorizeRouterData,
    ) -> CustomResult<Option<String>, errors::ConnectorError> {
        let connector_req = checkout::PaymentsRequest::try_from(req)?;
        let checkout_req =
            utils::Encode::<checkout::PaymentsRequest>::encode_to_string_of_json(&connector_req)
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(Some(checkout_req))
    }
    fn build_request(
        &self,
        req: &types::RouterData<
            api::Authorize,
            types::PaymentsAuthorizeData,
            types::PaymentsResponseData,
        >,
        connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        Ok(Some(
            services::RequestBuilder::new()
                .method(services::Method::Post)
                .url(&types::PaymentsAuthorizeType::get_url(
                    self, req, connectors,
                )?)
                .headers(types::PaymentsAuthorizeType::get_headers(
                    self, req, connectors,
                )?)
                .header(headers::X_ROUTER, "test")
                .body(types::PaymentsAuthorizeType::get_request_body(self, req)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &types::PaymentsAuthorizeRouterData,
        res: types::Response,
    ) -> CustomResult<types::PaymentsAuthorizeRouterData, errors::ConnectorError> {
        logger::debug!(payments_create_response=?res);
        let response: checkout::PaymentsResponse = res
            .response
            .parse_struct("PaymentIntentResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        types::RouterData::try_from(types::ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: types::Response,
    ) -> CustomResult<types::ErrorResponse, errors::ConnectorError> {
        logger::debug!(checkout_error_response=?res);

        let response: checkout::ErrorResponse = if res.response.is_empty() {
            checkout::ErrorResponse {
                request_id: None,
                error_type: if res.status_code == 401 {
                    Some("Invalid Api Key".to_owned())
                } else {
                    None
                },
                error_codes: None,
            }
        } else {
            res.response
                .parse_struct("ErrorResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?
        };

        Ok(types::ErrorResponse {
            status_code: res.status_code,
            code: response
                .error_codes
                .unwrap_or_else(|| vec![consts::NO_ERROR_CODE.to_string()])
                .join(" & "),
            message: response
                .error_type
                .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
            reason: None,
        })
    }
}

impl
    services::ConnectorIntegration<
        api::Void,
        types::PaymentsCancelData,
        types::PaymentsResponseData,
    > for Checkout
{
    fn get_headers(
        &self,
        req: &types::PaymentsCancelRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        let mut header = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                types::PaymentsVoidType::get_content_type(self).to_string(),
            ),
            (headers::X_ROUTER.to_string(), "test".to_string()),
        ];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &types::PaymentsCancelRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}payments/{}/voids",
            self.base_url(connectors),
            &req.request.connector_transaction_id
        ))
    }

    fn get_request_body(
        &self,
        req: &types::PaymentsCancelRouterData,
    ) -> CustomResult<Option<String>, errors::ConnectorError> {
        let connector_req = checkout::PaymentVoidRequest::try_from(req)?;
        let checkout_req =
            utils::Encode::<checkout::PaymentVoidRequest>::encode_to_string_of_json(&connector_req)
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(Some(checkout_req))
    }
    fn build_request(
        &self,
        req: &types::PaymentsCancelRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        Ok(Some(
            services::RequestBuilder::new()
                .method(services::Method::Post)
                .url(&types::PaymentsVoidType::get_url(self, req, connectors)?)
                .headers(types::PaymentsVoidType::get_headers(self, req, connectors)?)
                .body(types::PaymentsVoidType::get_request_body(self, req)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &types::PaymentsCancelRouterData,
        res: types::Response,
    ) -> CustomResult<types::PaymentsCancelRouterData, errors::ConnectorError> {
        logger::debug!(payments_cancel_response=?res);

        let mut response: checkout::PaymentVoidResponse = res
            .response
            .parse_struct("PaymentVoidResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        response.status = res.status_code;
        types::RouterData::try_from(types::ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: types::Response,
    ) -> CustomResult<types::ErrorResponse, errors::ConnectorError> {
        let response: checkout::ErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        Ok(types::ErrorResponse {
            status_code: res.status_code,
            code: response
                .error_codes
                .unwrap_or_else(|| vec![consts::NO_ERROR_CODE.to_string()])
                .join(" & "),
            message: response
                .error_type
                .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
            reason: None,
        })
    }
}

impl api::Refund for Checkout {}
impl api::RefundExecute for Checkout {}
impl api::RefundSync for Checkout {}

impl services::ConnectorIntegration<api::Execute, types::RefundsData, types::RefundsResponseData>
    for Checkout
{
    fn get_headers(
        &self,
        req: &types::RefundsRouterData<api::Execute>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        let mut header = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                types::RefundExecuteType::get_content_type(self).to_string(),
            ),
            (headers::X_ROUTER.to_string(), "test".to_string()),
        ];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &types::RefundsRouterData<api::Execute>,
        connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let id = req.request.connector_transaction_id.clone();
        Ok(format!(
            "{}payments/{}/refunds",
            self.base_url(connectors),
            id
        ))
    }

    fn get_request_body(
        &self,
        req: &types::RefundsRouterData<api::Execute>,
    ) -> CustomResult<Option<String>, errors::ConnectorError> {
        let connector_req = checkout::RefundRequest::try_from(req)?;
        let body =
            utils::Encode::<checkout::RefundRequest>::encode_to_string_of_json(&connector_req)
                .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(Some(body))
    }

    fn build_request(
        &self,
        req: &types::RefundsRouterData<api::Execute>,
        connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        let request = services::RequestBuilder::new()
            .method(services::Method::Post)
            .url(&types::RefundExecuteType::get_url(self, req, connectors)?)
            .headers(types::RefundExecuteType::get_headers(
                self, req, connectors,
            )?)
            .body(types::RefundExecuteType::get_request_body(self, req)?)
            .build();
        Ok(Some(request))
    }

    fn handle_response(
        &self,
        data: &types::RefundsRouterData<api::Execute>,
        res: types::Response,
    ) -> CustomResult<types::RefundsRouterData<api::Execute>, errors::ConnectorError> {
        logger::debug!(response=?res);
        let response: checkout::RefundResponse = res
            .response
            .parse_struct("checkout::RefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        let response = checkout::CheckoutRefundResponse {
            response,
            status: res.status_code,
        };
        types::ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        }
        .try_into()
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: types::Response,
    ) -> CustomResult<types::ErrorResponse, errors::ConnectorError> {
        let response: checkout::ErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        Ok(types::ErrorResponse {
            status_code: res.status_code,
            code: response
                .error_codes
                .unwrap_or_else(|| vec![consts::NO_ERROR_CODE.to_string()])
                .join(" & "),
            message: response
                .error_type
                .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
            reason: None,
        })
    }
}

impl services::ConnectorIntegration<api::RSync, types::RefundsData, types::RefundsResponseData>
    for Checkout
{
    fn get_headers(
        &self,
        req: &types::RefundsRouterData<api::RSync>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, String)>, errors::ConnectorError> {
        let mut header = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                types::RefundSyncType::get_content_type(self).to_string(),
            ),
            (headers::X_ROUTER.to_string(), "test".to_string()),
        ];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_url(
        &self,
        req: &types::RefundsRouterData<api::RSync>,
        connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let id = req.request.connector_transaction_id.clone();
        Ok(format!(
            "{}/payments/{}/actions",
            self.base_url(connectors),
            id
        ))
    }

    fn build_request(
        &self,
        req: &types::RefundsRouterData<api::RSync>,
        connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        Ok(Some(
            services::RequestBuilder::new()
                .method(services::Method::Get)
                .url(&types::RefundSyncType::get_url(self, req, connectors)?)
                .headers(types::RefundSyncType::get_headers(self, req, connectors)?)
                .body(types::RefundSyncType::get_request_body(self, req)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &types::RefundsRouterData<api::RSync>,
        res: types::Response,
    ) -> CustomResult<types::RefundsRouterData<api::RSync>, errors::ConnectorError> {
        let refund_action_id = data.request.get_connector_refund_id()?;

        let response: Vec<checkout::ActionResponse> = res
            .response
            .parse_struct("checkout::CheckoutRefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        let response = response
            .iter()
            .find(|&x| x.action_id.clone() == refund_action_id)
            .ok_or(errors::ConnectorError::ResponseHandlingFailed)?;
        types::ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        }
        .try_into()
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: types::Response,
    ) -> CustomResult<types::ErrorResponse, errors::ConnectorError> {
        let response: checkout::ErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        Ok(types::ErrorResponse {
            status_code: res.status_code,
            code: response
                .error_codes
                .unwrap_or_else(|| vec![consts::NO_ERROR_CODE.to_string()])
                .join(" & "),
            message: response
                .error_type
                .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string()),
            reason: None,
        })
    }
}

#[async_trait::async_trait]
impl api::IncomingWebhook for Checkout {
    fn get_webhook_source_verification_algorithm(
        &self,
        _headers: &actix_web::http::header::HeaderMap,
        _body: &[u8],
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(crypto::HmacSha256))
    }

    fn get_webhook_source_verification_signature(
        &self,
        headers: &actix_web::http::header::HeaderMap,
        _body: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        let signature = conn_utils::get_header_key_value("cko-signature", headers)
            .change_context(errors::ConnectorError::WebhookSignatureNotFound)?;
        let sign = hex::decode(signature)
            .into_report()
            .change_context(errors::ConnectorError::WebhookSignatureNotFound);

        // let signbase64 = consts::BASE64_ENGINE
        //     .decode(sign.unwrap())
        //     .into_report()
        //     .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;
        // println!("-------->{:?}", signature);
        // println!("****-----> {:?}", sign);

        // println!("@#$---> {:?}",  String::from_utf8_lossy(&signbase64));
        // Ok(format!("{}",String::from_utf8_lossy(signature)).into_bytes())
        //print!(">>>signatureRecieved{}",signature);
        sign.change_context(errors::ConnectorError::WebhookSignatureDecodingFailed)
    }

    fn get_webhook_source_verification_message(
        &self,
        _headers: &actix_web::http::header::HeaderMap,
        body: &[u8],
        _merchant_id: &str,
        _secret: &[u8],
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        //println!("$$----> bodyy : {:?}",body);
        Ok(format!("{}", String::from_utf8_lossy(body)).into_bytes())
    }

    async fn get_webhook_source_verification_merchant_secret(
        &self,
        db: &dyn StorageInterface,
        merchant_id: &str,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        //let key = "8V8x0dLK%ByD*DNS0GGh".to_string();
        // format!("whsec_verification_{}_{}", self.id(), merchant_id);
        // let secret = db
        //     .get_key(&key)
        //     .await
        //     .change_context(errors::ConnectorError::WebhookVerificationSecretNotFound)?;
        let key = format!("whsec_verification_{}_{}", self.id(), merchant_id);
        let secret = db
            .get_key(&key)
            .await
            .change_context(errors::ConnectorError::WebhookVerificationSecretNotFound)?;
        Ok("e19a3824-d45d-43be-a27b-52075dfae514".to_string().as_bytes().to_vec())
    }

    fn get_webhook_object_reference_id(
        &self,
        body: &[u8],
    ) -> CustomResult<String, errors::ConnectorError> {
        let webhook: checkout::CheckoutWebhookObjectResource = body
            .parse_struct("CheckoutIncomingWebhook")
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;
        match webhook.data["id"].as_str() {
            Some(id) => Ok(id.to_string()),
            None => Err(errors::ConnectorError::WebhookReferenceIdNotFound).into_report(),
        }
    }

    fn get_webhook_event_type(
        &self,
        body: &[u8],
    ) -> CustomResult<api::IncomingWebhookEvent, errors::ConnectorError> {
        let webhook: checkout::CheckoutWebhookObjectResource = body
            .parse_struct("CheckoutIncomingWebhook")
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;
        Ok(match webhook.event_type {
            checkout::CheckoutWebhookEventType::AuthenticationFailed
            | checkout::CheckoutWebhookEventType::Declined => {
                api::IncomingWebhookEvent::PaymentIntentFailure
            }
            checkout::CheckoutWebhookEventType::Captured => {
                api::IncomingWebhookEvent::PaymentIntentSuccess
            }
        })
    }

    fn get_webhook_resource_object(
        &self,
        body: &[u8],
    ) -> CustomResult<serde_json::Value, errors::ConnectorError> {
        let mut webhook: checkout::CheckoutWebhookObjectResource = body
            .parse_struct("CheckoutWebhookObjectResource")
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;
        // In case of success response we will call PSync's handle_response considering we are receiving payment entity from the connector. Checkout webhook body differs from Psyn's response so to keep the fields identical we are mapping status from the incomin webhook event type.
        webhook.data["status"] = serde_json::Value::String(format!(
            "{:?}",
            transformers::CheckoutPaymentStatus::from(webhook.event_type)
        ));
        Ok(webhook.data)
    }
}

impl services::ConnectorRedirectResponse for Checkout {
    fn get_flow_type(
        &self,
        query_params: &str,
    ) -> CustomResult<payments::CallConnectorAction, errors::ConnectorError> {
        let query =
            serde_urlencoded::from_str::<transformers::CheckoutRedirectResponse>(query_params)
                .into_report()
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        Ok(query
            .status
            .map(|checkout_status| {
                payments::CallConnectorAction::StatusUpdate(checkout_status.into())
            })
            .unwrap_or(payments::CallConnectorAction::Trigger))
    }
}
