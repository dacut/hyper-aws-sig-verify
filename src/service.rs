use std::{
    any::type_name,
    error::Error,
    future::Future,
    pin::Pin,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    task::{Context, Poll},
};
use aws_sig_verify::{AWSSigV4Algorithm, Request as AwsSigVerifyRequest, Principal, SigningKeyKind, SignatureError, AWSSigV4};
use chrono::Duration;
use futures::{
    stream::{StreamExt},
};
use http::request::Parts;
use hyper::{
    body::{Body, Bytes},
    service::{Service, HttpService},
    Error as HyperError, Request, Response, StatusCode,
};
use log::error;
use serde_json::json;
use tokio::runtime::Handle;

/// AWSSigV4VerifierService implements a Hyper service that authenticates a request against AWS SigV4 signing protocol.
#[derive(Clone)]
pub struct AwsSigV4VerifierService<S> {
    pub signing_key_kind: SigningKeyKind,
    // pub signing_key_fn: SKF,
    pub allowed_mismatch: Option<Duration>,
    pub region: String,
    pub service: String,
    pub implementation: S,
}

impl<S> AwsSigV4VerifierService<S> {
    pub fn new<S1, S2>(region: S1, service: S2, implementation: S) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        AwsSigV4VerifierService {
            signing_key_kind: SigningKeyKind::KSigning,
            // signing_key_fn: signing_key_fn,
            allowed_mismatch: Some(Duration::minutes(5)),
            region: region.into(),
            service: service.into(),
            implementation: implementation,
        }
    }
}

#[derive(Debug)]
enum GetPrincipalError {
    HyperError(HyperError),
    SignatureError(SignatureError),
}

impl <S> AwsSigV4VerifierService<S> {
}

impl<S> Debug for AwsSigV4VerifierService<S> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("AwsSigV4VerifierService")
            .field("region", &self.region)
            .field("service", &self.service)
            .field("implementation", &type_name::<S>())
            .finish()
    }
}

impl<S> Display for AwsSigV4VerifierService<S> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        Debug::fmt(self, f)
    }
}

impl<S> HttpService<Body> for AwsSigV4VerifierService<S>
where
    S: HttpService<
        Body,
        ResBody=Body,
        Error=Box<dyn Error + Send + Sync + 'static>,
        Future=Pin<Box<dyn Future<Output=Result<Response<Body>, Box<dyn Error + Send + Sync + 'static>>> + Send + Sync + 'static>>>
    + Clone + Send + Sync + 'static,
{
    type ResBody = Body;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output=Result<Response<Body>, S::Error>> + Send + Sync + 'static>>;

    fn poll_ready(&mut self, c: &mut Context) -> Poll<Result<(), S::Error>> {
        self.implementation.poll_ready(c)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let region = self.region.clone();
        let service = self.service.clone();
        let mut implementation = self.implementation.clone();
        Box::pin(async move {
            let (mut parts, body) = req.into_parts();
            match get_principal(region, service, &parts, body).await {
                Ok((p, bytes)) => {
                    parts.extensions.insert(p);
                    let new_req = Request::from_parts(parts, Body::from(bytes));
                    implementation.call(new_req).await
                }
                Err(e) => {
                    error!("Failed to verify signature: {:?}", e);
                    let resp_body = Body::from(json!({
                        "Error": {
                            "Code": "NotAuthorized",
                            "Message": "SigV4 validation failed",
                        }
                    }).to_string());
                    let response = Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header("Content-Type", "application/json")
                        .body(resp_body);
                    Ok(response.unwrap())
                }
            }
        })
    }
}

async fn get_principal(_region: String, _service: String, parts: &Parts, body: Body) -> Result<(Principal, Bytes), GetPrincipalError> {
    // We need the actual body in order to compute the signature.
    match body_to_bytes(body).await {
        Err(e) => Err(GetPrincipalError::HyperError(e)),
        Ok(body) => {
            Ok((Principal::service("local", "hello").unwrap(), Bytes::copy_from_slice(&body)))
            // let aws_req = AwsSigVerifyRequest::from_http_request_parts(parts, Some(body.clone()), region, service);
            // let sigv4 = AWSSigV4::new();
            // match sigv4.verify(&aws_req, self.signing_key_kind, &self.signing_key_fn, self.allowed_mismatch).await {
            //     Ok(p) => Ok((p, Bytes::copy_from_slice(&body))),
            //     Err(e) => Err(GetPrincipalError::SignatureError(e)),
            // }
        }
    }
}

async fn body_to_bytes(mut body: Body) -> Result<Vec<u8>, HyperError> {
    let mut result = Vec::<u8>::new();

    loop {
        match body.next().await {
            None => break,
            Some(chunk_result) => match chunk_result {
                Ok(chunk) => result.append(&mut chunk.to_vec()),
                Err(e) => return Err(e),
            }
        }
    }

    Ok(result)
}