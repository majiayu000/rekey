//! Test doubles required by the spec's headless testing layer. Production
//! code must never construct these; tests inject them through
//! `BrokerConfig::transport`.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use crate::upstream::{
    UpstreamError, UpstreamFuture, UpstreamRequest, UpstreamResponse, UpstreamTransport,
};

struct QueuedResponse {
    delay: Duration,
    response: Result<UpstreamResponse, UpstreamError>,
}

fn lock_test_mutex<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub struct RecordedRequest {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub auth_name: String,
    pub auth_value: Vec<u8>,
    pub body: Vec<u8>,
}

#[derive(Default)]
pub struct FakeUpstreamTransport {
    responses: Mutex<VecDeque<QueuedResponse>>,
    pub requests: Mutex<Vec<RecordedRequest>>,
}

impl FakeUpstreamTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(&self, response: Result<UpstreamResponse, UpstreamError>) {
        self.push_response_delayed(response, Duration::ZERO);
    }

    pub fn push_response_delayed(
        &self,
        response: Result<UpstreamResponse, UpstreamError>,
        delay: Duration,
    ) {
        lock_test_mutex(&self.responses).push_back(QueuedResponse { delay, response });
    }

    pub fn take_requests(&self) -> Vec<RecordedRequest> {
        std::mem::take(&mut lock_test_mutex(&self.requests))
    }
}

impl UpstreamTransport for FakeUpstreamTransport {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(async move {
            lock_test_mutex(&self.requests).push(RecordedRequest {
                host: request.host.clone(),
                port: request.port,
                method: request.method.as_str().to_owned(),
                path: request.path.clone(),
                headers: request.headers.clone(),
                auth_name: request.auth_header.0.clone(),
                auth_value: request.auth_header.1.to_vec(),
                body: request.body.clone(),
            });
            let queued = lock_test_mutex(&self.responses).pop_front();
            if let Some(queued) = queued {
                if !queued.delay.is_zero() {
                    tokio::time::sleep(queued.delay).await;
                }
                queued.response
            } else {
                Ok(UpstreamResponse {
                    status: 200,
                    headers: vec![("content-type".to_owned(), "application/json".to_owned())]
                        .into(),
                    body: b"{\"ok\":true}".to_vec().into(),
                })
            }
        })
    }
}
