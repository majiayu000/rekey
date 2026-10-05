//! BrokerRuntime-owned execution tasks. This is deliberately not a generic
//! task framework: it owns only fixed Action admission, effect, and response.

use std::sync::Arc;

use rekey_vault::AuthorityError;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinError, JoinSet};

use crate::error::BrokerError;
use crate::executor::text_stream::{TextStreamEvent, TextStreamSender};
use crate::executor::{
    ActionExecutor, AdmittedExecution, ExecuteOutcome, ExecuteRequest, LocalExecuteRequest,
};
use rekey_domain::ipc::TextStreamStatus;

const EXECUTION_QUEUE_CAPACITY: usize = 120;

struct ExecutionJob {
    request: ExecutionRequest,
    response: ExecutionResponse,
}
enum ExecutionRequest {
    Action(ExecuteRequest),
    Local(LocalExecuteRequest),
}
impl ExecutionRequest {
    async fn admit(
        self,
        executor: &Arc<ActionExecutor>,
        http: bool,
        stream: bool,
    ) -> Result<AdmittedExecution, BrokerError> {
        match self {
            Self::Local(request) => executor.admit_connection(request).await,
            Self::Action(request) if http => executor.admit_http(request).await,
            Self::Action(request) if stream => executor.admit_stream(request).await,
            Self::Action(request) => executor.admit(request).await,
        }
    }
}
enum ExecutionResponse {
    Buffered(oneshot::Sender<Result<ExecuteOutcome, BrokerError>>),
    Stream(TextStreamSender),
    Http(oneshot::Sender<Result<HttpExecution, BrokerError>>),
}

pub(crate) enum HttpExecution {
    Buffered(ExecuteOutcome),
    Stream(mpsc::Receiver<TextStreamEvent>),
}

enum SupervisorEvent {
    Shutdown,
    Child(Option<Result<(), JoinError>>),
    Job(Option<Box<ExecutionJob>>),
}

async fn next_event(
    shutdown: &mut watch::Receiver<bool>,
    rx: &mut mpsc::Receiver<ExecutionJob>,
    tasks: &mut JoinSet<()>,
) -> SupervisorEvent {
    tokio::select! {
        biased;
        _ = shutdown.changed() => SupervisorEvent::Shutdown,
        result = tasks.join_next(), if !tasks.is_empty() => SupervisorEvent::Child(result),
        job = rx.recv() => SupervisorEvent::Job(job.map(Box::new)),
    }
}

#[derive(Clone)]
pub(crate) struct ExecutionSupervisorHandle {
    tx: mpsc::Sender<ExecutionJob>,
}

pub(crate) struct ExecutionSupervisor {
    executor: Arc<ActionExecutor>,
    rx: mpsc::Receiver<ExecutionJob>,
    tasks: JoinSet<()>,
}

pub(crate) fn new(
    executor: Arc<ActionExecutor>,
) -> (ExecutionSupervisorHandle, ExecutionSupervisor) {
    let (tx, rx) = mpsc::channel(EXECUTION_QUEUE_CAPACITY);
    (
        ExecutionSupervisorHandle { tx },
        ExecutionSupervisor {
            executor,
            rx,
            tasks: JoinSet::new(),
        },
    )
}

impl ExecutionSupervisorHandle {
    pub(crate) async fn submit_local(
        &self,
        request: LocalExecuteRequest,
    ) -> Result<oneshot::Receiver<Result<HttpExecution, BrokerError>>, BrokerError> {
        let (response, result) = oneshot::channel();
        self.tx
            .send(ExecutionJob {
                request: ExecutionRequest::Local(request),
                response: ExecutionResponse::Http(response),
            })
            .await
            .map_err(|_| BrokerError::Authority(AuthorityError::Draining))?;
        Ok(result)
    }

    pub(crate) async fn submit_stream(
        &self,
        request: ExecuteRequest,
    ) -> Result<mpsc::Receiver<TextStreamEvent>, BrokerError> {
        let (response, result) = mpsc::channel(1);
        self.tx
            .send(ExecutionJob {
                request: ExecutionRequest::Action(request),
                response: ExecutionResponse::Stream(response),
            })
            .await
            .map_err(|_| BrokerError::Authority(AuthorityError::Draining))?;
        Ok(result)
    }
    /// The caller owns only the response receiver. Once the job is accepted,
    /// dropping that receiver cannot cancel admission or an admitted effect.
    pub(crate) async fn submit(
        &self,
        request: ExecuteRequest,
    ) -> Result<oneshot::Receiver<Result<ExecuteOutcome, BrokerError>>, BrokerError> {
        let (response, result) = oneshot::channel();
        self.tx
            .send(ExecutionJob {
                request: ExecutionRequest::Action(request),
                response: ExecutionResponse::Buffered(response),
            })
            .await
            .map_err(|_| BrokerError::Authority(AuthorityError::Draining))?;
        Ok(result)
    }
}

impl ExecutionSupervisor {
    pub(crate) async fn run(
        mut self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), BrokerError> {
        let mut first_error = None;
        if !*shutdown.borrow() {
            loop {
                match next_event(&mut shutdown, &mut self.rx, &mut self.tasks).await {
                    SupervisorEvent::Shutdown => {
                        self.rx.close();
                        break;
                    }
                    SupervisorEvent::Child(result) => {
                        if result.is_some_and(|result| result.is_err()) {
                            first_error
                                .get_or_insert(BrokerError::Authority(AuthorityError::Faulted));
                            self.rx.close();
                            break;
                        }
                    }
                    SupervisorEvent::Job(job) => {
                        let Some(job) = job else { break };
                        let executor = Arc::clone(&self.executor);
                        self.tasks.spawn(async move {
                            match job.response {
                                ExecutionResponse::Http(response) => {
                                    match job.request.admit(&executor, true, false).await {
                                        Ok(admitted) if admitted.raw_stream() => {
                                            let (sender, receiver) = mpsc::channel(1);
                                            let _ =
                                                response.send(Ok(HttpExecution::Stream(receiver)));
                                            let _ = sender
                                                .send(TextStreamEvent::Admitted {
                                                    deadline: admitted.deadline(),
                                                })
                                                .await;
                                            let status = match admitted.run_stream(&sender).await {
                                                Ok(outcome) if outcome.stream_status.is_none() => {
                                                    let _ = tokio::time::timeout(
                                                        std::time::Duration::from_secs(1),
                                                        sender.send(TextStreamEvent::Buffered(
                                                            outcome,
                                                        )),
                                                    )
                                                    .await;
                                                    return;
                                                }
                                                Ok(outcome) => outcome
                                                    .stream_status
                                                    .unwrap_or(TextStreamStatus::Failed),
                                                Err(error) => {
                                                    // Before the first chunk the gateway can still
                                                    // return the original safe error envelope. After
                                                    // a chunk this event aborts the HTTP body.
                                                    let _ = tokio::time::timeout(
                                                        std::time::Duration::from_secs(1),
                                                        sender.send(
                                                            TextStreamEvent::AdmissionError(error),
                                                        ),
                                                    )
                                                    .await;
                                                    return;
                                                }
                                            };
                                            let _ = tokio::time::timeout(
                                                std::time::Duration::from_secs(1),
                                                sender.send(TextStreamEvent::Terminal(status)),
                                            )
                                            .await;
                                        }
                                        Ok(admitted) => {
                                            let outcome =
                                                admitted.run().await.map(HttpExecution::Buffered);
                                            let _ = response.send(outcome);
                                        }
                                        Err(error) => {
                                            let _ = response.send(Err(error));
                                        }
                                    }
                                }
                                ExecutionResponse::Buffered(response) => {
                                    let outcome =
                                        match job.request.admit(&executor, false, false).await {
                                            Ok(admitted) => admitted.run().await,
                                            Err(err) => Err(err),
                                        };
                                    let _ = response.send(outcome);
                                }
                                ExecutionResponse::Stream(response) => {
                                    let outcome =
                                        match job.request.admit(&executor, false, true).await {
                                            Ok(admitted) => {
                                                let _ = response
                                                    .send(TextStreamEvent::Admitted {
                                                        deadline: admitted.deadline(),
                                                    })
                                                    .await;
                                                admitted.run_stream(&response).await
                                            }
                                            Err(err) => {
                                                let _ = tokio::time::timeout(
                                                    std::time::Duration::from_secs(1),
                                                    response
                                                        .send(TextStreamEvent::AdmissionError(err)),
                                                )
                                                .await;
                                                return;
                                            }
                                        };
                                    let status = outcome
                                        .ok()
                                        .and_then(|o| o.stream_status)
                                        .unwrap_or(TextStreamStatus::Failed);
                                    // Bound terminal backpressure too. If it cannot be delivered,
                                    // closing the stream remains an explicit client failure.
                                    let _ = tokio::time::timeout(
                                        std::time::Duration::from_secs(1),
                                        response.send(TextStreamEvent::Terminal(status)),
                                    )
                                    .await;
                                }
                            }
                        });
                    }
                }
            }
        }
        self.rx.close();
        while let Some(result) = self.tasks.join_next().await {
            if result.is_err() {
                first_error.get_or_insert(BrokerError::Authority(AuthorityError::Faulted));
            }
        }
        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use rekey_domain::capability::ActionVersionRef;
    use rekey_domain::ids::{ActionId, RequestId};
    use tokio::sync::Barrier;

    use super::*;

    fn queued_job() -> ExecutionJob {
        let (response, _) = oneshot::channel();
        ExecutionJob {
            request: ExecutionRequest::Action(ExecuteRequest {
                request_id: RequestId::new_random(),
                capability_token: String::new(),
                action: ActionVersionRef {
                    action_id: ActionId::new_random(),
                    version: 1,
                },
                content_type: None,
                extra_headers: Vec::new(),
                params: Default::default(),
                query: Default::default(),
                body: Vec::new(),
                approval_grants: Vec::new(),
                local_approval_request_id: None,
            }),
            response: ExecutionResponse::Buffered(response),
        }
    }

    #[tokio::test]
    async fn ready_child_panic_wins_over_saturated_admission_queue() {
        let (tx, mut rx) = mpsc::channel(EXECUTION_QUEUE_CAPACITY);
        for _ in 0..EXECUTION_QUEUE_CAPACITY {
            tx.try_send(queued_job()).expect("fill execution queue");
        }
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let barrier = Arc::new(Barrier::new(2));
        let child_barrier = Arc::clone(&barrier);
        let mut tasks = JoinSet::new();
        let child = tasks.spawn(async move {
            child_barrier.wait().await;
            panic!("injected ready child panic");
        });
        barrier.wait().await;
        while !child.is_finished() {
            tokio::task::yield_now().await;
        }

        let event = tokio::time::timeout(
            Duration::from_secs(1),
            next_event(&mut shutdown, &mut rx, &mut tasks),
        )
        .await
        .expect("ready child fault must be observed without blocking");
        assert!(matches!(event, SupervisorEvent::Child(Some(Err(_)))));
        assert_eq!(
            rx.len(),
            EXECUTION_QUEUE_CAPACITY,
            "queued admission won after child panic"
        );
    }
}
