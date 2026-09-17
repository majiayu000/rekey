//! BrokerRuntime-owned execution tasks. This is deliberately not a generic
//! task framework: it owns only fixed Action admission, effect, and response.

use std::sync::Arc;

use rekey_vault::AuthorityError;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinError, JoinSet};

use crate::error::BrokerError;
use crate::executor::text_stream::{TextStreamEvent, TextStreamSender};
use crate::executor::{ActionExecutor, ExecuteOutcome, ExecuteRequest};
use rekey_domain::ipc::TextStreamStatus;

const EXECUTION_QUEUE_CAPACITY: usize = 120;

struct ExecutionJob {
    request: ExecuteRequest,
    response: ExecutionResponse,
}
enum ExecutionResponse {
    Buffered(oneshot::Sender<Result<ExecuteOutcome, BrokerError>>),
    Stream(TextStreamSender),
}

enum SupervisorEvent {
    Shutdown,
    Child(Option<Result<(), JoinError>>),
    Job(Option<ExecutionJob>),
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
        job = rx.recv() => SupervisorEvent::Job(job),
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
    pub(crate) async fn submit_stream(
        &self,
        request: ExecuteRequest,
    ) -> Result<mpsc::Receiver<TextStreamEvent>, BrokerError> {
        let (response, result) = mpsc::channel(1);
        self.tx
            .send(ExecutionJob {
                request,
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
                request,
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
                                ExecutionResponse::Buffered(response) => {
                                    let outcome = match executor.admit(job.request).await {
                                        Ok(admitted) => admitted.run().await,
                                        Err(err) => Err(err),
                                    };
                                    let _ = response.send(outcome);
                                }
                                ExecutionResponse::Stream(response) => {
                                    let outcome = match executor.admit(job.request).await {
                                        Ok(admitted) => {
                                            let _ = response
                                                .send(TextStreamEvent::Admitted {
                                                    deadline: admitted.deadline(),
                                                })
                                                .await;
                                            admitted.run_stream(&response).await
                                        }
                                        Err(err) => Err(err),
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
            request: ExecuteRequest {
                request_id: RequestId::new_random(),
                capability_token: String::new(),
                action: ActionVersionRef {
                    action_id: ActionId::new_random(),
                    version: 1,
                },
                content_type: None,
                extra_headers: Vec::new(),
                body: Vec::new(),
                approval_grants: Vec::new(),
            },
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
