//! BrokerRuntime-owned execution tasks. This is deliberately not a generic
//! task framework: it owns only fixed Action admission, effect, and response.

use std::sync::Arc;

use rekey_vault::AuthorityError;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;

use crate::error::BrokerError;
use crate::executor::{ActionExecutor, ExecuteOutcome, ExecuteRequest};

const EXECUTION_QUEUE_CAPACITY: usize = 120;

struct ExecutionJob {
    request: ExecuteRequest,
    response: oneshot::Sender<Result<ExecuteOutcome, BrokerError>>,
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
    /// The caller owns only the response receiver. Once the job is accepted,
    /// dropping that receiver cannot cancel admission or an admitted effect.
    pub(crate) async fn submit(
        &self,
        request: ExecuteRequest,
    ) -> Result<oneshot::Receiver<Result<ExecuteOutcome, BrokerError>>, BrokerError> {
        let (response, result) = oneshot::channel();
        self.tx
            .send(ExecutionJob { request, response })
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
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => {
                        self.rx.close();
                        break;
                    }
                    job = self.rx.recv() => {
                        let Some(job) = job else { break };
                        let executor = Arc::clone(&self.executor);
                        self.tasks.spawn(async move {
                            let outcome = match executor.admit(job.request).await {
                                Ok(admitted) => admitted.run().await,
                                Err(err) => Err(err),
                            };
                            let _ = job.response.send(outcome);
                        });
                    }
                    result = self.tasks.join_next(), if !self.tasks.is_empty() => {
                        if result.is_some_and(|result| result.is_err()) {
                            first_error.get_or_insert(BrokerError::Authority(AuthorityError::Faulted));
                        }
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
