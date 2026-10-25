use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use re0auth_api::Clock;
use re0auth_api::schedule::{ScheduledTask, TaskError};
use tokio_util::sync::CancellationToken;

use super::*;

struct TestClock(AtomicI64);

impl TestClock {
    fn new(now: Unix) -> Self {
        Self(AtomicI64::new(now))
    }

    fn advance(&self, seconds: i64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Unix {
        self.0.load(Ordering::SeqCst)
    }
}

struct CountingTask {
    name: &'static str,
    interval: Duration,
    runs: AtomicUsize,
    fail: bool,
}

impl CountingTask {
    fn new(name: &'static str, interval: Duration) -> Self {
        Self {
            name,
            interval,
            runs: AtomicUsize::new(0),
            fail: false,
        }
    }

    fn failing(name: &'static str) -> Self {
        Self {
            fail: true,
            ..Self::new(name, Duration::from_secs(10))
        }
    }

    fn runs(&self) -> usize {
        self.runs.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ScheduledTask for CountingTask {
    fn name(&self) -> &'static str {
        self.name
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    async fn run(&self) -> Result<(), TaskError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(TaskError::failed("boom"));
        }
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn runs_each_task_once_at_startup() {
    let clock = Arc::new(TestClock::new(1_000));
    let shutdown = CancellationToken::new();
    let task = Arc::new(CountingTask::new("sweep", Duration::from_secs(600)));

    let scheduler =
        Scheduler::new(clock.clone(), shutdown.clone()).with_tick(Duration::from_secs(1));
    let handle = scheduler.start(vec![task.clone() as Arc<dyn ScheduledTask>]);

    // The first tick of `tokio::time::interval` is immediate; yield until the
    // startup pass has run instead of sleeping for a wall-clock duration.
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    assert_eq!(task.runs(), 1, "startup pass must run exactly once");

    shutdown.cancel();
    let _ = handle.await;
}

#[tokio::test(start_paused = true)]
async fn interval_is_measured_on_the_injected_clock() {
    // A ten-minute interval must not run twice in two minutes of clock time,
    // and must run again once the clock passes the interval. Driving `tokio`
    // time and the `Clock` port together is what makes this observable.
    let clock = Arc::new(TestClock::new(1_000));
    let shutdown = CancellationToken::new();
    let task = Arc::new(CountingTask::new("sweep", Duration::from_secs(600)));

    let scheduler =
        Scheduler::new(clock.clone(), shutdown.clone()).with_tick(Duration::from_secs(1));
    let handle = scheduler.start(vec![task.clone() as Arc<dyn ScheduledTask>]);

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(task.runs(), 1);

    // Advance both clocks by two minutes: not yet due.
    clock.advance(120);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        task.runs(),
        1,
        "two minutes is inside a ten-minute interval"
    );

    // Advance past the interval.
    clock.advance(600);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(task.runs(), 2, "the task is due again after its interval");

    shutdown.cancel();
    let _ = handle.await;
}

#[tokio::test(start_paused = true)]
async fn a_failing_task_does_not_stop_the_others() {
    let clock = Arc::new(TestClock::new(1_000));
    let shutdown = CancellationToken::new();
    let broken = Arc::new(CountingTask::failing("broken"));
    let healthy = Arc::new(CountingTask::new("healthy", Duration::from_secs(10)));

    let scheduler = Scheduler::new(clock, shutdown.clone()).with_tick(Duration::from_secs(1));
    let handle = scheduler.start(vec![
        broken.clone() as Arc<dyn ScheduledTask>,
        healthy.clone() as Arc<dyn ScheduledTask>,
    ]);

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(broken.runs(), 1, "the broken task still ran");
    assert_eq!(
        healthy.runs(),
        1,
        "the healthy task ran despite the failure"
    );

    shutdown.cancel();
    let _ = handle.await;
}

#[tokio::test(start_paused = true)]
async fn shutdown_stops_the_loop() {
    let clock = Arc::new(TestClock::new(1_000));
    let shutdown = CancellationToken::new();
    let task = Arc::new(CountingTask::new("sweep", Duration::from_secs(1)));

    let scheduler =
        Scheduler::new(clock.clone(), shutdown.clone()).with_tick(Duration::from_secs(1));
    let handle = scheduler.start(vec![task.clone() as Arc<dyn ScheduledTask>]);

    tokio::time::sleep(Duration::from_millis(200)).await;
    shutdown.cancel();

    // The loop exits promptly rather than waiting for the next tick.
    let finished = tokio::time::timeout(Duration::from_secs(5), handle).await;
    assert!(finished.is_ok(), "scheduler must observe shutdown");

    let after_cancel = task.runs();
    clock.advance(60);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(task.runs(), after_cancel, "no task may run after shutdown");
}

#[tokio::test(start_paused = true)]
async fn an_empty_task_list_returns_immediately() {
    let clock = Arc::new(TestClock::new(1_000));
    let shutdown = CancellationToken::new();
    let scheduler = Scheduler::new(clock, shutdown);
    // No tasks: `run` must not park a task forever.
    let finished = tokio::time::timeout(Duration::from_secs(1), scheduler.run(Vec::new())).await;
    assert!(finished.is_ok());
}

#[test]
fn scan_interval_tracks_the_shortest_task() {
    let short =
        Arc::new(CountingTask::new("short", Duration::from_secs(8))) as Arc<dyn ScheduledTask>;
    let long =
        Arc::new(CountingTask::new("long", Duration::from_secs(3600))) as Arc<dyn ScheduledTask>;
    assert_eq!(
        scan_interval(&[long.clone(), short.clone()]),
        Duration::from_secs(2),
        "a quarter of the shortest interval"
    );

    // A sub-second interval must not spin.
    let fast =
        Arc::new(CountingTask::new("fast", Duration::from_millis(10))) as Arc<dyn ScheduledTask>;
    assert_eq!(scan_interval(&[fast]), Duration::from_secs(1));

    // An hour-long interval must still be observed within a minute.
    let slow =
        Arc::new(CountingTask::new("slow", Duration::from_secs(86_400))) as Arc<dyn ScheduledTask>;
    assert_eq!(scan_interval(&[slow]), Duration::from_secs(60));
}
