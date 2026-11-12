use std::sync::Arc;

pub type AssetTaskFuture = futures_util::future::BoxFuture<'static, ()>;
pub type SharedAssetTaskSpawner = Arc<dyn AssetTaskSpawner>;

pub trait AssetTaskSpawner: Send + Sync {
    fn spawn(&self, future: AssetTaskFuture);
}

impl<F> AssetTaskSpawner for F
where
    F: Fn(AssetTaskFuture) + Send + Sync + 'static,
{
    fn spawn(&self, future: AssetTaskFuture) {
        self(future);
    }
}
