use std::time::{SystemTime, UNIX_EPOCH};

use re0auth_api::{Clock, Unix};

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Unix {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs() as Unix)
    }
}
