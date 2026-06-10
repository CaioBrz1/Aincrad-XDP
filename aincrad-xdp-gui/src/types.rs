use chrono::{DateTime, Utc, Duration};
use std::net::Ipv4Addr;

pub struct BannedClient {
    pub ip: Ipv4Addr,
    pub ban_until: DateTime<Utc>,
    pub total_duration: Duration,
}

impl BannedClient {
    pub fn cooldown_percentage(&self) -> f32 {
        let now = Utc::now();
        if now >= self.ban_until {
            return 0.0;
        }
        let remaining = self.ban_until.signed_duration_since(now);
        
        let pct = remaining.num_milliseconds() as f32 / self.total_duration.num_milliseconds() as f32;
        pct.clamp(0.0, 1.0)
    }
}

pub struct BlockHistory {
    pub timestamps: Vec<DateTime<Utc>>,
}

impl BlockHistory {
    pub fn new() -> Self {
        Self { timestamps: Vec::new() }
    }

    pub fn push_block(&mut self) {
        self.timestamps.push(Utc::now());
    }

    pub fn clean_expired_blocks(&mut self) {
        let one_hour_ago = Utc::now() - Duration::hours(1);
        self.timestamps.retain(|&t| t > one_hour_ago);
    }

    pub fn count_last_hour(&self) -> usize {
        self.timestamps.len()
    }
}
