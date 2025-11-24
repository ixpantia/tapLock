use jsonwebtoken::jwk::{Jwk, JwkSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;

use crate::error::TapLockError;

#[derive(Clone)]
pub struct JwksClient {
    url: String,
    // Use std::sync::RwLock for fast, synchronous reads during validation
    jwks: Arc<RwLock<JwkSet>>,
    client: reqwest::Client,
    // Async mutex to ensure only one thread performs the network refresh
    refresh_lock: Arc<AsyncMutex<()>>,
    // Track last refresh to prevent spam
    last_updated: Arc<Mutex<Instant>>,
}

impl JwksClient {
    pub async fn new(url: String, client: reqwest::Client) -> Result<Self, TapLockError> {
        // Initial fetch
        let jwks = client.get(&url).send().await?.json::<JwkSet>().await?;

        Ok(Self {
            url,
            jwks: Arc::new(RwLock::new(jwks)),
            client,
            refresh_lock: Arc::new(AsyncMutex::new(())),
            last_updated: Arc::new(Mutex::new(Instant::now())),
        })
    }

    pub fn get_key(&self, kid: &str) -> Option<Jwk> {
        let jwks = self.jwks.read().expect("jwks lock poisoned");
        jwks.find(kid).cloned()
    }

    pub async fn get_key_with_refresh(&self, kid: &str) -> Result<Jwk, TapLockError> {
        // 1. Fast path: Check if we already have it
        if let Some(key) = self.get_key(kid) {
            return Ok(key);
        }

        // 2. Slow path: Acquire lock to refresh
        let _guard = self.refresh_lock.lock().await;

        // 3. Double-check: Someone else might have refreshed while we waited for the lock
        if let Some(key) = self.get_key(kid) {
            return Ok(key);
        }

        // 4. Rate limit check
        {
            let mut last = self.last_updated.lock().expect("time lock poisoned");
            if last.elapsed() < Duration::from_secs(10) {
                // We just refreshed recently and still didn't find it.
                // The key genuinely doesn't exist or we are being spammed.
                return Err(TapLockError::KidNotFound);
            }
            *last = Instant::now();
        }

        // 5. Perform the network request
        let new_jwks = self
            .client
            .get(&self.url)
            .send()
            .await?
            .json::<JwkSet>()
            .await?;

        // 6. Update the cache
        let found_key = new_jwks.find(kid).cloned();
        {
            let mut w = self.jwks.write().expect("jwks lock poisoned");
            *w = new_jwks;
        }

        found_key.ok_or(TapLockError::KidNotFound)
    }
}
