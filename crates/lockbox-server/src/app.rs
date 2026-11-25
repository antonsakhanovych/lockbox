use std::sync::Arc;

use crate::adapters::driven::{DelayScheduler, ExpiryWorker};
use crate::core::ports::driven::{Clock, ExpiryScheduler, FileStore};
use crate::core::services::{Challenges, Deletes, Expiry, Fetches, Registry, Uploads};

pub trait Ports {
    type Clock: Clock;
    type Store: FileStore;
    type Scheduler: ExpiryScheduler;
}

impl<C, S, X> Ports for (C, S, X)
where
    C: Clock,
    S: FileStore,
    X: ExpiryScheduler,
{
    type Clock = C;
    type Store = S;
    type Scheduler = X;
}

pub struct Assembled<C, S>
where
    C: Clock,
    S: FileStore,
{
    pub services: Arc<Services<(C, S, DelayScheduler)>>,
    pub worker: ExpiryWorker<C, S>,
}

pub struct Services<P>
where
    P: Ports,
{
    pub challenges: Challenges<P::Clock>,
    pub uploads: Uploads<P::Clock, P::Store, P::Scheduler>,
    pub fetches: Fetches<P::Clock, P::Store>,
    pub deletes: Deletes<P::Clock, P::Store>,
}

impl<P> Services<P>
where
    P: Ports,
{
    pub fn new(
        clock: Arc<P::Clock>,
        store: Arc<P::Store>,
        registry: Arc<Registry<P::Clock>>,
        scheduler: Arc<P::Scheduler>,
    ) -> Self {
        Self {
            challenges: Challenges::new(clock),
            uploads: Uploads::new(registry.clone(), store.clone(), scheduler),
            fetches: Fetches::new(registry.clone(), store.clone()),
            deletes: Deletes::new(registry, store),
        }
    }
}

pub fn assemble<C, S>(clock: Arc<C>, store: Arc<S>) -> Assembled<C, S>
where
    C: Clock,
    S: FileStore,
{
    let registry = Arc::new(Registry::new(clock.clone()));
    let expiry = Arc::new(Expiry::new(registry.clone(), store.clone()));
    let (scheduler, worker) = DelayScheduler::new(clock.clone(), expiry);
    let services = Services::new(clock, store, registry, Arc::new(scheduler));
    Assembled {
        services: Arc::new(services),
        worker,
    }
}
