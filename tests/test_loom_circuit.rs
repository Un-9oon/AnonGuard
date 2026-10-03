#![allow(unexpected_cfgs)]
#![cfg(loom)]

use loom::sync::{Arc, Mutex, RwLock};
use loom::thread;
use std::collections::HashMap;

#[test]
fn test_lock_ordering_tracker() {
    loom::model(|| {
        struct ReverseNodeEntry {
            streams: Arc<Mutex<Vec<u32>>>,
        }

        let directory = Arc::new(RwLock::new(HashMap::new()));

        // Initial state setup
        {
            let mut dir = directory.write().unwrap();
            dir.insert(
                "node1".to_string(),
                ReverseNodeEntry {
                    streams: Arc::new(Mutex::new(Vec::new())),
                },
            );
        }

        let dir_clone1 = directory.clone();
        let dir_clone2 = directory.clone();

        let t1 = thread::spawn(move || {
            // Thread 1: CONNECT_REVERSE behavior
            // Drops the Directory lock before acquiring streams
            let streams_arc = {
                let dir = dir_clone1.read().unwrap();
                dir.get("node1").map(|entry| entry.streams.clone())
            };
            if let Some(streams) = streams_arc {
                let mut s = streams.lock().unwrap();
                s.push(1);
            }
        });

        let t2 = thread::spawn(move || {
            // Thread 2: REGISTER_REVERSE behavior
            // Holds Directory while acquiring streams
            let dir = dir_clone2.read().unwrap();
            if let Some(entry) = dir.get("node1") {
                let mut s = entry.streams.lock().unwrap();
                s.push(2);
            }
        });

        t1.join().unwrap();
        t2.join().unwrap();
    });
}
