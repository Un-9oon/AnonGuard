#![no_main]

use anonguard::mesh::node::ProxyNode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = ProxyNode::parse(data);
});
