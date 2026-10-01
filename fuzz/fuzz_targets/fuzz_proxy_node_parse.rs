#![no_main]

use libfuzzer_sys::fuzz_target;
use anonguard::mesh::node::ProxyNode;

fuzz_target!(|data: &str| {
    let _ = ProxyNode::parse(data);
});
