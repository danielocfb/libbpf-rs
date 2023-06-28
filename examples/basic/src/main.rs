// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::Result;
use libbpf_rs::RingBuffer;
use libbpf_rs::RingBufferBuilder;

use crate::basic::BasicSkelBuilder;

mod basic {
    include!(concat!(env!("OUT_DIR"), "/basic.skel.rs"));
}

pub(crate) struct Bpf<'a> {
    /// BPF ring buffer
    ring_buffer: RingBuffer<'a>,
}

impl Bpf<'_> {
    pub(crate) fn with() -> Result<Self> {
        let mut skel = BasicSkelBuilder::default().open()?.load()?;

        let handle_raw_buffer = |data: &[u8]| -> i32 { 0 };

        let maps = skel.maps();
        let mut ring_builder = RingBufferBuilder::new();
        ring_builder.add(maps.events(), handle_raw_buffer)?;
        let ring_buffer = ring_builder.build()?;

        Ok(Self { ring_buffer })
    }
}

fn main() {
    let _bpf = Bpf::with().unwrap();
    //let mut _skel_builder = BasicSkelBuilder::default();
}
