use rusb;
use usbredirhost::{Device, DeviceHandler};

#[derive(Debug)]
struct Handler {
    test: i32,
}

impl DeviceHandler for Handler {
    fn log(&mut self, level: i32, msg: &str) {
        eprintln!("log-{}: {}", level, msg);
    }

    fn flush_writes(&mut self) {
        dbg!("flush writes");
        dbg!(self);
    }

    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        dbg!(buf);
        unimplemented!()
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        dbg!(buf);
        unimplemented!()
    }
}

#[test]
fn test() {
    let ctxt = rusb::Context::new().unwrap();
    let handler = Handler { test: 32 };
    let host = Device::new::<rusb::Context>(&ctxt, None, handler, 10);
    dbg!(host);
}
