use usbredirparser::{Parser, ParserHandler};

#[derive(Debug)]
struct Handler {}

impl ParserHandler for Handler {
    fn log(&mut self) {
        dbg!("log");
    }
}

#[test]
fn test() {
    let handler = Handler {};
    let parser = Parser::new(handler);
    dbg!(parser);
}
