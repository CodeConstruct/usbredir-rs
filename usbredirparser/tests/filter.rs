use std::str::FromStr;

use usbredirparser::FilterRules;

#[test]
fn test() {
    let rules = FilterRules::from_str("-1,-1,-1,-1,0").unwrap();
    println!("{}", rules);
}
