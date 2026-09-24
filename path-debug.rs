use std::path::Path;
fn main(){let p=Path::new("."); let a=std::fs::canonicalize(p).unwrap(); let b=std::fs::canonicalize(a.join(".")).unwrap(); println!("a={:?}\nb={:?}\neq={}",a,b,a==b); for x in a.components(){println!("{:?}",x);} }
