mod halo2;

fn main() {
    println!("Hello, world!");
}

#[test]
fn halo2_test() {
    let vsc = halo2::rand_vec_scalar(3);
    print!("{:?}", vsc);
}
