//! Gen Self Signed Cert
//!
//!
//! if no exists generate ca cert and privkey
//!
//! generate new p12 cert for native-tls
//!

mod gen;
use clap::Arg;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

fn main() {
    let matches = clap::App::new("certgen")
        .arg(
            Arg::with_name("ca_file")
                .long("ca")
                .default_value("ca.pem")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ca_privkey_file")
                .long("privkey")
                .default_value("ca_privkey.pem")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("p12_file")
                .long("p12")
                .default_value("localhost.p12")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("password")
                .long("password")
                .default_value("changeit")
                .takes_value(true),
        )
        .arg(Arg::with_name("cn").long("CN").help("Common Name"))
        .arg(
            Arg::with_name("dns")
                .long("dns")
                .multiple(true)
                .help("domain"),
        )
        .arg(
            Arg::with_name("ip")
                .long("ip")
                .multiple(true)
                .help("ip address"),
        )
        .get_matches();

    let ca_file = matches.value_of("ca_file").unwrap_or("ca.pem");
    let ca_privkey_file = matches
        .value_of("ca_privkey_file")
        .unwrap_or("ca_privkey.pem");
    let p12_file = matches.value_of("p12_file").unwrap_or("localhost.p12");
    let pass = matches.value_of("password").unwrap_or("changeit");
    let dns = matches
        .values_of_lossy("dns")
        .unwrap_or_else(|| vec!["localhost".to_string()]);
    let ip = matches.values_of_lossy("ip").unwrap_or_else(|| vec![]);
    let cn = matches.value_of("cn").unwrap_or("localhost");

    gen_p12(ca_file, ca_privkey_file, p12_file, pass, dns, ip, cn);
}

fn gen_p12(
    ca_file_name: &str,
    ca_privkey_file_name: &str,
    p12_file_name: &str,
    pass: &str,
    dns: Vec<String>,
    ip: Vec<String>,
    cn: &str,
) {
    use openssl::pkey::{PKey, Private};
    use openssl::x509::X509;

    //gen ca
    if let Ok(mut ca_file) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(ca_file_name)
    {
        let (ca_cert, ca_privkey) = gen::mk_ca_cert().unwrap();
        ca_file.write_all(&ca_cert.to_pem().unwrap()).unwrap();
        let mut ca_privkey_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(ca_privkey_file_name)
            .unwrap();
        ca_privkey_file.set_len(0).unwrap();
        ca_privkey_file
            .write_all(&ca_privkey.private_key_to_pem_pkcs8().unwrap())
            .unwrap();
    };

    //load ca
    let ca_cert = {
        let mut ca_pem = vec![];
        let mut ca_file = File::open(ca_file_name).unwrap();
        ca_file.read_to_end(&mut ca_pem).unwrap();
        X509::from_pem(&ca_pem).unwrap()
    };

    //load ca privkey
    let ca_privkey = {
        let mut ca_privkey_pem = vec![];
        let mut ca_privkey_file = File::open(ca_privkey_file_name).unwrap();
        ca_privkey_file.read_to_end(&mut ca_privkey_pem).unwrap();
        PKey::<Private>::private_key_from_pem(&ca_privkey_pem).unwrap()
    };

    let p12 = gen::mk_ca_signed_cert(&ca_cert, &ca_privkey, dns, ip, pass, cn).unwrap();
    let mut p12_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(p12_file_name)
        .unwrap();
    p12_file.set_len(0).unwrap();
    p12_file.write_all(&p12.to_der().unwrap()).unwrap();
}
