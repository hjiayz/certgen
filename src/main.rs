//! Gen Self Signed Cert
//!
//!
//! if no exists generate ca cert and privkey
//!
//! generate new p12 cert for native-tls
//!

mod lib;
use clap::Arg;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::str::FromStr;

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
        .arg(
            Arg::with_name("c")
                .long("C")
                .help("Country Name")
                .default_value("CN")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("o")
                .long("O")
                .help("Organization Name")
                .default_value("Cert Gen")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cn")
                .long("CN")
                .help("Common Name")
                .default_value("localhost")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ca_c")
                .long("CA_C")
                .help("CA Country Name")
                .default_value("CN")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ca_o")
                .long("CA_O")
                .help("CA Organization Name")
                .default_value("Cert Gen")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ca_cn")
                .long("CA_CN")
                .help("CA Common Name")
                .default_value("Cert Gen CA")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("dns")
                .long("dns")
                .multiple(true)
                .help("domain")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ip")
                .long("ip")
                .multiple(true)
                .help("ip address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("friendly_name")
                .long("fn")
                .help("Friendly Name")
                .default_value("localhost")
                .takes_value(true),
        )
        .get_matches();

    let ca_file_name = matches.value_of("ca_file").unwrap_or("ca.pem");
    let ca_privkey_file_name = matches
        .value_of("ca_privkey_file")
        .unwrap_or("ca_privkey.pem");
    let p12_file_name = matches.value_of("p12_file").unwrap_or("localhost.p12");
    let pass = matches.value_of("password").unwrap_or("changeit");
    let dns = matches
        .values_of_lossy("dns")
        .unwrap_or_else(|| vec!["localhost".to_string()]);
    let ip = matches
        .values_of_lossy("ip")
        .unwrap_or_else(|| vec!["127.0.0.1".to_string()]);

    let cn = matches.value_of("cn").unwrap_or("localhost");
    let c = matches.value_of("c").unwrap_or("CN");
    let o = matches.value_of("o").unwrap_or("Cert Gen");

    let cacn = matches.value_of("ca_cn").unwrap_or("Cert Gen CA");
    let cac = matches.value_of("ca_c").unwrap_or("CN");
    let cao = matches.value_of("ca_o").unwrap_or("Cert Gen");

    let friendly_name = matches.value_of("friendly_name").unwrap_or("localhost");

    let mut ip_address = vec![];

    for address in ip {
        ip_address.push(IpAddr::from_str(&address).unwrap());
    }

    let caparams = lib::Params {
        domain_names: vec![],
        ip_address: vec![],
        country: cac.to_owned(),
        organization: cao.to_owned(),
        common: cacn.to_owned(),
    };

    let params = lib::Params {
        domain_names: dns,
        ip_address,
        country: c.to_owned(),
        organization: o.to_owned(),
        common: cn.to_owned(),
    };

    //gen ca
    if let Ok(mut ca_file) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(ca_file_name)
    {
        let ca = caparams.ca().unwrap();
        ca_file
            .write_all(&ca.serialize_pem().unwrap().as_bytes())
            .unwrap();
        let mut ca_privkey_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(ca_privkey_file_name)
            .unwrap();
        ca_privkey_file.set_len(0).unwrap();
        ca_privkey_file
            .write_all(&ca.serialize_private_key_pem().as_bytes())
            .unwrap();
    };

    //load ca
    let ca_pem = {
        let mut ca_pem = vec![];
        let mut ca_file = File::open(ca_file_name).unwrap();
        ca_file.read_to_end(&mut ca_pem).unwrap();
        String::from_utf8(ca_pem).unwrap()
    };

    //load ca privkey
    let ca_privkey_pem = {
        let mut ca_privkey_pem = vec![];
        let mut ca_privkey_file = File::open(ca_privkey_file_name).unwrap();
        ca_privkey_file.read_to_end(&mut ca_privkey_pem).unwrap();
        String::from_utf8(ca_privkey_pem).unwrap()
    };

    let ca = lib::CA::from_pem(&ca_pem, &ca_privkey_pem).unwrap();

    let cert = params.cert().unwrap();

    let p12 = ca.make_pfx(&cert, pass, friendly_name).unwrap();
    let mut p12_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(p12_file_name)
        .unwrap();
    p12_file.set_len(0).unwrap();
    p12_file.write_all(&p12).unwrap();
}
