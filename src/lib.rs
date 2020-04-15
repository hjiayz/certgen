use chrono::Datelike;
use core::convert::TryFrom;
use p12::PFX;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose::*, IsCa,
    KeyIdMethod, KeyPair, RcgenError,
};
use std::net::IpAddr;

#[derive(Debug)]
pub enum Error {
    PFXError,
    RcgenError(RcgenError),
    PemError(pem::PemError),
}

impl From<RcgenError> for Error {
    fn from(src: RcgenError) -> Error {
        Error::RcgenError(src)
    }
}

impl From<pem::PemError> for Error {
    fn from(src: pem::PemError) -> Error {
        Error::PemError(src)
    }
}

pub struct CA(Certificate, Option<Vec<u8>>);

impl CA {
    pub fn from_pem(ca_cert: &str, ca_key: &str) -> Result<Self, Error> {
        let key = KeyPair::from_pem(ca_key)?;
        let params = CertificateParams::from_ca_cert_pem(ca_cert, key)?;
        let ca_data = pem::parse(ca_cert)?.contents;
        let mut result = Self::from_params(params)?;
        result.1 = Some(ca_data);
        Ok(result)
    }
    pub fn from_der(ca_cert: &[u8], ca_key: &[u8]) -> Result<Self, Error> {
        let key = KeyPair::try_from(ca_key)?;
        let params = CertificateParams::from_ca_cert_der(ca_cert, key)?;
        let mut result = Self::from_params(params)?;
        result.1 = Some(ca_cert.to_owned());
        Ok(result)
    }
    pub fn from_params(mut params: CertificateParams) -> Result<Self, Error> {
        if let IsCa::SelfSignedOnly = params.is_ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        Ok(CA(Certificate::from_params(params)?, None))
    }
    pub fn make_pfx(
        &self,
        cert: &Cert,
        password: &str,
        friendly_name: &str,
    ) -> Result<Vec<u8>, Error> {
        let cert_der = cert.0.serialize_der_with_signer(&self.0)?;
        let key_der = cert.0.serialize_private_key_der();

        let ca_der = self.serialize_der()?;

        Ok(
            PFX::new(&cert_der, &key_der, Some(&ca_der), password, friendly_name)
                .ok_or_else(|| Error::PFXError)?
                .to_der(),
        )
    }

    pub fn serialize_der(&self) -> Result<Vec<u8>, Error> {
        match &self.1 {
            Some(data) => Ok(data.to_owned()),
            None => Ok(self.0.serialize_der()?),
        }
    }

    pub fn serialize_pem(&self) -> Result<String, Error> {
        let p = pem::Pem {
            tag: "CERTIFICATE".to_string(),
            contents: self.serialize_der()?,
        };
        Ok(pem::encode(&p))
    }
    pub fn serialize_private_key_pem(&self) -> String {
        self.0.serialize_private_key_pem()
    }
    pub fn serialize_private_key_der(&self) -> Vec<u8> {
        self.0.serialize_private_key_der()
    }
}

pub struct Cert(Certificate);

impl Cert {
    pub fn from_params(params: CertificateParams) -> Result<Self, Error> {
        Ok(Cert(Certificate::from_params(params)?))
    }
}

pub struct Params {
    pub domain_names: Vec<String>,
    pub ip_address: Vec<IpAddr>,
    pub country: String,
    pub organization: String,
    pub common: String,
}

impl Params {
    fn build_cert_params(&self) -> CertificateParams {
        use chrono::offset::Utc;
        use rcgen::{DistinguishedName, DnType, SanType, PKCS_ECDSA_P256_SHA256};
        let alg = &PKCS_ECDSA_P256_SHA256;
        let not_before = Utc::now();
        let not_after = not_before.with_year(not_before.year() + 1).unwrap();
        let mut subject_alt_names = vec![];
        for dns in self.domain_names.iter() {
            subject_alt_names.push(SanType::DnsName(dns.to_owned()));
        }
        for ip in self.ip_address.iter() {
            subject_alt_names.push(SanType::IpAddress(ip.to_owned()));
        }
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CountryName, &self.country);
        distinguished_name.push(DnType::OrganizationName, &self.organization);
        distinguished_name.push(DnType::CommonName, &self.common);
        let extended_key_usages = vec![ServerAuth, ClientAuth];
        let mut params = CertificateParams::default();
        params.alg = alg;
        params.not_before = not_before;
        params.not_after = not_after;
        params.subject_alt_names = subject_alt_names;
        params.distinguished_name = distinguished_name;
        params.extended_key_usages = extended_key_usages;
        params.use_authority_key_identifier_extension = true;
        params.key_identifier_method = KeyIdMethod::Sha512;
        params
    }
    pub fn ca(&self) -> Result<CA, Error> {
        let mut params = self.build_cert_params();
        params.not_after = params
            .not_before
            .with_year(params.not_before.year() + 10)
            .unwrap();
        params.extended_key_usages = vec![Any];
        CA::from_params(params)
    }
    pub fn cert(&self) -> Result<Cert, Error> {
        let params = self.build_cert_params();
        Cert::from_params(params)
    }
}
