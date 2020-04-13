use failure::Fail;

#[derive(Debug, Fail)]
pub enum Ja3Error {
    #[fail(display = "Not a TLS handshake packet")]
    NotHandshake,
    #[fail(display = "Parsing error")]
    ParseError
}
