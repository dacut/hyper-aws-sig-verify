mod service;
pub use crate::service::AwsSigV4VerifierService;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
