use failure::{Error, Fail};

#[derive(Fail, Debug)]
#[fail(display = "")]
pub struct CompositeError {
    pub errors: Vec<Error>,
}
