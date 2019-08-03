use failure::Fail;

#[derive(Fail, Debug)]
#[fail(display = "Early termination")]
pub struct EarlyTerminationError;
