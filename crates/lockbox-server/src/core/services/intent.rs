use lockbox_protocol::Purpose;

mod sealed {
    pub trait Sealed {}
}

pub trait Intent: sealed::Sealed {
    const PURPOSE: Purpose;
}

#[derive(Debug, Clone, Copy)]
pub struct ForUpload;

#[derive(Debug, Clone, Copy)]
pub struct ForFetch;

#[derive(Debug, Clone, Copy)]
pub struct ForDelete;

impl sealed::Sealed for ForUpload {}
impl sealed::Sealed for ForFetch {}
impl sealed::Sealed for ForDelete {}

impl Intent for ForUpload {
    const PURPOSE: Purpose = Purpose::Upload;
}

impl Intent for ForFetch {
    const PURPOSE: Purpose = Purpose::Fetch;
}

impl Intent for ForDelete {
    const PURPOSE: Purpose = Purpose::Delete;
}
