use std::fmt;

/// What an [`Error`] is about: the kind of value that was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum What {
    /// A kebab-case label ([`Label`](crate::Label)).
    Label,
    /// A Component Model interface name ([`InterfaceName`](crate::InterfaceName)).
    InterfaceName,
    /// A version ([`Version`](crate::Version)).
    Version,
    /// A guest path ([`GuestPath`](crate::GuestPath)).
    Path,
    /// A directory access ([`Access`](crate::Access)).
    Access,
    /// A host ([`Host`](crate::Host)).
    Host,
    /// A port ([`Port`](crate::Port)).
    Port,
    /// An environment variable ([`Variable`](crate::Variable)).
    Variable,
    /// A capability line ([`Capability`](crate::Capability)).
    Capability,
}

impl What {
    fn noun(self) -> &'static str {
        match self {
            What::Label => "label",
            What::InterfaceName => "interface name",
            What::Version => "version",
            What::Path => "guest path",
            What::Access => "access",
            What::Host => "host",
            What::Port => "port",
            What::Variable => "variable",
            What::Capability => "capability",
        }
    }
}

/// A value the crate refused: what it was meant to be, the text given, and why.
///
/// Every parse in the crate fails with one of these; the message names all three.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Error {
    what: What,
    input: String,
    reason: &'static str,
}

impl Error {
    pub(crate) fn new(what: What, input: &str, reason: &'static str) -> Self {
        Error {
            what,
            input: input.to_owned(),
            reason,
        }
    }

    /// The kind of value the text was meant to be.
    pub fn what(&self) -> What {
        self.what
    }

    /// The text that was refused.
    pub fn input(&self) -> &str {
        &self.input
    }

    /// Why it was refused, in one sentence.
    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid {} `{}`: {}",
            self.what.noun(),
            self.input,
            self.reason
        )
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_names_the_kind_the_input_and_the_reason() {
        let err = Error::new(What::Port, "70000", "a port is 0 to 65535 or `*`");
        assert_eq!(
            err.to_string(),
            "invalid port `70000`: a port is 0 to 65535 or `*`"
        );
        assert_eq!(err.what(), What::Port);
        assert_eq!(err.input(), "70000");
        assert_eq!(err.reason(), "a port is 0 to 65535 or `*`");
    }
}
