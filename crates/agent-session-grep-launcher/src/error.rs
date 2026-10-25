use std::fmt;

/// Errors contain no OS error payload, input text, path, or environment value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LauncherError {
    NotInstalled,
    PointerInvalid,
    VersionMissing,
    ReleaseInvalid,
    TargetMismatch,
    UpdateRequired,
    IntegrityFailed,
    UnsafePath,
    ExecFailed,
    IoFailed,
    Internal,
}

impl LauncherError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotInstalled => "launcher_not_installed",
            Self::PointerInvalid => "launcher_pointer_invalid",
            Self::VersionMissing => "launcher_version_missing",
            Self::ReleaseInvalid => "launcher_release_invalid",
            Self::TargetMismatch => "launcher_target_mismatch",
            Self::UpdateRequired => "launcher_update_required",
            Self::IntegrityFailed => "launcher_integrity_failed",
            Self::UnsafePath => "launcher_unsafe_path",
            Self::ExecFailed => "launcher_exec_failed",
            Self::IoFailed => "launcher_io_failed",
            Self::Internal => "launcher_internal_error",
        }
    }

    pub const fn exit_code(self) -> i32 {
        match self {
            Self::NotInstalled | Self::VersionMissing => 4,
            Self::ExecFailed | Self::IoFailed => 5,
            Self::Internal => 70,
            _ => 9,
        }
    }

    pub const fn action(self) -> &'static str {
        match self {
            Self::UpdateRequired => "install a package compatible with launcher protocol v1",
            Self::TargetMismatch => "install the package for this platform",
            Self::ExecFailed | Self::IoFailed => "check installation access and retry",
            Self::Internal => "retry; repair the installation if this persists",
            _ => "repair the installation from a verified package",
        }
    }
}

impl fmt::Display for LauncherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.action())
    }
}

impl std::error::Error for LauncherError {}

pub type Result<T> = std::result::Result<T, LauncherError>;
