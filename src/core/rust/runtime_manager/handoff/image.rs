// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/main.c prepare_reexecute(); src/core/manager-serialize.c

//! Versioned, bounded precommit image for a live manager handoff.
//!
//! The first wire version deliberately carries only the validated inventory
//! and descriptor-role manifest. It is *not* a manager-state serialization.
//! Encoding that limitation in the wire header prevents a future adopter from
//! mistaking today's preparation proof for a bootable state image.

use std::collections::BTreeSet;

use super::{CgroupFdKind, DescriptorRole, HandoffAssessment, HandoffPurpose};

const MAGIC: &[u8; 8] = b"SRHNDFF\0";
pub const HANDOFF_IMAGE_VERSION: u16 = 1;
const MAX_IMAGE_SIZE: usize = 16 * 1024 * 1024;
const MAX_DESCRIPTOR_ROLES: usize = 1 << 16;
const MAX_UNIT_NAME_SIZE: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffImageCoverage {
    /// Descriptor ownership is represented, but units, jobs, timers, process
    /// identities, event sources, and manager scalars are not serialized.
    DescriptorManifestOnly,
}

impl HandoffImageCoverage {
    const fn wire_code(self) -> u8 {
        match self {
            Self::DescriptorManifestOnly => 1,
        }
    }

    fn from_wire(code: u8) -> Result<Self, HandoffImageError> {
        match code {
            1 => Ok(Self::DescriptorManifestOnly),
            other => Err(HandoffImageError::UnsupportedCoverage(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum DescriptorRoleManifest {
    SocketListener { unit: String, port_index: u64 },
    CgroupRoot,
    UnitCgroup { unit: String, kind: u8 },
    CgroupInotify,
    BoundStopRetryTimer,
}

impl DescriptorRoleManifest {
    fn from_runtime(role: &DescriptorRole) -> Result<Self, HandoffImageError> {
        Ok(match role {
            DescriptorRole::SocketListener { unit, port_index } => Self::SocketListener {
                unit: unit.clone(),
                port_index: (*port_index)
                    .try_into()
                    .map_err(|_| HandoffImageError::ValueOutOfRange)?,
            },
            DescriptorRole::CgroupRoot => Self::CgroupRoot,
            DescriptorRole::UnitCgroup { unit, kind } => Self::UnitCgroup {
                unit: unit.clone(),
                kind: match kind {
                    CgroupFdKind::Directory => 1,
                    CgroupFdKind::ProcessesWrite => 2,
                    CgroupFdKind::ProcessesRead => 3,
                    CgroupFdKind::EventsRead => 4,
                },
            },
            DescriptorRole::CgroupInotify => Self::CgroupInotify,
            DescriptorRole::BoundStopRetryTimer => Self::BoundStopRetryTimer,
        })
    }

    fn encode(&self, output: &mut Vec<u8>) -> Result<(), HandoffImageError> {
        match self {
            Self::SocketListener { unit, port_index } => {
                output.push(1);
                encode_string(output, unit)?;
                output.extend_from_slice(&port_index.to_le_bytes());
            }
            Self::CgroupRoot => output.push(2),
            Self::UnitCgroup { unit, kind } => {
                output.push(3);
                encode_string(output, unit)?;
                output.push(*kind);
            }
            Self::CgroupInotify => output.push(4),
            Self::BoundStopRetryTimer => output.push(5),
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor<'_>) -> Result<Self, HandoffImageError> {
        match cursor.read_u8()? {
            1 => Ok(Self::SocketListener {
                unit: cursor.read_string()?,
                port_index: cursor.read_u64()?,
            }),
            2 => Ok(Self::CgroupRoot),
            3 => {
                let unit = cursor.read_string()?;
                let kind = cursor.read_u8()?;
                if !(1..=4).contains(&kind) {
                    return Err(HandoffImageError::InvalidDescriptorRole);
                }
                Ok(Self::UnitCgroup { unit, kind })
            }
            4 => Ok(Self::CgroupInotify),
            5 => Ok(Self::BoundStopRetryTimer),
            _ => Err(HandoffImageError::InvalidDescriptorRole),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffImageError {
    ImageTooLarge,
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u16),
    UnsupportedCoverage(u8),
    UnsupportedPurpose(u8),
    InvalidDescriptorRole,
    InvalidUtf8,
    DuplicateDescriptorRole,
    DescriptorCountMismatch { declared: usize, actual: usize },
    PurposeMismatch,
    IncompleteStateCoverage,
    RoundTripMismatch,
    TrailingData,
    ValueOutOfRange,
}

impl std::fmt::Display for HandoffImageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ImageTooLarge => formatter.write_str("handoff image exceeds its size limit"),
            Self::Truncated => formatter.write_str("handoff image is truncated"),
            Self::InvalidMagic => formatter.write_str("handoff image has invalid magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported handoff image version {version}")
            }
            Self::UnsupportedCoverage(coverage) => {
                write!(formatter, "unsupported handoff image coverage {coverage}")
            }
            Self::UnsupportedPurpose(purpose) => {
                write!(formatter, "unsupported handoff purpose {purpose}")
            }
            Self::InvalidDescriptorRole => {
                formatter.write_str("handoff image contains an invalid descriptor role")
            }
            Self::InvalidUtf8 => formatter.write_str("handoff image contains invalid UTF-8"),
            Self::DuplicateDescriptorRole => {
                formatter.write_str("handoff image contains a duplicate descriptor role")
            }
            Self::DescriptorCountMismatch { declared, actual } => write!(
                formatter,
                "handoff image declares {declared} descriptors but contains {actual} roles"
            ),
            Self::PurposeMismatch => {
                formatter.write_str("handoff image purpose does not match the requested transition")
            }
            Self::IncompleteStateCoverage => formatter.write_str(
                "handoff image does not contain complete manager state and cannot be adopted",
            ),
            Self::RoundTripMismatch => {
                formatter.write_str("handoff image changed during an encode/decode round trip")
            }
            Self::TrailingData => formatter.write_str("handoff image contains trailing data"),
            Self::ValueOutOfRange => {
                formatter.write_str("handoff image value does not fit its wire representation")
            }
        }
    }
}

impl std::error::Error for HandoffImageError {}

/// A deterministic precommit artifact created from the same descriptor bundle
/// that a lifecycle transaction owns. Its coverage is intentionally explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffPrecommitImage {
    purpose: HandoffPurpose,
    coverage: HandoffImageCoverage,
    assessment: HandoffAssessment,
    descriptor_roles: Vec<DescriptorRoleManifest>,
}

impl HandoffPrecommitImage {
    pub(super) fn from_runtime_roles<'a>(
        assessment: HandoffAssessment,
        roles: impl IntoIterator<Item = &'a DescriptorRole>,
    ) -> Result<Self, HandoffImageError> {
        let descriptor_roles = roles
            .into_iter()
            .map(DescriptorRoleManifest::from_runtime)
            .collect::<Result<Vec<_>, _>>()?;
        let image = Self {
            purpose: assessment.purpose,
            coverage: HandoffImageCoverage::DescriptorManifestOnly,
            assessment,
            descriptor_roles,
        };
        image.validate_internal()?;
        Ok(image)
    }

    pub fn purpose(&self) -> HandoffPurpose {
        self.purpose
    }

    pub fn coverage(&self) -> HandoffImageCoverage {
        self.coverage
    }

    pub fn assessment(&self) -> &HandoffAssessment {
        &self.assessment
    }

    pub fn descriptor_count(&self) -> usize {
        self.descriptor_roles.len()
    }

    /// Encode using a bounded, length-delimited binary format. The result is
    /// deterministic because descriptor roles originate in a `BTreeMap`.
    pub fn encode(&self) -> Result<Vec<u8>, HandoffImageError> {
        self.validate_internal()?;
        let mut output = Vec::new();
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&HANDOFF_IMAGE_VERSION.to_le_bytes());
        output.push(self.coverage.wire_code());
        output.push(purpose_wire_code(self.purpose));
        for count in [
            self.assessment.unit_count,
            self.assessment.job_count,
            self.assessment.socket_listener_count,
            self.assessment.unit_cgroup_count,
            self.assessment.cgroup_watch_count,
            self.assessment.descriptor_count,
        ] {
            output.extend_from_slice(&usize_to_u64(count)?.to_le_bytes());
        }
        let role_count: u32 = self
            .descriptor_roles
            .len()
            .try_into()
            .map_err(|_| HandoffImageError::ValueOutOfRange)?;
        output.extend_from_slice(&role_count.to_le_bytes());
        for role in &self.descriptor_roles {
            role.encode(&mut output)?;
            if output.len() > MAX_IMAGE_SIZE {
                return Err(HandoffImageError::ImageTooLarge);
            }
        }
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, HandoffImageError> {
        if input.len() > MAX_IMAGE_SIZE {
            return Err(HandoffImageError::ImageTooLarge);
        }
        let mut cursor = Cursor::new(input);
        if cursor.read_exact(MAGIC.len())? != MAGIC {
            return Err(HandoffImageError::InvalidMagic);
        }
        let version = cursor.read_u16()?;
        if version != HANDOFF_IMAGE_VERSION {
            return Err(HandoffImageError::UnsupportedVersion(version));
        }
        let coverage = HandoffImageCoverage::from_wire(cursor.read_u8()?)?;
        let purpose = purpose_from_wire(cursor.read_u8()?)?;
        let unit_count = cursor.read_usize()?;
        let job_count = cursor.read_usize()?;
        let socket_listener_count = cursor.read_usize()?;
        let unit_cgroup_count = cursor.read_usize()?;
        let cgroup_watch_count = cursor.read_usize()?;
        let descriptor_count = cursor.read_usize()?;
        let role_count =
            usize::try_from(cursor.read_u32()?).map_err(|_| HandoffImageError::ValueOutOfRange)?;
        if role_count > MAX_DESCRIPTOR_ROLES {
            return Err(HandoffImageError::ImageTooLarge);
        }
        // Every role has at least a one-byte tag. Reject impossible counts
        // before reserving memory based on untrusted input.
        if role_count > cursor.remaining() {
            return Err(HandoffImageError::Truncated);
        }
        let mut descriptor_roles = Vec::with_capacity(role_count);
        for _ in 0..role_count {
            descriptor_roles.push(DescriptorRoleManifest::decode(&mut cursor)?);
        }
        if !cursor.is_empty() {
            return Err(HandoffImageError::TrailingData);
        }
        let image = Self {
            purpose,
            coverage,
            assessment: HandoffAssessment {
                purpose,
                unit_count,
                job_count,
                socket_listener_count,
                unit_cgroup_count,
                cgroup_watch_count,
                descriptor_count,
            },
            descriptor_roles,
        };
        image.validate_internal()?;
        Ok(image)
    }

    /// Validate the non-destructive half of adoption. This checks transition
    /// identity and descriptor cardinality, but deliberately rejects commit
    /// while complete manager state is absent.
    pub fn validate_for_adoption(
        &self,
        expected_purpose: HandoffPurpose,
        supplied_descriptors: usize,
    ) -> Result<(), HandoffImageError> {
        self.validate_internal()?;
        if self.purpose != expected_purpose {
            return Err(HandoffImageError::PurposeMismatch);
        }
        if supplied_descriptors != self.descriptor_roles.len() {
            return Err(HandoffImageError::DescriptorCountMismatch {
                declared: self.descriptor_roles.len(),
                actual: supplied_descriptors,
            });
        }
        match self.coverage {
            HandoffImageCoverage::DescriptorManifestOnly => {
                Err(HandoffImageError::IncompleteStateCoverage)
            }
        }
    }

    fn validate_internal(&self) -> Result<(), HandoffImageError> {
        let declared = self.assessment.descriptor_count;
        let actual = self.descriptor_roles.len();
        if declared != actual {
            return Err(HandoffImageError::DescriptorCountMismatch { declared, actual });
        }
        if actual > MAX_DESCRIPTOR_ROLES {
            return Err(HandoffImageError::ImageTooLarge);
        }
        if self.descriptor_roles.iter().collect::<BTreeSet<_>>().len() != actual {
            return Err(HandoffImageError::DuplicateDescriptorRole);
        }
        Ok(())
    }
}

fn purpose_wire_code(purpose: HandoffPurpose) -> u8 {
    match purpose {
        HandoffPurpose::ReloadInProcess => 1,
        HandoffPurpose::Reexecute => 2,
        HandoffPurpose::SwitchRoot => 3,
        HandoffPurpose::SoftReboot => 4,
    }
}

fn purpose_from_wire(code: u8) -> Result<HandoffPurpose, HandoffImageError> {
    match code {
        1 => Ok(HandoffPurpose::ReloadInProcess),
        2 => Ok(HandoffPurpose::Reexecute),
        3 => Ok(HandoffPurpose::SwitchRoot),
        4 => Ok(HandoffPurpose::SoftReboot),
        other => Err(HandoffImageError::UnsupportedPurpose(other)),
    }
}

fn usize_to_u64(value: usize) -> Result<u64, HandoffImageError> {
    value
        .try_into()
        .map_err(|_| HandoffImageError::ValueOutOfRange)
}

fn encode_string(output: &mut Vec<u8>, value: &str) -> Result<(), HandoffImageError> {
    if value.len() > MAX_UNIT_NAME_SIZE {
        return Err(HandoffImageError::ImageTooLarge);
    }
    let length: u32 = value
        .len()
        .try_into()
        .map_err(|_| HandoffImageError::ValueOutOfRange)?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], HandoffImageError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(HandoffImageError::Truncated)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(HandoffImageError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, HandoffImageError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, HandoffImageError> {
        Ok(u16::from_le_bytes(
            self.read_exact(2)?.try_into().expect("exact length"),
        ))
    }

    fn read_u32(&mut self) -> Result<u32, HandoffImageError> {
        Ok(u32::from_le_bytes(
            self.read_exact(4)?.try_into().expect("exact length"),
        ))
    }

    fn read_u64(&mut self) -> Result<u64, HandoffImageError> {
        Ok(u64::from_le_bytes(
            self.read_exact(8)?.try_into().expect("exact length"),
        ))
    }

    fn read_usize(&mut self) -> Result<usize, HandoffImageError> {
        self.read_u64()?
            .try_into()
            .map_err(|_| HandoffImageError::ValueOutOfRange)
    }

    fn read_string(&mut self) -> Result<String, HandoffImageError> {
        let length =
            usize::try_from(self.read_u32()?).map_err(|_| HandoffImageError::ValueOutOfRange)?;
        if length > MAX_UNIT_NAME_SIZE {
            return Err(HandoffImageError::ImageTooLarge);
        }
        let bytes = self.read_exact(length)?;
        std::str::from_utf8(bytes)
            .map(ToOwned::to_owned)
            .map_err(|_| HandoffImageError::InvalidUtf8)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.input.len()
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> HandoffPrecommitImage {
        let assessment = HandoffAssessment {
            purpose: HandoffPurpose::Reexecute,
            unit_count: 3,
            job_count: 0,
            socket_listener_count: 1,
            unit_cgroup_count: 0,
            cgroup_watch_count: 0,
            descriptor_count: 2,
        };
        HandoffPrecommitImage {
            purpose: HandoffPurpose::Reexecute,
            coverage: HandoffImageCoverage::DescriptorManifestOnly,
            assessment,
            descriptor_roles: vec![
                DescriptorRoleManifest::SocketListener {
                    unit: "api.socket".into(),
                    port_index: 0,
                },
                DescriptorRoleManifest::CgroupRoot,
            ],
        }
    }

    #[test]
    fn wire_roundtrip_is_deterministic_and_versioned() {
        let fixture = fixture();
        let first = fixture.encode().unwrap();
        let decoded = HandoffPrecommitImage::decode(&first).unwrap();
        assert_eq!(decoded, fixture);
        assert_eq!(decoded.encode().unwrap(), first);
        assert_eq!(
            decoded.coverage(),
            HandoffImageCoverage::DescriptorManifestOnly
        );
    }

    #[test]
    fn decoder_rejects_truncation_unknown_version_and_trailing_bytes() {
        let encoded = fixture().encode().unwrap();
        assert_eq!(
            HandoffPrecommitImage::decode(&encoded[..encoded.len() - 1]),
            Err(HandoffImageError::Truncated)
        );

        let mut unknown_version = encoded.clone();
        unknown_version[MAGIC.len()] = 2;
        assert_eq!(
            HandoffPrecommitImage::decode(&unknown_version),
            Err(HandoffImageError::UnsupportedVersion(2))
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            HandoffPrecommitImage::decode(&trailing),
            Err(HandoffImageError::TrailingData)
        );
    }

    #[test]
    fn descriptor_manifest_cannot_be_adopted_as_complete_state() {
        let image = fixture();
        assert_eq!(
            image.validate_for_adoption(HandoffPurpose::Reexecute, 2),
            Err(HandoffImageError::IncompleteStateCoverage)
        );
        assert_eq!(
            image.validate_for_adoption(HandoffPurpose::SwitchRoot, 2),
            Err(HandoffImageError::PurposeMismatch)
        );
        assert_eq!(
            image.validate_for_adoption(HandoffPurpose::Reexecute, 1),
            Err(HandoffImageError::DescriptorCountMismatch {
                declared: 2,
                actual: 1,
            })
        );
    }
}
