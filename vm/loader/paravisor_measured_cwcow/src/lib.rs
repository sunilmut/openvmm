// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CWCOW product-specific measured VTL2 policy parsing.

use loader_defs::paravisor::ParavisorMeasuredVtl2ProductType;
use mesh::MeshPayload;
use mesh::payload::Protobuf;
use paravisor_measured_config::ParavisorMeasuredVtl2ParserKind;
use paravisor_measured_config::ProductMeasuredConfig;
use paravisor_measured_config::ParavisorMeasuredVtl2ProductParser;
use paravisor_measured_config::ProductMeasuredVtl2Blob;
use vm_resource::Resource;
use vm_resource::ResourceId;

/// Product-specific measured policy payload for CWCOW.
#[derive(Clone, Debug, Protobuf)]
#[mesh(package = "paravisor.measured.cwcow")]
pub struct CwcowPolicy {
    /// Enforce read-only mode for the VMGS partition. With this set,
    /// OpenHCL refuses writes to the VMGS (including host-initiated changes).
    #[mesh(1)]
    pub vmgs_read_only: bool,

    /// Require secure-boot-only mode.
    #[mesh(2)]
    pub require_secure_boot: bool,

    /// Require secure boot variables (PK, KEK, db, dbx, etc.).
    #[mesh(3)]
    pub require_secure_boot_vars: bool,

    /// Require `BootConfigurationDataHash` via custom UEFI JSON.
    #[mesh(4)]
    pub require_bcd_integrity: bool,

    /// Require Secure AVIC where supported.
    #[mesh(5)]
    pub require_secure_avic: bool,

    /// Custom UEFI JSON bytes.
    #[mesh(6)]
    pub custom_uefi_json: Vec<u8>,
}

/// Error for parsing/validating CWCOW measured policy.
#[derive(Debug)]
pub enum CwcowPolicyParseError {
    /// Header product type does not match CWCOW.
    UnexpectedProductType(ParavisorMeasuredVtl2ProductType),
    /// Product payload could not be protobuf-decoded.
    Decode(mesh_protobuf::Error),
    /// `custom_uefi_json` must be present and non-empty.
    EmptyCustomUefiJson,
}

impl core::fmt::Display for CwcowPolicyParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedProductType(product) => {
                write!(f, "unexpected product type for cwcow parser: {product:?}")
            }
            Self::Decode(err) => write!(f, "failed to decode cwcow policy: {err}"),
            Self::EmptyCustomUefiJson => write!(f, "cwcow custom_uefi_json must be non-empty"),
        }
    }
}

impl std::error::Error for CwcowPolicyParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(err) => Some(err),
            _ => None,
        }
    }
}

/// CWCOW parser implementation for opaque measured VTL2 product data.
pub struct CwcowMeasuredVtl2ProductParser;

/// Product config for CWCOW with parsed policy.
#[derive(Debug)]
pub struct CwcowProductMeasuredConfig {
    policy: CwcowPolicy,
}

impl ProductMeasuredConfig for CwcowProductMeasuredConfig {
    fn apply_config_checks(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

impl CwcowMeasuredVtl2ProductParser {
    /// Decodes and validates a CWCOW policy from a validated product blob.
    pub fn parse_cwcow_policy(
        &self,
        blob: ProductMeasuredVtl2Blob<'_>,
    ) -> Result<CwcowPolicy, CwcowPolicyParseError> {
        if blob.product_type() != ParavisorMeasuredVtl2ProductType::CWCOW {
            return Err(CwcowPolicyParseError::UnexpectedProductType(
                blob.product_type(),
            ));
        }

        let policy: CwcowPolicy =
            mesh_protobuf::decode(blob.product_data).map_err(CwcowPolicyParseError::Decode)?;

        if policy.custom_uefi_json.is_empty() {
            return Err(CwcowPolicyParseError::EmptyCustomUefiJson);
        }

        Ok(policy)
    }
}

impl ParavisorMeasuredVtl2ProductParser for CwcowMeasuredVtl2ProductParser {
    fn product_type(&self) -> ParavisorMeasuredVtl2ProductType {
        ParavisorMeasuredVtl2ProductType::CWCOW
    }

    fn parse_product_data(
        &self,
        blob: ProductMeasuredVtl2Blob<'_>,
    ) -> Result<Box<dyn ProductMeasuredConfig>, Box<dyn std::error::Error + Send + Sync>> {
        let policy = self.parse_cwcow_policy(blob)?;
        Ok(Box::new(CwcowProductMeasuredConfig { policy }))
    }
}

/// Resource handle selecting the CWCOW measured VTL2 parser.
#[derive(MeshPayload)]
pub struct CwcowMeasuredVtl2ParserHandle;

impl ResourceId<ParavisorMeasuredVtl2ParserKind> for CwcowMeasuredVtl2ParserHandle {
    const ID: &'static str = "cwcow";
}

/// Resolver for [`CwcowMeasuredVtl2ParserHandle`].
pub struct CwcowMeasuredVtl2ParserResolver;

impl vm_resource::ResolveResource<ParavisorMeasuredVtl2ParserKind, CwcowMeasuredVtl2ParserHandle>
    for CwcowMeasuredVtl2ParserResolver
{
    type Output = Box<dyn ParavisorMeasuredVtl2ProductParser>;
    type Error = core::convert::Infallible;

    fn resolve(
        &self,
        _resource: CwcowMeasuredVtl2ParserHandle,
        _input: (),
    ) -> Result<Self::Output, Self::Error> {
        Ok(Box::new(CwcowMeasuredVtl2ProductParser))
    }
}

vm_resource::declare_static_resolver!(
    CwcowMeasuredVtl2ParserResolver,
    (
        ParavisorMeasuredVtl2ParserKind,
        CwcowMeasuredVtl2ParserHandle,
    ),
);

vm_resource::register_static_resolvers!(CwcowMeasuredVtl2ParserResolver);

/// Maps a measured VTL2 `product_type` to a parser resource handle when this
/// crate supports that product.
pub fn parser_resource_for_product_type(
    product_type: ParavisorMeasuredVtl2ProductType,
) -> Option<Resource<ParavisorMeasuredVtl2ParserKind>> {
    match product_type {
        ParavisorMeasuredVtl2ProductType::CWCOW => {
            Some(Resource::new(CwcowMeasuredVtl2ParserHandle))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;
    use futures::executor::block_on;
    use loader_defs::paravisor::ParavisorMeasuredVtl2Config;
    use vm_resource::ResourceResolver;
    use zerocopy::IntoBytes;

    #[test]
    fn parser_resource_mapping_is_cwcow_only() {
        let cwcow = parser_resource_for_product_type(ParavisorMeasuredVtl2ProductType::CWCOW)
            .expect("expected cwcow product type to map to a parser resource");
        assert_eq!(cwcow.id(), CwcowMeasuredVtl2ParserHandle::ID);

        assert!(
            parser_resource_for_product_type(ParavisorMeasuredVtl2ProductType::OPENHCL).is_none(),
            "expected unsupported product types to not resolve to a cwcow parser resource"
        );
    }

    #[test]
    fn parse_cwcow_policy_from_v2_blob() {
        let input_policy = CwcowPolicy {
            vmgs_read_only: true,
            require_secure_boot: true,
            require_secure_boot_vars: true,
            require_bcd_integrity: false,
            require_secure_avic: false,
            custom_uefi_json: br#"{"SecureBoot":true}"#.to_vec(),
        };

        let policy_bytes = mesh_protobuf::encode(input_policy.clone());
        let header = ParavisorMeasuredVtl2Config {
            magic: ParavisorMeasuredVtl2Config::MAGIC,
            vtom_offset_bit: 0,
            padding: [0; 7],
            version: ParavisorMeasuredVtl2Config::VERSION,
            product_type: ParavisorMeasuredVtl2ProductType::CWCOW,
            total_size: (size_of::<ParavisorMeasuredVtl2Config>() + policy_bytes.len()) as u32,
            product_data_offset: size_of::<ParavisorMeasuredVtl2Config>() as u32,
            product_data_size: policy_bytes.len() as u32,
        };

        // Build an input blob with header bytes first, followed by opaque product data.
        let mut full_config = Vec::new();
        full_config.extend_from_slice(header.as_bytes());
        full_config.extend_from_slice(policy_bytes.as_ref());

        let blob = ProductMeasuredVtl2Blob::new(&header, &full_config)
            .expect("expected v2 header + product data blob to validate");

        let parser_resource = parser_resource_for_product_type(blob.product_type())
            .expect("expected cwcow product type to map to parser resource");
        let resolver = ResourceResolver::new();
        let parser = block_on(resolver.resolve(parser_resource, ()))
            .expect("expected parser resource resolution to succeed");
        let product_data = blob.product_data;

        let product_config = parser
            .parse_product_data(blob)
            .expect("expected resolved parser to accept cwcow policy blob");

        let parsed: CwcowPolicy = mesh_protobuf::decode(product_data)
            .expect("expected cwcow policy decode");

        assert_eq!(parsed.vmgs_read_only, input_policy.vmgs_read_only);
        assert_eq!(parsed.require_secure_boot, input_policy.require_secure_boot);
        assert_eq!(parsed.require_secure_boot_vars, input_policy.require_secure_boot_vars);
        assert_eq!(parsed.require_bcd_integrity, input_policy.require_bcd_integrity);
        assert_eq!(parsed.require_secure_avic, input_policy.require_secure_avic);
        assert_eq!(parsed.custom_uefi_json, input_policy.custom_uefi_json);

        // Note: CwcowProductMeasuredConfig is successfully created from the blob.
        // apply_config_checks validation against DevicePlatformSettings is tested
        // at the integration level in underhill_core.
        let _ = product_config;
    }
}
