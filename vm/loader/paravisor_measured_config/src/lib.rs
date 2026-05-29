// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared interfaces for product-specific measured VTL2 config parsers.

use loader_defs::paravisor::ParavisorMeasuredVtl2Config;
use loader_defs::paravisor::ParavisorMeasuredVtl2ConfigValidationError;
use loader_defs::paravisor::ParavisorMeasuredVtl2ProductType;
use vm_resource::CanResolveTo;
use vm_resource::ResourceKind;

/// Resource kind used to select a product-specific measured VTL2 parser.
pub enum ParavisorMeasuredVtl2ParserKind {}

impl ResourceKind for ParavisorMeasuredVtl2ParserKind {
    const NAME: &'static str = "paravisor_measured_vtl2_parser";
}

impl CanResolveTo<Box<dyn ParavisorMeasuredVtl2ProductParser>> for ParavisorMeasuredVtl2ParserKind {
    type Input<'a> = ();
}

/// Header + validated opaque product blob slice.
#[derive(Debug)]
pub struct ProductMeasuredVtl2Blob<'a> {
    /// Shared fixed V2 header.
    pub header: &'a ParavisorMeasuredVtl2Config,
    /// Product-owned opaque measured payload bytes.
    pub product_data: &'a [u8],
}

impl<'a> ProductMeasuredVtl2Blob<'a> {
    /// Validates `header` and returns the bounded product blob from `full_config`.
    pub fn new(
        header: &'a ParavisorMeasuredVtl2Config,
        full_config: &'a [u8],
    ) -> Result<Self, ParavisorMeasuredVtl2ConfigValidationError> {
        let product_data = header.product_data(full_config)?;
        Ok(Self {
            header,
            product_data,
        })
    }

    /// The product type declared in the shared header.
    pub fn product_type(&self) -> ParavisorMeasuredVtl2ProductType {
        self.header.product_type
    }
}

/// Product-owned parser contract for measured VTL2 config payloads.
///
/// Implementors parse only the validated opaque `product_data` bytes for the
/// declared product type.
pub trait ParavisorMeasuredVtl2ProductParser: Send + Sync {
    /// Product type this parser supports.
    fn product_type(&self) -> ParavisorMeasuredVtl2ProductType;

    /// Parses the validated product-specific measured blob and returns
    /// product-owned config checks to apply.
    fn parse_product_data(
        &self,
        blob: ProductMeasuredVtl2Blob<'_>,
    ) -> Result<Box<dyn ProductMeasuredConfig>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Product-owned checks to validate parsed measured config policy against
/// runtime/environment constraints.
pub trait ProductMeasuredConfig: Send + Sync + core::fmt::Debug {
    /// Applies product-specific config checks against device platform settings.
    fn apply_config_checks(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}
