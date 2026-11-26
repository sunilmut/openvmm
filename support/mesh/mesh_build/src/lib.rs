// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code generator for protobuf service definitions.
//!
//! Used in `build.rs` with the [`prost`](https://docs.rs/prost-build) protobuf
//! code generator to produce Rust service traits compatible with
//! [`mesh_rpc`](https://openvmm.dev/rustdoc/linux/mesh_rpc/index.html).
//!
//! # Example
//!
//! ```rust,ignore
//! // build.rs
//! fn main() {
//!     prost_build::Config::new()
//!         .service_generator(Box::new(mesh_build::MeshServiceGenerator))
//!         .compile_protos(&["src/my_service.proto"], &["src/"])
//!         .unwrap();
//! }
//! ```

#![forbid(unsafe_code)]

use heck::ToUpperCamelCase;
use proc_macro2::Span;
use syn::Ident;

/// A service generator for mesh services.
pub struct MeshServiceGenerator {
    replacements: Vec<(syn::TypePath, syn::Type)>,
}

impl MeshServiceGenerator {
    /// Creates a new service generator.
    pub fn new() -> Self {
        Self {
            replacements: Vec::new(),
        }
    }

    /// Configures the generator to replace any instance of Rust `ty` with
    /// `replacement`.
    ///
    /// This can be useful when some input or output messages already have mesh
    /// types defined, and you want to use them instead of the generated prost
    /// types.
    pub fn replace_type(mut self, ty: &str, replacement: &str) -> Self {
        let ty = syn::parse_str(ty).unwrap();
        let replacement = syn::parse_str(replacement).unwrap();
        self.replacements.push((ty, replacement));
        self
    }

    fn lookup_type(&self, ty: &str) -> syn::Type {
        let ty: syn::Type = syn::parse_str(ty).unwrap_or_else(|err| {
            panic!("failed to parse type {}: {}", ty, err);
        });
        if let syn::Type::Path(ty) = &ty {
            for (from, to) in &self.replacements {
                if from == ty {
                    return to.clone();
                }
            }
        }
        ty
    }
}

impl prost_build::ServiceGenerator for MeshServiceGenerator {
    fn generate(&mut self, service: prost_build::Service, buf: &mut String) {
        let name = format!("{}.{}", service.package, service.proto_name);
        let ident = Ident::new(&service.name, Span::call_site());
        let method_names: Vec<_> = service.methods.iter().map(|m| &m.proto_name).collect();
        let method_idents: Vec<_> = service
            .methods
            .iter()
            .map(|m| Ident::new(&m.name.to_upper_camel_case(), Span::call_site()))
            .collect();
        let request_types: Vec<_> = service
            .methods
            .iter()
            .map(|m| self.lookup_type(&m.input_type))
            .collect();
        let response_types: Vec<_> = service
            .methods
            .iter()
            .map(|m| self.lookup_type(&m.output_type))
            .collect();

        *buf += &quote::quote! {
            #[derive(Debug)]
            pub enum #ident {
                #(
                    #method_idents(
                        #request_types,
                        ::mesh::OneshotSender<::core::result::Result<#response_types, ::mesh_rpc::service::Status>>,
                    ),
                )*
            }

            impl #ident {
                #[allow(dead_code)]
                pub fn fail(self, status: ::mesh_rpc::service::Status) {
                    match self {
                        #(
                            #ident::#method_idents(_, response) => response.send(Err(status)),
                        )*
                    }
                }
            }

            impl ::mesh_rpc::service::ServiceRpc for #ident {
                const NAME: &'static str = #name;

                fn method(&self) -> &'static str {
                    match self {
                        #(
                            #ident::#method_idents(_, _) => #method_names,
                        )*
                    }
                }

                fn encode(
                    self,
                    writer: ::mesh::payload::protobuf::FieldWriter<'_, '_, ::mesh::resource::Resource>,
                ) -> ::mesh::local_node::Port {
                    match self {
                        #(
                            #ident::#method_idents(req, port) => {
                                <<#request_types as ::mesh::payload::DefaultEncoding>::Encoding as ::mesh::payload::FieldEncode<_, _>>::write_field(req, writer);
                                port.into()
                            }
                        )*
                    }
                }

                fn compute_size(&mut self, sizer: ::mesh::payload::protobuf::FieldSizer<'_>) {
                    match self {
                        #(
                            #ident::#method_idents(req, _) => {
                                <<#request_types as ::mesh::payload::DefaultEncoding>::Encoding as ::mesh::payload::FieldEncode::<_, ::mesh::resource::Resource>>::compute_field_size(
                                    req,
                                    sizer);
                            }
                        )*
                    }
                }

                fn decode(
                    method: &str,
                    port: ::mesh::local_node::Port,
                    data: &[u8],
                ) -> Result<Self, (::mesh_rpc::service::ServiceRpcError, ::mesh::local_node::Port)> {
                    match method {
                        #(
                            #method_names => {
                                match mesh::payload::decode(data) {
                                    Ok(req) => Ok(#ident::#method_idents(req, port.into())),
                                    Err(e) => Err((::mesh_rpc::service::ServiceRpcError::InvalidInput(e), port)),
                                }
                            }
                        )*
                        _ => Err((::mesh_rpc::service::ServiceRpcError::UnknownMethod, port)),
                    }
                }
            }
        }
        .to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::MeshServiceGenerator;
    use prost_build::ServiceGenerator;
    use test_with_tracing::test;

    fn service() -> prost_build::Service {
        prost_build::Service {
            name: "Storage".into(),
            proto_name: "StorageAPI".into(),
            package: "sample.storage".into(),
            comments: Default::default(),
            methods: vec![prost_build::Method {
                name: "get_http_status".into(),
                proto_name: "GetHTTPStatus".into(),
                comments: Default::default(),
                input_type: "Request".into(),
                output_type: "Response".into(),
                input_proto_type: ".sample.Request".into(),
                output_proto_type: ".sample.Response".into(),
                options: Default::default(),
                client_streaming: false,
                server_streaming: false,
            }],
            options: Default::default(),
        }
    }

    // Test: Generate a service after existing Rust source with distinct Rust and protobuf method/service names.
    // Expected: Output stays parseable, preserves existing items, and gives the RPC variant the exact request/response types and wire identity.
    #[test]
    fn generated_service_preserves_wire_identity_and_types() {
        let mut output = String::from("fn existing() {}");
        MeshServiceGenerator::new().generate(service(), &mut output);
        let file = syn::parse_file(&output).unwrap();
        assert_eq!(file.items.len(), 4);
        let syn::Item::Fn(existing) = &file.items[0] else {
            panic!("existing item was overwritten");
        };
        assert_eq!(existing.sig.ident, "existing");
        let syn::Item::Enum(rpc) = &file.items[1] else {
            panic!("missing RPC enum");
        };
        assert_eq!(rpc.ident, "Storage");
        assert_eq!(rpc.variants.len(), 1);
        assert_eq!(rpc.variants[0].ident, "GetHttpStatus");
        let syn::Fields::Unnamed(fields) = &rpc.variants[0].fields else {
            panic!("RPC variant must carry request and response channel");
        };
        assert_eq!(fields.unnamed.len(), 2);
        assert_eq!(
            fields.unnamed[0].ty,
            syn::parse_str::<syn::Type>("Request").unwrap()
        );
        assert_eq!(fields.unnamed[1].ty, syn::parse_str::<syn::Type>(
            "::mesh::OneshotSender<::core::result::Result<Response, ::mesh_rpc::service::Status>>"
        ).unwrap());
        let syn::Item::Impl(implementation) = &file.items[3] else {
            panic!("missing RPC trait implementation");
        };
        let name = implementation
            .items
            .iter()
            .find_map(|item| match item {
                syn::ImplItem::Const(item) if item.ident == "NAME" => Some(&item.expr),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            name,
            &syn::parse_str::<syn::Expr>("\"sample.storage.StorageAPI\"").unwrap()
        );
        let method = implementation
            .items
            .iter()
            .find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == "method" => Some(item),
                _ => None,
            })
            .unwrap();
        let syn::Stmt::Expr(syn::Expr::Match(methods), _) = &method.block.stmts[0] else {
            panic!("method identity must dispatch on the RPC variant");
        };
        assert_eq!(methods.arms.len(), 1);
        assert_eq!(
            *methods.arms[0].body,
            syn::parse_str::<syn::Expr>("\"GetHTTPStatus\"").unwrap()
        );
    }

    // Test: Replace qualified request/response types while generating unrelated qualified types and unit messages.
    // Expected: Only exact configured types change; every variant retains its request and typed response channel.
    #[test]
    fn type_replacements_are_exact_and_preserve_unrelated_messages() {
        let mut definition = service();
        definition.methods[0].input_type = "message::Request".into();
        definition.methods[0].output_type = "message::Response".into();
        let mut unrelated = definition.methods[0].clone();
        unrelated.name = "unrelated".into();
        unrelated.proto_name = "Unrelated".into();
        unrelated.input_type = "other::Request".into();
        unrelated.output_type = "other::Response".into();
        let mut unit = unrelated.clone();
        unit.name = "empty".into();
        unit.proto_name = "Empty".into();
        unit.input_type = "()".into();
        unit.output_type = "()".into();
        definition.methods.extend([unrelated, unit]);
        let mut output = String::new();
        MeshServiceGenerator::new()
            .replace_type("Unused", "Never")
            .replace_type("message::Request", "Box<[u8]>")
            .replace_type("message::Response", "(u32, bool)")
            .generate(definition, &mut output);
        let file = syn::parse_file(&output).unwrap();
        let syn::Item::Enum(rpc) = &file.items[0] else {
            panic!("missing RPC enum");
        };
        assert_eq!(rpc.variants.len(), 3);
        for (variant, (name, request, response)) in rpc.variants.iter().zip([
            ("GetHttpStatus", "Box<[u8]>", "(u32, bool)"),
            ("Unrelated", "other::Request", "other::Response"),
            ("Empty", "()", "()"),
        ]) {
            assert_eq!(variant.ident, name);
            let syn::Fields::Unnamed(fields) = &variant.fields else {
                panic!("missing request/response channel fields");
            };
            assert_eq!(fields.unnamed.len(), 2);
            assert_eq!(
                fields.unnamed[0].ty,
                syn::parse_str::<syn::Type>(request).unwrap()
            );
            let channel = format!(
                "::mesh::OneshotSender<::core::result::Result<{response}, ::mesh_rpc::service::Status>>"
            );
            assert_eq!(
                fields.unnamed[1].ty,
                syn::parse_str::<syn::Type>(&channel).unwrap()
            );
        }
    }

    // Test: Generate decoders for one-method and empty services.
    // Expected: Unknown methods and malformed requests return the caller's original port with the correct typed error.
    #[test]
    fn generated_decoder_preserves_port_on_unknown_and_invalid_input() {
        for empty in [false, true] {
            let mut definition = service();
            if empty {
                definition.methods.clear();
            }
            let mut output = String::new();
            MeshServiceGenerator::new().generate(definition, &mut output);
            let file = syn::parse_file(&output).unwrap();
            let syn::Item::Impl(implementation) = &file.items[2] else {
                panic!("missing RPC trait implementation");
            };
            let decode = implementation
                .items
                .iter()
                .find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == "decode" => Some(item),
                    _ => None,
                })
                .unwrap();
            let syn::Stmt::Expr(syn::Expr::Match(methods), _) = &decode.block.stmts[0] else {
                panic!("decoder must select a method before decoding input");
            };
            assert_eq!(methods.arms.len(), if empty { 1 } else { 2 });
            let unknown = methods.arms.last().unwrap();
            assert!(matches!(unknown.pat, syn::Pat::Wild(_)));
            assert_eq!(
                *unknown.body,
                syn::parse_str::<syn::Expr>(
                    "Err((::mesh_rpc::service::ServiceRpcError::UnknownMethod, port))"
                )
                .unwrap()
            );
            if !empty {
                let syn::Expr::Block(block) = &*methods.arms[0].body else {
                    panic!("missing request decoder");
                };
                let syn::Stmt::Expr(syn::Expr::Match(request), _) = &block.block.stmts[0] else {
                    panic!("request decoding must handle success and failure");
                };
                assert_eq!(request.arms.len(), 2);
                assert_eq!(
                    *request.arms[1].body,
                    syn::parse_str::<syn::Expr>(
                        "Err((::mesh_rpc::service::ServiceRpcError::InvalidInput(e), port))"
                    )
                    .unwrap()
                );
            }
        }
    }
}
