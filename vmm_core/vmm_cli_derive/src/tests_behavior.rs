// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use syn::parse_quote;
use test_with_tracing::test;

// Test: Expand the same declarations exercised by the compiled consumer integration tests.
// Expected: All supported field and group forms emit syntactically valid Rust.
#[test]
fn consumer_fixtures_expand_to_valid_rust() {
    let fixtures = syn::parse_file(include_str!("../tests/fixtures/mod.rs")).unwrap();
    for item in fixtures.items {
        let input: DeriveInput = syn::parse2(quote!(#item)).unwrap();
        let expanded = match &input.data {
            Data::Struct(_) => expand_struct(input),
            Data::Enum(_) => expand_group(input),
            Data::Union(_) => panic!("consumer fixture must be a struct or enum"),
        }
        .unwrap();
        syn::parse2::<syn::File>(expanded).unwrap();
    }
}

// Test: Apply struct derives to enum, union, tuple and unit declarations.
// Expected: Unsupported shapes produce specific compile diagnostics instead of an expansion.
#[test]
fn struct_derive_rejects_unsupported_shapes() {
    for declaration in [
        quote!(
            enum Args {
                One,
            }
        ),
        quote!(union Args { value: u8 }),
    ] {
        assert_eq!(
            expand_struct(syn::parse2(declaration).unwrap())
                .unwrap_err()
                .to_string(),
            "KeyValueArgs may only be derived for structs"
        );
    }
    for declaration in [
        quote!(
            struct Args(u8);
        ),
        quote!(
            struct Args;
        ),
    ] {
        assert_eq!(
            expand_struct(syn::parse2(declaration).unwrap())
                .unwrap_err()
                .to_string(),
            "KeyValueArgs requires named fields"
        );
    }
}

// Test: Declare two positional arguments, incompatible tri-state flags or one-sided mappings.
// Expected: Each ambiguous field declaration is rejected with its actionable diagnostic.
#[test]
fn ambiguous_field_modes_are_rejected() {
    let cases: [(DeriveInput, &str); 4] = [
        (
            parse_quote! {
                struct Args {
                    #[kv(positional)] first: String,
                    #[kv(positional)] second: String,
                }
            },
            "only one `positional` field is allowed",
        ),
        (
            parse_quote! {
                struct Args {
                    #[kv(flag, present = true, absent = false)] flag: Option<bool>,
                }
            },
            "`present`/`absent` are not allowed on an `Option<bool>` flag",
        ),
        (
            parse_quote! { struct Args { #[kv(flag, present = 8)] flag: u8 } },
            "`flag` requires both `present` and `absent` (for non-bool fields), or neither (for bool)",
        ),
        (
            parse_quote! { struct Args { #[kv(flag, absent = 3)] flag: u8 } },
            "`flag` requires both `present` and `absent` (for non-bool fields), or neither (for bool)",
        ),
    ];
    for (input, message) in cases {
        assert_eq!(expand_struct(input).unwrap_err().to_string(), message);
    }
}

// Test: Use misspelled field or variant options in otherwise valid declarations.
// Expected: Both derives reject the unknown kv attribute, rather than silently ignoring it.
#[test]
fn unknown_attributes_are_rejected() {
    let field: DeriveInput = parse_quote! {
        struct Args { #[kv(defualt)] count: u32 }
    };
    let variant: DeriveInput = parse_quote! {
        enum Backend { #[kv(defualt)] Memory }
    };
    assert_eq!(
        expand_struct(field).unwrap_err().to_string(),
        "unknown `kv` attribute"
    );
    assert_eq!(
        expand_group(variant).unwrap_err().to_string(),
        "unknown `kv` attribute"
    );
}

// Test: Apply group derives to non-enums or variants with unsupported payload shapes.
// Expected: Invalid declarations fail with the appropriate type or variant diagnostic.
#[test]
fn group_derive_rejects_unsupported_shapes() {
    assert_eq!(
        expand_group(parse_quote!(
            struct Backend {}
        ))
        .unwrap_err()
        .to_string(),
        "KeyValueGroup may only be derived for enums"
    );
    for declaration in [
        quote!(
            enum Backend {
                File { path: String },
            }
        ),
        quote!(
            enum Backend {
                File(String, u8),
            }
        ),
        quote!(
            enum Backend {
                File(),
            }
        ),
    ] {
        assert_eq!(
            expand_group(syn::parse2(declaration).unwrap())
                .unwrap_err()
                .to_string(),
            "KeyValueGroup variants must be a unit or a single-field tuple"
        );
    }
}

// Test: Mark a payload variant or two unit variants as the group default.
// Expected: Only a single unit default is accepted, with specific errors for both violations.
#[test]
fn group_defaults_must_be_unique_unit_variants() {
    assert_eq!(
        expand_group(parse_quote! {
            enum Backend { #[kv(default)] File(String) }
        })
        .unwrap_err()
        .to_string(),
        "`#[kv(default)]` is only allowed on unit variants"
    );
    assert_eq!(
        expand_group(parse_quote! {
            enum Backend { #[kv(default)] Memory, #[kv(default)] File }
        })
        .unwrap_err()
        .to_string(),
        "only one variant may be marked `#[kv(default)]`"
    );
}
