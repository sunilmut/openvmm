// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Types and methods for defining and layering sets of UEFI nvram variables.

#![expect(missing_docs)]
#![forbid(unsafe_code)]

use guid::Guid;
use mesh_protobuf::Protobuf;
use thiserror::Error;
use uefi_specs::uefi::nvram::vars::EFI_GLOBAL_VARIABLE;

pub mod delta;

/// A complete base template deferred as raw JSON.
#[derive(Debug, Clone, Protobuf)]
#[mesh(transparent)]
pub struct BaseTemplateJson(Vec<u8>);

impl BaseTemplateJson {
    /// Return the JSON bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for BaseTemplateJson {
    fn from(json: Vec<u8>) -> Self {
        Self(json)
    }
}

/// A complete base template deferred as raw JSON.
///
/// This envelope leaves room for adding reliably sourced template metadata
/// without changing the UEFI configuration interface.
#[derive(Debug, Clone, Protobuf)]
pub struct BaseTemplate {
    pub json: BaseTemplateJson,
}

/// A customer-provided UEFI variable delta deferred as raw JSON.
#[derive(Debug, Clone, Protobuf)]
#[mesh(transparent)]
pub struct UefiVarsDeltaJson(Vec<u8>);

impl UefiVarsDeltaJson {
    /// Return the JSON bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for UefiVarsDeltaJson {
    fn from(json: Vec<u8>) -> Self {
        Self(json)
    }
}

/// Collection of UEFI nvram variables that will be injected on first boot.
#[derive(Debug, Default, Clone, Protobuf)]
pub struct UefiVars {
    /// Secure Boot signature vars
    pub signatures: Option<Signatures>,
    /// UEFI vars that are not Secure Boot signature vars
    pub non_signature_vars: Vec<(String, UefiVar)>,
}

/// A complete set of variables supplied by a built-in template.
#[derive(Debug, Default, Clone, Protobuf)]
#[mesh(transparent)]
pub struct BaseTemplateVars(UefiVars);

/// A complete set of variables ready for NVRAM injection.
#[derive(Debug)]
pub struct FinalVars(UefiVars);

impl From<UefiVars> for BaseTemplateVars {
    fn from(vars: UefiVars) -> Self {
        Self(vars)
    }
}

impl BaseTemplateVars {
    /// Return the Secure Boot signatures supplied by this template.
    pub fn signatures(&self) -> Option<&Signatures> {
        self.0.signatures.as_ref()
    }
}

impl FinalVars {
    /// Resolve an optional base template and custom delta into final variables.
    pub fn resolve(
        base_template: Option<BaseTemplateVars>,
        custom_template_delta: Option<delta::UefiVarsDelta>,
    ) -> Result<Self, ApplyDeltaError> {
        let base_vars = base_template.map_or_else(UefiVars::default, |base| base.0);
        let final_vars = match custom_template_delta {
            Some(delta) => base_vars.apply_delta(delta)?,
            None => base_vars,
        };
        Ok(Self(final_vars))
    }

    /// Return the finalized UEFI variables.
    pub fn into_uefi_vars(self) -> UefiVars {
        self.0
    }
}

#[derive(Debug, Clone, Protobuf)]
pub struct Signatures {
    pub pk: Signature,
    pub kek: Vec<Signature>,
    pub db: Vec<Signature>,
    pub dbx: Vec<Signature>,
    pub moklist: Vec<Signature>,
    pub moklistx: Vec<Signature>,
}

#[derive(Debug, Clone, Protobuf)]
pub enum Signature {
    X509(Vec<X509Cert>),
    Sha256(Vec<Sha256Digest>),
}

#[derive(Debug, Clone, Protobuf)]
pub struct UefiVar {
    pub guid: Guid,
    pub attr: u32,
    pub value: Vec<u8>,
}

#[derive(Clone, Protobuf)]
pub struct X509Cert(pub Vec<u8>);

impl std::fmt::Debug for X509Cert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("X509Cert").field(&"[..]").finish()
    }
}

#[derive(Clone, Protobuf)]
pub struct Sha256Digest(pub [u8; 32]);

impl std::fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Sha256Digest")
            .field(&self.0.map(|b| format!("{:02x?}", b)).join(""))
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum ApplyDeltaError {
    #[error("cannot Append if no base signatures are provided")]
    AppendWithoutBase,
    #[error("cannot use \"Default\" variable type if no base signatures are provided")]
    DefaultWithoutBase,
    #[error("cannot set restricted variable: {name}:{guid}")]
    RestrictedUefiVar { name: String, guid: Guid },
}

impl UefiVars {
    /// Create a new, blank set of UEFI variables.
    pub fn new() -> UefiVars {
        UefiVars::default()
    }

    /// Apply a delta on top of an existing set of UEFI variables.
    pub fn apply_delta(self, delta: delta::UefiVarsDelta) -> Result<UefiVars, ApplyDeltaError> {
        use delta::SignatureDelta;
        use delta::SignatureDeltaVec;
        use delta::SignaturesAppend;
        use delta::SignaturesDelta;
        use delta::SignaturesReplace;

        let signatures = match (self.signatures, delta.signatures) {
            (None, SignaturesDelta::Append(..)) => {
                return Err(ApplyDeltaError::AppendWithoutBase);
            }
            (
                None,
                SignaturesDelta::Replace(SignaturesReplace {
                    pk,
                    kek,
                    db,
                    dbx,
                    moklist,
                    moklistx,
                }),
            ) => {
                fn deny_default(sig_delta: SignatureDelta) -> Result<Signature, ApplyDeltaError> {
                    match sig_delta {
                        SignatureDelta::Sig(sig) => Ok(sig),
                        SignatureDelta::Default => Err(ApplyDeltaError::DefaultWithoutBase),
                    }
                }

                fn deny_default_vec(
                    sig_delta_vec: SignatureDeltaVec,
                ) -> Result<Vec<Signature>, ApplyDeltaError> {
                    match sig_delta_vec {
                        SignatureDeltaVec::Sigs(sig) => Ok(sig),
                        SignatureDeltaVec::Default => Err(ApplyDeltaError::DefaultWithoutBase),
                    }
                }

                Signatures {
                    pk: deny_default(pk)?,
                    kek: deny_default_vec(kek)?,
                    db: deny_default_vec(db)?,
                    dbx: deny_default_vec(dbx)?,
                    moklist: moklist
                        .map(deny_default_vec)
                        .transpose()?
                        .unwrap_or_default(),
                    moklistx: moklistx
                        .map(deny_default_vec)
                        .transpose()?
                        .unwrap_or_default(),
                }
            }
            (
                Some(Signatures {
                    pk,
                    mut kek,
                    mut db,
                    mut dbx,
                    mut moklist,
                    mut moklistx,
                }),
                sig_delta,
            ) => match sig_delta {
                SignaturesDelta::Append(SignaturesAppend {
                    kek: append_kek,
                    db: append_db,
                    dbx: append_dbx,
                    moklist: append_moklist,
                    moklistx: append_moklistx,
                }) => {
                    if let Some(append_kek) = append_kek {
                        kek.extend(append_kek);
                    }

                    if let Some(append_db) = append_db {
                        db.extend(append_db);
                    }

                    if let Some(append_dbx) = append_dbx {
                        dbx.extend(append_dbx);
                    }

                    if let Some(append_moklist) = append_moklist {
                        moklist.extend(append_moklist)
                    }

                    if let Some(append_moklistx) = append_moklistx {
                        moklistx.extend(append_moklistx)
                    }

                    Signatures {
                        pk,
                        kek,
                        db,
                        dbx,
                        moklist,
                        moklistx,
                    }
                }
                SignaturesDelta::Replace(SignaturesReplace {
                    pk: replace_pk,
                    kek: replace_kek,
                    db: replace_db,
                    dbx: replace_dbx,
                    moklist: replace_moklist,
                    moklistx: replace_moklistx,
                }) => {
                    fn replace_default(sig_delta: SignatureDelta, base: Signature) -> Signature {
                        match sig_delta {
                            SignatureDelta::Sig(sig) => sig,
                            SignatureDelta::Default => base,
                        }
                    }

                    fn replace_default_vec(
                        sig_delta_vec: SignatureDeltaVec,
                        base: Vec<Signature>,
                    ) -> Vec<Signature> {
                        match sig_delta_vec {
                            SignatureDeltaVec::Sigs(sigs) => sigs,
                            SignatureDeltaVec::Default => base,
                        }
                    }

                    fn replace_default_option_vec(
                        sig_delta_vec: Option<SignatureDeltaVec>,
                        base: Vec<Signature>,
                    ) -> Vec<Signature> {
                        match sig_delta_vec {
                            Some(SignatureDeltaVec::Sigs(sigs)) => sigs,
                            Some(SignatureDeltaVec::Default) | None => base,
                        }
                    }

                    Signatures {
                        pk: replace_default(replace_pk, pk),
                        kek: replace_default_vec(replace_kek, kek),
                        db: replace_default_vec(replace_db, db),
                        dbx: replace_default_vec(replace_dbx, dbx),
                        moklist: replace_default_option_vec(replace_moklist, moklist),
                        moklistx: replace_default_option_vec(replace_moklistx, moklistx),
                    }
                }
            },
        };

        let mut non_signature_vars = self.non_signature_vars;

        // Replace overwritten vars, append new vars
        'outer: for (new_key, new_val) in delta.non_signature_vars {
            if new_key == "dbDefault" && new_val.guid == EFI_GLOBAL_VARIABLE {
                return Err(ApplyDeltaError::RestrictedUefiVar {
                    name: new_key,
                    guid: new_val.guid,
                });
            }

            for (old_key, old_val) in &mut non_signature_vars {
                if *old_key == new_key {
                    *old_val = new_val;
                    continue 'outer;
                }
            }
            non_signature_vars.push((new_key, new_val));
        }

        Ok(UefiVars {
            signatures: Some(signatures),
            non_signature_vars,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delta::SignatureDelta;
    use crate::delta::SignatureDeltaVec;
    use crate::delta::SignaturesAppend;
    use crate::delta::SignaturesDelta;
    use crate::delta::SignaturesReplace;
    use crate::delta::UefiVarsDelta;
    use test_with_tracing::test;

    fn signature(marker: u8) -> Signature {
        Signature::Sha256(vec![Sha256Digest([marker; 32])])
    }

    // Test: Retain deferred template and delta JSON envelopes without eagerly validating or normalizing their bytes.
    // Expected: Empty, whitespace-rich, malformed and non-UTF8 inputs remain byte-identical across wrapper construction and cloning.
    #[test]
    fn deferred_json_envelopes_preserve_opaque_bytes() {
        for bytes in [
            vec![],
            b" { \"Name\" : 1 } \n".to_vec(),
            vec![b'{', 0, 0xff],
        ] {
            let base = BaseTemplate {
                json: bytes.clone().into(),
            };
            let delta = UefiVarsDeltaJson::from(bytes.clone());
            assert_eq!(base.json.as_bytes(), bytes);
            assert_eq!(base.clone().json.as_bytes(), bytes);
            assert_eq!(delta.as_bytes(), bytes);
            assert_eq!(delta.clone().as_bytes(), bytes);
        }
    }

    fn base() -> UefiVars {
        UefiVars {
            signatures: Some(Signatures {
                pk: signature(0),
                kek: vec![signature(1)],
                db: vec![signature(2)],
                dbx: vec![signature(3)],
                moklist: vec![signature(4)],
                moklistx: vec![signature(5)],
            }),
            non_signature_vars: Vec::new(),
        }
    }

    fn markers(signatures: &[Signature]) -> Vec<u8> {
        signatures
            .iter()
            .map(|signature| {
                let Signature::Sha256(digests) = signature else {
                    panic!("expected SHA256 signature")
                };
                assert_eq!(digests.len(), 1);
                let marker = digests[0].0[0];
                assert_eq!(digests[0].0, [marker; 32]);
                marker
            })
            .collect()
    }

    // Test: Append distinct signatures to every appendable collection.
    // Expected: The platform key stays unchanged and each list retains old-before-new order without crossing collections.
    #[test]
    fn append_preserves_platform_key_and_each_collection_order() {
        let template: BaseTemplateVars = base().into();
        assert_eq!(markers(&[template.signatures().unwrap().pk.clone()]), [0]);
        let delta = UefiVarsDelta {
            signatures: SignaturesDelta::Append(SignaturesAppend {
                kek: Some(vec![signature(11)]),
                db: Some(vec![signature(12)]),
                dbx: Some(vec![signature(13)]),
                moklist: Some(vec![signature(14)]),
                moklistx: Some(vec![signature(15)]),
            }),
            non_signature_vars: Vec::new(),
        };
        let vars = FinalVars::resolve(Some(template), Some(delta))
            .unwrap()
            .into_uefi_vars();
        let signatures = vars.signatures.unwrap();
        assert_eq!(markers(&[signatures.pk]), [0]);
        for (index, list) in [
            signatures.kek,
            signatures.db,
            signatures.dbx,
            signatures.moklist,
            signatures.moklistx,
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(markers(list), [index as u8 + 1, index as u8 + 11]);
        }
    }

    // Test: Replace with defaults, explicit values, empty lists, and omitted optional MOK lists.
    // Expected: Defaults/omissions retain base entries; explicit empty lists clear them; no-base explicit replacements create a complete set.
    #[test]
    fn replacement_distinguishes_defaults_omissions_and_explicit_empty_lists() {
        for mode in 0..3 {
            let replace = SignaturesReplace {
                pk: if mode == 0 {
                    SignatureDelta::Default
                } else {
                    SignatureDelta::Sig(signature(20))
                },
                kek: if mode == 0 {
                    SignatureDeltaVec::Default
                } else {
                    SignatureDeltaVec::Sigs(Vec::new())
                },
                db: if mode == 0 {
                    SignatureDeltaVec::Default
                } else {
                    SignatureDeltaVec::Sigs(vec![signature(22)])
                },
                dbx: if mode == 0 {
                    SignatureDeltaVec::Default
                } else {
                    SignatureDeltaVec::Sigs(Vec::new())
                },
                moklist: match mode {
                    0 => Some(SignatureDeltaVec::Default),
                    1 => Some(SignatureDeltaVec::Sigs(Vec::new())),
                    _ => None,
                },
                moklistx: match mode {
                    0 => Some(SignatureDeltaVec::Default),
                    1 => Some(SignatureDeltaVec::Sigs(vec![signature(25)])),
                    _ => None,
                },
            };
            let vars = base()
                .apply_delta(UefiVarsDelta {
                    signatures: SignaturesDelta::Replace(replace),
                    non_signature_vars: Vec::new(),
                })
                .unwrap();
            let signatures = vars.signatures.unwrap();
            assert_eq!(
                markers(&[signatures.pk]),
                if mode == 0 { vec![0] } else { vec![20] }
            );
            assert_eq!(
                markers(&signatures.kek),
                if mode == 0 { vec![1] } else { vec![] }
            );
            assert_eq!(
                markers(&signatures.db),
                if mode == 0 { vec![2] } else { vec![22] }
            );
            assert_eq!(
                markers(&signatures.dbx),
                if mode == 0 { vec![3] } else { vec![] }
            );
            assert_eq!(
                markers(&signatures.moklist),
                if mode == 1 { vec![] } else { vec![4] }
            );
            assert_eq!(
                markers(&signatures.moklistx),
                if mode == 1 { vec![25] } else { vec![5] }
            );
        }
        for optional in [None, Some(SignatureDeltaVec::Sigs(vec![signature(9)]))] {
            let vars = UefiVars::new()
                .apply_delta(UefiVarsDelta {
                    signatures: SignaturesDelta::Replace(SignaturesReplace {
                        pk: SignatureDelta::Sig(signature(7)),
                        kek: SignatureDeltaVec::Sigs(Vec::new()),
                        db: SignatureDeltaVec::Sigs(Vec::new()),
                        dbx: SignatureDeltaVec::Sigs(Vec::new()),
                        moklist: optional.clone(),
                        moklistx: optional.clone(),
                    }),
                    non_signature_vars: Vec::new(),
                })
                .unwrap();
            let signatures = vars.signatures.unwrap();
            assert_eq!(markers(&[signatures.pk]), [7]);
            assert!(
                signatures.kek.is_empty() && signatures.db.is_empty() && signatures.dbx.is_empty()
            );
            let expected = if optional.is_some() { vec![9] } else { vec![] };
            assert_eq!(markers(&signatures.moklist), expected);
            assert_eq!(markers(&signatures.moklistx), expected);
        }
        let error = UefiVars::new()
            .apply_delta(UefiVarsDelta {
                signatures: SignaturesDelta::Replace(SignaturesReplace {
                    pk: SignatureDelta::Sig(signature(7)),
                    kek: SignatureDeltaVec::Default,
                    db: SignatureDeltaVec::Sigs(Vec::new()),
                    dbx: SignatureDeltaVec::Sigs(Vec::new()),
                    moklist: None,
                    moklistx: None,
                }),
                non_signature_vars: Vec::new(),
            })
            .unwrap_err();
        assert!(matches!(error, ApplyDeltaError::DefaultWithoutBase));
    }

    fn variable(guid: Guid, marker: u8) -> UefiVar {
        UefiVar {
            guid,
            attr: 7,
            value: vec![marker],
        }
    }

    fn apply_variables(vars: UefiVars, variables: Vec<(String, UefiVar)>) -> UefiVars {
        vars.apply_delta(UefiVarsDelta {
            signatures: SignaturesDelta::Append(SignaturesAppend {
                kek: None,
                db: None,
                dbx: None,
                moklist: None,
                moklistx: None,
            }),
            non_signature_vars: variables,
        })
        .unwrap()
    }

    // Test: Replace an exact variable identity and append a differently named variable, including dbDefault outside the restricted namespace.
    // Expected: Exact replacements keep ordering, appended entries retain values/attributes, and restriction is vendor-sensitive.
    #[test]
    fn ordinary_variable_replacement_and_append_preserve_values() {
        let mut vars = base();
        vars.non_signature_vars
            .push(("Name".into(), variable(EFI_GLOBAL_VARIABLE, 1)));
        let vars = apply_variables(
            vars,
            vec![
                ("Name".into(), variable(EFI_GLOBAL_VARIABLE, 2)),
                ("dbDefault".into(), variable(Guid::ZERO, 3)),
            ],
        );
        assert_eq!(vars.non_signature_vars.len(), 2);
        for (index, (name, value)) in vars.non_signature_vars.iter().enumerate() {
            assert_eq!(name, ["Name", "dbDefault"][index]);
            assert_eq!(value.value, [index as u8 + 2]);
            assert_eq!(value.attr, 7);
            assert_eq!(value.guid, [EFI_GLOBAL_VARIABLE, Guid::ZERO][index]);
        }
    }

    // Test: Add the same variable name in a distinct vendor namespace after an exact-identity replacement control.
    // Expected: UEFI variable identity includes both name and GUID, so the two namespace values coexist.
    #[test]
    #[ignore = "product bug: delta replacement matches variable name without vendor GUID"]
    fn same_name_variables_in_distinct_vendor_namespaces_coexist() {
        let mut vars = base();
        vars.non_signature_vars
            .push(("Name".into(), variable(EFI_GLOBAL_VARIABLE, 1)));
        let vars = apply_variables(
            vars,
            vec![("Name".into(), variable(EFI_GLOBAL_VARIABLE, 2))],
        );
        assert_eq!(vars.non_signature_vars.len(), 1);
        assert_eq!(vars.non_signature_vars[0].1.value, [2]);
        let vars = apply_variables(vars, vec![("Name".into(), variable(Guid::ZERO, 3))]);
        assert_eq!(vars.non_signature_vars.len(), 2);
        assert_eq!(vars.non_signature_vars[0].1.guid, EFI_GLOBAL_VARIABLE);
        assert_eq!(vars.non_signature_vars[0].1.value, [2]);
        assert_eq!(vars.non_signature_vars[1].1.guid, Guid::ZERO);
        assert_eq!(vars.non_signature_vars[1].1.value, [3]);
    }

    #[test]
    fn no_templates_resolve_to_empty_final_vars() {
        let vars = FinalVars::resolve(None, None).unwrap().into_uefi_vars();

        assert!(vars.signatures.is_none());
        assert!(vars.non_signature_vars.is_empty());
    }

    #[test]
    fn append_without_base_fails() {
        let delta = UefiVarsDelta {
            signatures: SignaturesDelta::Append(SignaturesAppend {
                kek: None,
                db: None,
                dbx: None,
                moklist: None,
                moklistx: None,
            }),
            non_signature_vars: Vec::new(),
        };

        assert!(matches!(
            FinalVars::resolve(None, Some(delta)),
            Err(ApplyDeltaError::AppendWithoutBase)
        ));
    }

    #[test]
    fn default_without_base_fails() {
        let delta = UefiVarsDelta {
            signatures: SignaturesDelta::Replace(SignaturesReplace {
                pk: SignatureDelta::Default,
                kek: SignatureDeltaVec::Default,
                db: SignatureDeltaVec::Default,
                dbx: SignatureDeltaVec::Default,
                moklist: None,
                moklistx: None,
            }),
            non_signature_vars: Vec::new(),
        };

        assert!(matches!(
            FinalVars::resolve(None, Some(delta)),
            Err(ApplyDeltaError::DefaultWithoutBase)
        ));
    }

    #[test]
    fn restricted_uefi_var_fails() {
        let base_template = UefiVars {
            signatures: Some(Signatures {
                pk: Signature::X509(Vec::new()),
                kek: Vec::new(),
                db: Vec::new(),
                dbx: Vec::new(),
                moklist: Vec::new(),
                moklistx: Vec::new(),
            }),
            non_signature_vars: Vec::new(),
        }
        .into();
        let delta = UefiVarsDelta {
            signatures: SignaturesDelta::Append(SignaturesAppend {
                kek: None,
                db: None,
                dbx: None,
                moklist: None,
                moklistx: None,
            }),
            non_signature_vars: vec![(
                "dbDefault".into(),
                UefiVar {
                    guid: EFI_GLOBAL_VARIABLE,
                    attr: 0,
                    value: Vec::new(),
                },
            )],
        };

        assert!(matches!(
            FinalVars::resolve(Some(base_template), Some(delta)),
            Err(ApplyDeltaError::RestrictedUefiVar { name, guid })
                if name == "dbDefault" && guid == EFI_GLOBAL_VARIABLE
        ));
    }
}
