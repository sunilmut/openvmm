// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Serde defs for ADO YAML

#![expect(missing_docs)]
#![forbid(unsafe_code)]

use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

mod none {
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;

    pub fn serialize<S>(_: &(), ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_str("none")
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<(), D::Error> {
        let s: &str = Deserialize::deserialize(d)?;
        if s != "none" {
            return Err(serde::de::Error::custom("field must be 'none'"));
        }
        Ok(())
    }
}

/// Valid names may only contain alphanumeric characters and '_' and may not
/// start with a number.
fn validate_name<S>(s: &str, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if s.is_empty() {
        return Err(serde::ser::Error::custom("name cannot be empty"));
    }

    if s.chars().next().unwrap().is_ascii_digit() {
        return Err(serde::ser::Error::custom("name cannot start with a number"));
    }

    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(serde::ser::Error::custom(
            "name must be ascii alphanumeric + '_'",
        ));
    }

    ser.serialize_str(s)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerBranches {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    // Wrapping this in an Option is necessary to prevent problems when deserializing and exclude isn't present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerTags {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    // Wrapping this in an Option is necessary to prevent problems when deserializing and exclude isn't present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerPaths {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    // Wrapping this in an Option is necessary to prevent problems when deserializing and exclude isn't present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(rename_all = "camelCase")]
pub enum PrTrigger {
    None(#[serde(with = "none")] ()),
    #[serde(rename_all = "camelCase")]
    Some {
        auto_cancel: bool,
        drafts: bool,
        branches: TriggerBranches,
        #[serde(skip_serializing_if = "Option::is_none")]
        paths: Option<TriggerPaths>,
    },
    // serde has a bug with untagged and `with` during deserialization
    NoneWorkaround(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(rename_all = "camelCase")]
pub enum CiTrigger {
    None(#[serde(with = "none")] ()),
    #[serde(rename_all = "camelCase")]
    Some {
        batch: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        branches: Option<TriggerBranches>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tags: Option<TriggerTags>,
        #[serde(skip_serializing_if = "Option::is_none")]
        paths: Option<TriggerPaths>,
    },
    // serde has a bug with untagged and `with` during deserialization
    NoneWorkaround(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Schedule {
    // FUTURE?: proper cron validation?
    pub cron: String,
    pub display_name: String,
    pub branches: TriggerBranches,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    #[serde(default)]
    pub batch: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Variable {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pipeline {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<CiTrigger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pr: Option<PrTrigger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedules: Option<Vec<Schedule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables: Option<Vec<Variable>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<Parameter>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stages: Option<Vec<Stage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jobs: Option<Vec<Job>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extends: Option<Extends>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Extends {
    pub template: String,
    pub parameters: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resources {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub repositories: Vec<ResourcesRepository>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesRepository {
    // Alias for the specified repository.
    //
    // Acceptable values: [-_A-Za-z0-9]*.
    pub repository: String,
    /// ID of the service endpoint connecting to this repository
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Repository name. Format depends on 'type'; does not accept variables
    pub name: String,
    /// ref name to checkout; defaults to 'refs/heads/main'.
    #[serde(rename = "ref")]
    pub r#ref: String,
    #[serde(rename = "type")]
    pub r#type: ResourcesRepositoryType,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourcesRepositoryType {
    Git,
    GitHub,
    GitHubEnterprise,
    Bitbucket,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parameter {
    pub name: String,
    pub display_name: String,
    #[serde(flatten)]
    pub ty: ParameterType,
}

// ADO also has specialized types for things like steps/jobs/stages, etc... but
// at this time, it's unclear how they'd be useful in flowey.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ParameterType {
    Boolean {
        #[serde(skip_serializing_if = "Option::is_none")]
        default: Option<bool>,
    },
    String {
        #[serde(skip_serializing_if = "Option::is_none")]
        default: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        values: Option<Vec<String>>,
    },
    Number {
        #[serde(skip_serializing_if = "Option::is_none")]
        default: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        values: Option<Vec<i64>>,
    },
    Object {
        #[serde(skip_serializing_if = "Option::is_none")]
        default: Option<serde_yaml::Value>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stage {
    /// Valid names may only contain alphanumeric characters and '_' and may
    /// not start with a number.
    #[serde(serialize_with = "validate_name")]
    pub stage: String,
    pub display_name: String,
    pub depends_on: BTreeSet<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    pub jobs: Vec<Job>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(rename_all = "camelCase")]
pub enum Pool {
    Pool(String),
    PoolWithMetadata(BTreeMap<String, serde_yaml::Value>),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    #[serde(serialize_with = "validate_name")]
    pub job: String,
    pub display_name: String,
    pub pool: Pool,
    pub depends_on: BTreeSet<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_in_minutes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables: Option<Vec<Variable>>,
    // individual steps are not type-checked by the serde schema, as there are a
    // _lot_ of different step kinds nodes might be emitting.
    //
    // instead, trust that the user knows what they're doing when emitting yaml
    // snippets.
    pub steps: Vec<serde_yaml::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    fn job(name: &str) -> Job {
        Job {
            job: name.into(),
            display_name: "Job".into(),
            pool: Pool::Pool("ubuntu".into()),
            depends_on: BTreeSet::new(),
            timeout_in_minutes: None,
            condition: None,
            variables: None,
            steps: vec![],
        }
    }

    fn yaml<T: Serialize>(value: &T) -> Result<serde_yaml::Value, serde_yaml::Error> {
        serde_yaml::to_value(value)
    }

    // Test: Serialize jobs and stages whose names are valid, empty, start with
    //       a digit, or contain '-', a space or non-ASCII letters.
    // Expected: Only ASCII alphanumeric/underscore names not starting with a
    //       digit serialize; every other name fails with an explanation.
    #[test]
    fn job_and_stage_names_are_validated() {
        for valid in ["build", "_x", "Job_2"] {
            assert_eq!(yaml(&job(valid)).unwrap()["job"], valid);
        }
        for (invalid, expected) in [
            ("", "name cannot be empty"),
            ("2build", "name cannot start with a number"),
            ("build-x", "ascii alphanumeric"),
            ("build x", "ascii alphanumeric"),
            ("bü", "ascii alphanumeric"),
        ] {
            let error = yaml(&job(invalid)).unwrap_err().to_string();
            assert!(error.contains(expected), "{invalid:?}: {error}");
            let stage = Stage {
                stage: invalid.into(),
                display_name: "S".into(),
                depends_on: BTreeSet::new(),
                condition: None,
                jobs: vec![],
            };
            assert!(yaml(&stage).is_err(), "{invalid:?}");
        }
    }

    // Test: Serialize disabled triggers, enabled triggers with empty and
    //       populated filters, schedules with and without batch, and parse a
    //       schedule that omits batch.
    // Expected: Disabled triggers are the literal "none"; field names are
    //       camelCase; empty includes, absent excludes and false batch are
    //       omitted; a missing batch parses as false.
    #[test]
    fn triggers_and_schedules_use_ado_field_names() {
        assert_eq!(yaml(&PrTrigger::None(())).unwrap(), "none");
        assert_eq!(yaml(&CiTrigger::None(())).unwrap(), "none");
        let pr = PrTrigger::Some {
            auto_cancel: true,
            drafts: false,
            branches: TriggerBranches {
                include: vec!["main".into()],
                exclude: None,
            },
            paths: Some(TriggerPaths {
                include: vec![],
                exclude: Some(vec!["Guide/*".into()]),
            }),
        };
        assert_eq!(
            serde_yaml::to_string(&pr).unwrap(),
            "autoCancel: true\ndrafts: false\nbranches:\n  include:\n  - main\npaths:\n  exclude:\n  - Guide/*\n"
        );
        let ci = CiTrigger::Some {
            batch: true,
            branches: None,
            tags: Some(TriggerTags {
                include: vec!["v*".into()],
                exclude: None,
            }),
            paths: None,
        };
        assert_eq!(
            serde_yaml::to_string(&ci).unwrap(),
            "batch: true\ntags:\n  include:\n  - v*\n"
        );

        let schedule = |batch| Schedule {
            cron: "0 0 * * *".into(),
            display_name: "Nightly".into(),
            branches: TriggerBranches {
                include: vec!["main".into()],
                exclude: None,
            },
            batch,
        };
        assert!(yaml(&schedule(false)).unwrap().get("batch").is_none());
        assert_eq!(yaml(&schedule(true)).unwrap()["batch"], true);
        let parsed: Schedule = serde_yaml::from_str(
            "cron: '0 0 * * *'\ndisplayName: Nightly\nbranches:\n  include: [main]\n",
        )
        .unwrap();
        assert!(!parsed.batch && parsed.display_name == "Nightly");
    }

    // Test: Serialize each parameter type, repository types and both pool
    //       forms, then round-trip a complete pipeline through YAML.
    // Expected: Parameters carry a lowercase `type` tag next to their name;
    //       repositories use `ref`/`type` with lowercase type names; pools are a
    //       string or a map; the pipeline re-serializes identically.
    #[test]
    fn parameters_repositories_pools_and_pipelines_round_trip() {
        let param = |ty| Parameter {
            name: "p".into(),
            display_name: "P".into(),
            ty,
        };
        assert_eq!(
            serde_yaml::to_string(&param(ParameterType::Boolean {
                default: Some(true)
            }))
            .unwrap(),
            "name: p\ndisplayName: P\ntype: boolean\ndefault: true\n"
        );
        assert_eq!(
            yaml(&param(ParameterType::Number {
                default: None,
                values: Some(vec![1, 2])
            }))
            .unwrap()["type"],
            "number"
        );
        assert_eq!(
            yaml(&param(ParameterType::Object { default: None })).unwrap()["type"],
            "object"
        );

        for (ty, name) in [
            (ResourcesRepositoryType::Git, "git"),
            (ResourcesRepositoryType::GitHub, "github"),
            (
                ResourcesRepositoryType::GitHubEnterprise,
                "githubenterprise",
            ),
            (ResourcesRepositoryType::Bitbucket, "bitbucket"),
        ] {
            let repo = ResourcesRepository {
                repository: "self_alias".into(),
                endpoint: None,
                name: "org/repo".into(),
                r#ref: "refs/heads/main".into(),
                r#type: ty,
            };
            let value = yaml(&repo).unwrap();
            assert_eq!(
                (value["type"].as_str(), value["ref"].as_str()),
                (Some(name), Some("refs/heads/main"))
            );
            assert!(value.get("endpoint").is_none());
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("name".to_string(), serde_yaml::Value::from("pool-a"));
        let mut pool_job = job("with_pool");
        pool_job.pool = Pool::PoolWithMetadata(metadata);
        let pipeline = Pipeline {
            name: Some("$(Date)".into()),
            trigger: Some(CiTrigger::None(())),
            pr: Some(PrTrigger::None(())),
            schedules: None,
            variables: Some(vec![Variable {
                name: "V".into(),
                value: "1".into(),
            }]),
            parameters: Some(vec![param(ParameterType::String {
                default: Some("a".into()),
                values: Some(vec!["a".into(), "b".into()]),
            })]),
            resources: Some(Resources {
                repositories: vec![ResourcesRepository {
                    repository: "tools".into(),
                    endpoint: Some("svc".into()),
                    name: "org/tools".into(),
                    r#ref: "refs/heads/main".into(),
                    r#type: ResourcesRepositoryType::GitHub,
                }],
            }),
            stages: None,
            jobs: Some(vec![job("plain"), pool_job]),
            extends: None,
        };
        let text = serde_yaml::to_string(&pipeline).unwrap();
        let reparsed: Pipeline = serde_yaml::from_str(&text).unwrap();
        assert_eq!(serde_yaml::to_string(&reparsed).unwrap(), text);
        assert!(text.contains("trigger: none\npr: none\n"), "{text}");
        assert!(
            text.contains("pool: ubuntu\n") && text.contains("pool:\n    name: pool-a\n"),
            "{text}"
        );
    }

    // IGNORED: entry348-bug1; fields skipped when empty on serialize
    //       (`Resources::repositories`, trigger `include` lists) are required on
    //       deserialize, so the crate's own output cannot be parsed back. Latent:
    //       nothing in the repository deserializes these types today.
    //
    // Test: Serialize a pipeline with empty resources and a branch filter that
    //       only excludes, then parse the YAML back.
    // Expected: The emitted YAML parses back into the same structure.
    #[test]
    #[ignore = "entry348-bug1: empty-skipped fields are required when parsing"]
    fn empty_skipped_fields_parse_back() {
        let pipeline = Pipeline {
            name: None,
            trigger: Some(CiTrigger::Some {
                batch: false,
                branches: Some(TriggerBranches {
                    include: vec![],
                    exclude: Some(vec!["old".into()]),
                }),
                tags: None,
                paths: None,
            }),
            pr: None,
            schedules: None,
            variables: None,
            parameters: None,
            resources: Some(Resources::default()),
            stages: None,
            jobs: None,
            extends: None,
        };
        let text = serde_yaml::to_string(&pipeline).unwrap();
        let reparsed: Pipeline = serde_yaml::from_str(&text).unwrap();
        assert_eq!(serde_yaml::to_string(&reparsed).unwrap(), text);
    }
}
