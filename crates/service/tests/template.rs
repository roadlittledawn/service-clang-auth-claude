//! §15: the SAM template sets the cost guardrails (§11) and contains none of
//! the forbidden resources. `scripts/check-template.sh` also runs cfn-lint.

use serde_yaml::Value;

fn template() -> (String, Value) {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../infra/template.yaml");
    let text = std::fs::read_to_string(path).expect("infra/template.yaml");
    let yaml: Value = serde_yaml::from_str(&text).expect("valid YAML");
    (text, yaml)
}

fn resources(t: &Value) -> Vec<(String, &Value)> {
    t["Resources"]
        .as_mapping()
        .expect("Resources")
        .iter()
        .map(|(k, v)| (k.as_str().unwrap().to_string(), v))
        .collect()
}

fn of_type<'a>(t: &'a Value, ty: &str) -> Vec<&'a Value> {
    resources(t)
        .into_iter()
        .filter(|(_, r)| r["Type"].as_str() == Some(ty))
        .map(|(_, r)| r)
        .collect()
}

/// `!Ref X` parses as a tagged value; return the referenced name.
fn ref_name(v: &Value) -> Option<String> {
    match v {
        Value::Tagged(t) if t.tag == "Ref" => t.value.as_str().map(str::to_string),
        Value::Mapping(m) => m.get("Ref").and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

#[test]
fn http_api_is_throttled() {
    let (_, t) = template();
    let apis = of_type(&t, "AWS::Serverless::HttpApi");
    assert_eq!(apis.len(), 1);
    let s = &apis[0]["Properties"]["DefaultRouteSettings"];
    assert_eq!(s["ThrottlingRateLimit"].as_f64(), Some(5.0));
    assert_eq!(s["ThrottlingBurstLimit"].as_u64(), Some(10));
    assert!(
        apis[0]["Properties"]["Domain"]["DomainName"].is_tagged()
            || apis[0]["Properties"]["Domain"]["DomainName"].is_string()
    );
}

trait Tagged {
    fn is_tagged(&self) -> bool;
}
impl Tagged for Value {
    fn is_tagged(&self) -> bool {
        matches!(self, Value::Tagged(_))
    }
}

#[test]
fn function_has_guardrails() {
    let (_, t) = template();
    let fns = of_type(&t, "AWS::Serverless::Function");
    assert_eq!(fns.len(), 1);
    let p = &fns[0]["Properties"];
    assert_eq!(p["ReservedConcurrentExecutions"].as_u64(), Some(5));
    assert_eq!(p["Timeout"].as_u64(), Some(10));
    assert_eq!(p["MemorySize"].as_u64(), Some(512));
    assert_eq!(p["Runtime"].as_str(), Some("provided.al2023"));
    assert_eq!(p["Architectures"][0].as_str(), Some("arm64"));
    assert!(p.get("VpcConfig").is_none(), "no Lambda-in-VPC");
    assert!(
        p.get("ProvisionedConcurrencyConfig").is_none(),
        "no provisioned concurrency"
    );
    assert!(p.get("AutoPublishAlias").is_none());
    assert_ne!(p["Tracing"].as_str(), Some("Active"), "no X-Ray");
    assert_eq!(
        fns[0]["Metadata"]["BuildMethod"].as_str(),
        Some("rust-cargolambda")
    );

    // Logs go to the explicit log group.
    let lg = ref_name(&p["LoggingConfig"]["LogGroup"]).expect("LoggingConfig.LogGroup is a !Ref");
    let groups = resources(&t);
    let (_, group) = groups
        .iter()
        .find(|(k, _)| *k == lg)
        .expect("referenced log group exists");
    assert_eq!(group["Type"].as_str(), Some("AWS::Logs::LogGroup"));
}

#[test]
fn log_group_retention_is_14_days() {
    let (_, t) = template();
    let groups = of_type(&t, "AWS::Logs::LogGroup");
    assert!(!groups.is_empty());
    for g in groups {
        assert_eq!(g["Properties"]["RetentionInDays"].as_u64(), Some(14));
    }
}

#[test]
fn no_forbidden_resources() {
    let (text, t) = template();
    let forbidden_prefixes = [
        "AWS::EC2::", // VPC, NAT Gateway, EIP, ...
        "AWS::CloudFront::",
        "AWS::WAF", // WAF and WAFv2
        "AWS::SecretsManager::",
        "AWS::KMS::", // customer-managed keys
        "AWS::XRay::",
        "AWS::CloudWatch::",    // dashboards, custom-metric alarms
        "AWS::ApiGateway::",    // REST API (v1)
        "AWS::Serverless::Api", // SAM REST API
        "AWS::ElasticLoadBalancingV2::",
    ];
    for (name, r) in resources(&t) {
        let ty = r["Type"].as_str().unwrap();
        assert!(
            !forbidden_prefixes.iter().any(|p| ty.starts_with(p)),
            "forbidden resource {name}: {ty}"
        );
        if ty == "AWS::Lambda::Function" || ty == "AWS::Serverless::Function" {
            assert!(r["Properties"].get("VpcConfig").is_none());
        }
    }
    if let Some(g) = t.get("Globals") {
        let f = &g["Function"];
        assert!(f.get("VpcConfig").is_none() && f.get("ProvisionedConcurrencyConfig").is_none());
        assert_ne!(f["Tracing"].as_str(), Some("Active"));
        assert_ne!(g["HttpApi"]["Tracing"].as_str(), Some("Active"));
    }
    let lower = text.to_lowercase();
    for needle in [
        "secretsmanager",
        "provisionedconcurrency",
        "vpcconfig",
        "tracing: active",
        "natgateway",
    ] {
        assert!(!lower.contains(needle), "template mentions {needle}");
    }
}

#[test]
fn no_secrets_in_template() {
    let (text, t) = template();
    let env =
        &of_type(&t, "AWS::Serverless::Function")[0]["Properties"]["Environment"]["Variables"];
    for secret in ["MONGODB_URI", "ADMIN_API_KEY_HASH", "SIGNING_KEY"] {
        assert!(
            env.get(secret).is_none(),
            "{secret} must come from SSM, not the template"
        );
        assert!(env.get(format!("{secret}_SSM_PARAM")).is_some());
    }
    assert!(!text.contains("PRIVATE KEY"));
    assert!(!text.contains("mongodb+srv://"));
}
