# Import custom rules

`custom-rules-active.ndjson` is the only supported Kibana import package in this directory. It contains 13 enabled custom rules with unique `rule_id` values: 10 query rules, two threshold rules and one EQL rule.

Import it in **Security → Rules → Detection rules → Import rules** and enable **Overwrite existing rules**. Overwrite is required so the latest IAM backdoor and SSM SendCommand logic replaces earlier versions that use the same `rule_id`.

The corresponding repository sources are the 13 TOML files under `rules/`. The NDJSON package and TOML sources must stay aligned by rule name and `rule_id`.

Three earlier rules were retired because native Elastic coverage or expected noise made the custom copy unnecessary:

- AWS EC2 Windows Password Data Retrieval Attempt
- AWS SES Account and Identity Enumeration
- AWS S3 Bucket One-Day Lifecycle Expiration Added

Do not enable Elastic's native `AWS SSM Session Started to EC2 Instance` together with the custom StartSession rule because both cover the same core API.

The SSM SecureString rule is a threshold rule: it requires five successful plural `GetParameters` calls with `withDecryption=true`, grouped by `user.id` and `source.ip`. Coverage should therefore be recorded as FULL-stateful when matching raw events and the threshold alert are both present.

Custom schema configuration remains in `_config.yaml`. Successful schema validation or import only proves structural validity; attack, benign and overlap tests are still required to assess detection quality.
