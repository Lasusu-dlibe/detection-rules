# Đối chiếu custom rule với repo Elastic

Tài liệu này lưu phân tích lịch sử giữa custom rule và snapshot rule Elastic. Gói import chính thức hiện tại là `custom-rules-active.ndjson`; các bản export và gói theo phiên bản cũ đã được loại bỏ.

Ba rule EC2 Windows Password Retrieval, SES Enumeration và S3 Lifecycle Expiration được giữ trong phần phân tích bên dưới để giải thích quyết định retired, nhưng không còn nằm trong bộ 13 rule active. Không thấy rule tương đương trong snapshot local cũng không chứng minh rằng sản phẩm Elastic hiện tại không có coverage.

## AWS EC2 Instance Unusual Cloud Enumeration Activity

- Rule ID: `cd813d4e-e2e1-432a-b379-2ea94e2ad0af`
- Đối chiếu: Không thấy query tương đương trực tiếp trong rules/ ở snapshot này.
- Nhận xét: GetAccountAuthorizationDetails + ARN *i-* chỉ là heuristic; cần xác minh session EC2, dataset/provider và hành vi enumeration rộng hơn.

```kql
event.action: "GetAccountAuthorizationDetails" and aws.cloudtrail.user_identity.arn: *i-*
```

## AWS EC2 Security Group Opened SSH Port 22 to the Internet

- Rule ID: `ea58a65a-448c-4d70-ab59-245a4f4ff8e7`
- Đối chiếu: defense_evasion_vpc_security_group_ingress_rule_added_for_remote_connections.toml
- Nhận xét: Elastic dùng field nested ipPermissions.items..., hỗ trợ IPv6 ::/0 và nhiều cổng. Custom chỉ cổng 22, IPv4; cần xác minh mapping, port range và protocol.

```kql
data_stream.dataset: "aws.cloudtrail"
  and event.provider: "ec2.amazonaws.com"
  and event.action: "AuthorizeSecurityGroupIngress"
  and event.outcome: "success"
  and (aws.cloudtrail.request_parameters: "*0.0.0.0/0*" or aws.cloudtrail.flattened.request_parameters.cidrIp: "0.0.0.0/0")
  and (aws.cloudtrail.request_parameters: "*fromPort=22*" or aws.cloudtrail.flattened.request_parameters.fromPort: 22)
```

Elastic type: `query`

```kuery
data_stream.dataset: "aws.cloudtrail"
    and event.provider: ec2.amazonaws.com
    and event.action: AuthorizeSecurityGroupIngress
    and event.outcome: success
    and aws.cloudtrail.flattened.request_parameters.ipPermissions.items.ipRanges.items.cidrIp: ("0.0.0.0/0" or "::/0")
    and aws.cloudtrail.flattened.request_parameters.ipPermissions.items.fromPort: (
        21 or 22 or 23 or 445 or 3389 or 5985 or 5986)

```

## AWS S3 CloudTrail Log Impairment via Lifecycle Rule

- Rule ID: `2d7d513e-83c6-46b7-b733-d638385956f1`
- Đối chiếu: defense_evasion_s3_bucket_lifecycle_expiration_added.toml
- Nhận xét: Elastic kiểm tra Expiration=, không dựa vào tên ctlr. Cả hai chưa tự chứng minh bucket chứa CloudTrail log; cần inventory để xác định target và thời gian expiration.

```kql
event.action: "PutBucketLifecycle"
  and event.outcome: "success"
  and (aws.cloudtrail.resources.arn: *ctlr* or aws.cloudtrail.request_parameters: "*ctlr*")
```

Elastic type: `eql`

```eql
info where data_stream.dataset == "aws.cloudtrail"
   and event.action == "PutBucketLifecycle"
   and event.outcome == "success"
   and stringContains(aws.cloudtrail.request_parameters, "Expiration=")

```

## AWS Lambda Function Code Modification or Overwrite

- Rule ID: `4e66773c-e953-435d-9ca0-f88792a65d94`
- Đối chiếu: Không thấy rule standalone tương đương trực tiếp; lateral_movement_k8_assumed_web_identity_session_with_multi_phase_api_use.toml có UpdateFunctionCode trong chuỗi hành vi.
- Nhận xét: Custom bắt mọi cập nhật code thành công; deployment hợp lệ cũng khớp. Không coi rule chuỗi Kubernetes là thay thế tương đương.

```kql
data_stream.dataset: "aws.cloudtrail"
  and event.provider: "lambda.amazonaws.com"
  and event.action: ("UpdateFunctionCode20150331v2" or "UpdateFunctionCode")
  and event.outcome: "success"
```

## AWS EC2 Windows Password Data Retrieval Attempt

- Rule ID: `4ef54dda-3af6-4859-b7aa-ec331e78373a`
- Đối chiếu: credential_access_aws_getpassword_for_ec2_instance.toml
- Nhận xét: Elastic dùng AssumedRole + Client.UnauthorizedOperation + new_terms theo issuer ARN, lịch sử 7 ngày. Custom rộng hơn, gồm thành công và các actor khác.

```kql
data_stream.dataset: "aws.cloudtrail" and event.provider: "ec2.amazonaws.com" and event.action: "GetPasswordData" and not aws.cloudtrail.user_identity.type: "AWSService"
```

Elastic type: `new_terms`

```kuery
data_stream.dataset:"aws.cloudtrail"
    and event.provider:"ec2.amazonaws.com" and event.action:"GetPasswordData"
    and aws.cloudtrail.user_identity.type:"AssumedRole" and aws.cloudtrail.error_code:"Client.UnauthorizedOperation"

```

## Suspended or Unauthorized EC2 High-Compute GPU Instances Launch

- Rule ID: `8669a2b1-e9ba-4638-8567-301ab752bc75`
- Đối chiếu: Không thấy query RunInstances/GPU tương đương trực tiếp trong rules/ ở snapshot này.
- Nhận xét: OR UnauthorizedOperation bắt cả non-GPU bị từ chối; danh sách instance chưa đầy đủ. Cần nhóm điều kiện theo mục tiêu rõ.

```kql
data_stream.dataset: "aws.cloudtrail"
  and event.provider: "ec2.amazonaws.com"
  and event.action: "RunInstances"
  and (
    aws.cloudtrail.request_parameters: "*p2.xlarge*"
    or aws.cloudtrail.request_parameters: "*g4dn*"
    or aws.cloudtrail.request_parameters: "*p3.*"
    or aws.cloudtrail.error_code: "Client.UnauthorizedOperation"

  )
```

## AWS SES Account and Identity Enumeration

- Rule ID: `316192c1-51eb-43a2-b4d3-0fdfd6c7085c`
- Đối chiếu: Không thấy query SES tương đương trực tiếp trong rules/ ở snapshot này.
- Nhận xét: Custom bắt cả thao tác kiểm kê hợp lệ. Cần xác minh API/provider thực tế và ngữ cảnh, tần suất hoặc chuỗi hành vi.

```kql
data_stream.dataset: "aws.cloudtrail"
  and event.provider: "ses.amazonaws.com"
  and event.action: (
    "GetAccountSendingEnabled" or
    "GetSendQuota" or
    "ListIdentities" or
    "GetIdentityVerificationAttributes"
  )
```

## Suspended or Denied EC2 User Data Enumeration Attempts

- Rule ID: `c00cc919-ae31-48c8-8df0-495e480eb074`
- Đối chiếu: discovery_ec2_userdata_request_for_ec2_instance.toml
- Nhận xét: Elastic bắt success, loại một số service và dùng new_terms account/user/instance, lịch sử 5 ngày. Custom bắt failure: phạm vi bổ sung, không hoàn toàn tương đương.

```kql
data_stream.dataset: "aws.cloudtrail"
  and event.provider: "ec2.amazonaws.com"
  and event.action: "DescribeInstanceAttribute"
  and event.outcome: "failure"
  and aws.cloudtrail.flattened.request_parameters.attribute: "userData"
```

Elastic type: `new_terms`

```kuery
data_stream.dataset: "aws.cloudtrail"
    and event.provider: "ec2.amazonaws.com"
    and event.action: "DescribeInstanceAttribute"
    and event.outcome: "success"
    and aws.cloudtrail.flattened.request_parameters.attribute: "userData"
    and not aws.cloudtrail.user_identity.invoked_by: (
        "AWS Internal" or
        "cloudformation.amazonaws.com" or
        "aidevops.amazonaws.com" or
        "elasticmapreduce.amazonaws.com" or
        "aiops.amazonaws.com"
    )

```

## AWS Systems Manager (SSM) SendCommand Execution

- Rule ID: `effc1726-adb6-475b-93ec-a0252381e1ac`
- Đối chiếu: execution_ssm_sendcommand_by_rare_user.toml
- Nhận xét: Elastic thêm loại trừ service source và new_terms account/user, lịch sử 7 ngày. Custom bắt mọi SendCommand thành công, gồm bảo trì hợp lệ.

```kql
data_stream.dataset: "aws.cloudtrail" and event.provider: "ssm.amazonaws.com" and event.action: "SendCommand" and event.outcome: "success"
```

Elastic type: `new_terms`

```kuery
data_stream.dataset: "aws.cloudtrail"
    and event.provider: "ssm.amazonaws.com"
    and event.action: "SendCommand"
    and event.outcome: "success"
    and not source.address: (
      "ssm-guiconnect.amazonaws.com" or
      "ssm.amazonaws.com" or
      "inspector2.amazonaws.com"
    )

```

## Các bước học cấu trúc rule

Đọc metadata; description (giả thuyết detection); type/language/query; index; interval/from; risk_score/severity; threat MITRE; note (triage, false positive, response); và new_terms nếu có. Với new_terms, kiểm thử phải kiểm soát lịch sử; không chỉ so sánh query.

Trước khi tuning, xác minh field từ event đã ingest và mapping. Giữ rule_id để theo dõi cùng rule qua các phiên bản. Dùng cả attack và benign để đánh giá; không mặc định rule Elastic đúng cho mọi môi trường.
