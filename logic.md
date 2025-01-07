1. regions = get_all_regions V
2. for each region: get sqs queue policies region  -> get_sqs_policies(region) 
3. filter only "problematic" queue policies -> is_other_account_has_access_or_whatever(sqs_policy, my_own_account_id) -> bool
4. log_all_problematic_queues_to_log_txt -> log_queues_to_file(sqs_policy[], path) 
5. upload_to_s3(path) 
if not log_mode: 
6. for all probmatic queue policies: 
    6.1 get_fixed_policy(SqsPolicy, account_id) -> SqsPolicy // better if immutable (not changing in place, but creating new object) 
    6.2 apply_policy(SqsPolicy policy) // 

@dataclass
class SqsPolicy:
    policy: dict/str
    queue_url: str
    region: str


    