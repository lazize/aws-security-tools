#!/usr/bin/env python3

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# For LICENSE information, plese check the source repository:
# https://github.com/lazize/aws-security-tools

import boto3
import sys
import argparse
import re

from botocore.exceptions import ClientError
from dataclasses import dataclass
from typing import Any, Dict, List, NoReturn, Tuple

@dataclass
class Account:
    id: str
    alias: str
    role_to_assume: str
    role_external_id: str

    is_administrator: bool

def assume_role(account: str, role_to_assume: str, role_external_id: str = None) -> boto3.Session:
    # Beginning the assume role process for account
    sts_client = boto3.client('sts')

    # Get the current partition
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]

    if role_external_id:
        response = sts_client.assume_role(
            RoleArn=f'arn:aws:iam::{account}:role/{role_to_assume}',
            RoleSessionName='ValidateSecurityServices',
            DurationSeconds=900,
            ExternalId=role_external_id
        )
    else:
        response = sts_client.assume_role(
            RoleArn=f'arn:aws:iam::{account}:role/{role_to_assume}',
            RoleSessionName='ValidateSecurityServices',
            DurationSeconds=900
        )

    # Storing STS credentials
    session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )
    return session

def get_bucket_location(session: boto3.Session, region: str, bucket_name:str) -> str:
    s3 = session.client('s3', region_name=region)
    buckets = s3.list_buckets()
    for name, _ in buckets['Buckets']:
        if name == bucket_name:
            location = s3.get_bucket_location(Bucket=bucket_name)
            return location['LocationConstraint']
    return None

def exists_role_by_path_prefix(session: boto3.Session, path_prefix: str, role_name: str) -> bool:
    iam = session.client('iam')
    paginator = iam.get_paginator('list_roles')
    response_iterator = paginator.paginate(PathPrefix=path_prefix)
    for page in response_iterator:
        for role in page['Roles']:
            if role['RoleName'] == role_name:
                return True
    return False

def check_config(session: boto3.Session, account: str, region: str, is_administrator_account: bool = False) -> NoReturn:
    try:
        config = session.client('config', region_name=region)
        
        default_role_arn = f'arn:aws:iam::{account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig'
        default_bucket_name = f'config-bucket-{account}'
        
        recorders = config.describe_configuration_recorders()
        if not recorders['ConfigurationRecorders']:
            print(f'{account} {region} - [Config] Configuration recorder not found')
        else:
            # Check if default bucket name exists
            bucket_location = get_bucket_location(session, region, default_bucket_name)
            if bucket_location:
                default_bucket_exists = True
            else:
                default_bucket_exists = False
            
            # Recorder
            recorder = recorders['ConfigurationRecorders'][0]
            if recorder['name'] != 'default':
                print(f'{account} {region} - [Config] Recorder name is not "default"')
            if recorder['roleARN'] != default_role_arn:
                print(f'{account} {region} - [Config] Recorder role is not standard one, using {recorder["roleARN"]}')
            if not recorder['recordingGroup']['allSupported']:
                print(f'{account} {region} - [Config] Record all resources supported in this region is "False"')
            if not recorder['recordingGroup']['includeGlobalResourceTypes']:
                print(f'{account} {region} - [Config] Include global resources (e.g., AWS IAM resources) is "False"')

            # Recorder status
            config_recorder_status = config.describe_configuration_recorder_status()
            if not config_recorder_status['ConfigurationRecordersStatus']:
                print(f'{account} {region} - [Config] Configuration recorder status not found')
            else:
                recorder_status = config_recorder_status['ConfigurationRecordersStatus'][0]
                if recorder_status['name'] != 'default':
                    print(f'{account} {region} - [Config] Recorder status name is not "default"')
                if not recorder_status['recording']:
                    print(f'{account} {region} - [Config] Recording is "False"')
                if recorder_status['lastStatus'] != 'SUCCESS':
                    print(f'{account} {region} - [Config] Recorder last status is "{recorder_status["lastStatus"]}"')

            # Delivery channel
            delivery_channels = config.describe_delivery_channels()
            if not delivery_channels['DeliveryChannels']:
                print(f'{account} {region} - [Config] Delivery channel not found')
            else:
                delivery_channel = delivery_channels['DeliveryChannels'][0]
                if delivery_channel['name'] != 'default':
                    print(f'{account} {region} - [Config] Delivery channel name is not "default"')
                if delivery_channel['s3BucketName'] != default_bucket_name:
                    print(f'{account} {region} - [Config] Delivery channel bucket name is "{delivery_channel["s3BucketName"]}"')
                    if default_bucket_exists:
                        print(f'{account} {region} - [Config] Delivery channel default bucket name "{default_bucket_name}" exists')
                    else:
                        print(f'{account} {region} - [Config] Delivery channel default bucket name "{default_bucket_name}" not found')
            
            # Delivery channel status
            config_delivery_channel_status = config.describe_delivery_channel_status()
            if not config_delivery_channel_status['DeliveryChannelsStatus']:
                print(f'{account} {region} - [Config] Delivery channel status not found')
            else:
                delivery_channel_status = config_delivery_channel_status['DeliveryChannelsStatus'][0]
                if delivery_channel_status['name'] != 'default':
                    print(f'{account} {region} - [Config] Delivery channel status name is not "default"')
                if delivery_channel_status['configHistoryDeliveryInfo']['lastStatus'] != 'SUCCESS':
                    print(f'{account} {region} - [Config] History delivery info last status is "{recorder_status["lastStatus"]}"')
            
            # Aggregator
            if is_administrator_account:
                aggregator_name = None
                configuration_aggregators = config.describe_configuration_aggregators()
                for configuration_aggregator in configuration_aggregators['ConfigurationAggregators']:
                    if configuration_aggregator['OrganizationAggregationSource']['AllAwsRegions']:
                        aggregator_name = configuration_aggregator['ConfigurationAggregatorName']
                if not aggregator_name:
                    print(f'{account} {region} - [Config] Aggregator to all AWS regions not found')
                else:
                    found_aggregated_source_status = None
                    
                    paginator = config.get_paginator('describe_configuration_aggregator_sources_status')
                    response_iterator = paginator.paginate(ConfigurationAggregatorName=aggregator_name)
                    for page in response_iterator:
                        for aggregated_source_status in page['AggregatedSourceStatusList']:
                            if aggregated_source_status['SourceType'] == 'ORGANIZATION' and aggregated_source_status['AwsRegion'] == region:
                                found_aggregated_source_status = aggregated_source_status
                                break
                    if not found_aggregated_source_status:
                        print(f'{account} {region} - [Config] Aggregator to "ORGANIZATION" in "{region}" region not found')
                    else:
                        if found_aggregated_source_status['LastUpdateStatus'] != 'SUCCEEDED':
                            print(f'{account} {region} - [Config] Aggregator status is "{found_aggregated_source_status["LastUpdateStatus"]}". {found_aggregated_source_status["LastErrorCode"]}: {found_aggregated_source_status["LastErrorMessage"]}')
    except Exception as e:
        print(f'{account} {region} - [Config] {e}')
        raise

def check_guardduty(session: boto3.Session, account: str, region: str, administrator_account: str, org_accounts: List[Account]) -> NoReturn:
    try:
        default_role_arn = f'arn:aws:iam::{account}:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty'
        
        guardduty = session.client('guardduty', region_name=region)

        detectors = guardduty.list_detectors()
        if not detectors['DetectorIds']:
            print(f'{account} {region} - [GuardDuty] Detector not found')
        else:
            detector_id = detectors['DetectorIds'][0]
            
            detector = guardduty.get_detector(DetectorId=detector_id)
            if detector['Status'] != 'ENABLED':
                print(f'{account} {region} - [GuardDuty] Detector status is "{detector["Status"]}"')
            if detector['FindingPublishingFrequency'] != 'SIX_HOURS':
                print(f'{account} {region} - [GuardDuty] Detector finding publishing frequency is "{detector["FindingPublishingFrequency"]}"')
            if detector['ServiceRole'] != default_role_arn:
                print(f'{account} {region} - [GuardDuty] Detector role is not standard one, using {detector["ServiceRole"]}')
            
            if detector['DataSources']['CloudTrail']['Status'] != 'ENABLED':
                print(f'{account} {region} - [GuardDuty] Detector data source for CloudTrail is "{detector["DataSources"]["CloudTrail"]["Status"]}"')
            if detector['DataSources']['DNSLogs']['Status'] != 'ENABLED':
                print(f'{account} {region} - [GuardDuty] Detector data source for DNSLogs is "{detector["DataSources"]["DNSLogs"]["Status"]}"')
            if detector['DataSources']['FlowLogs']['Status'] != 'ENABLED':
                print(f'{account} {region} - [GuardDuty] Detector data source for FlowLogs is "{detector["DataSources"]["FlowLogs"]["Status"]}"')
            if detector['DataSources']['S3Logs']['Status'] != 'ENABLED':
                print(f'{account} {region} - [GuardDuty] Detector data source for S3Logs is "{detector["DataSources"]["S3Logs"]["Status"]}"')

            if account != administrator_account:
                # Member account
                master = guardduty.get_master_account(DetectorId=detector_id)
                if 'Master' in master:
                    if master['Master']['RelationshipStatus'] != 'Enabled':
                        print(f'{account} {region} - [GuardDuty] Master relationship status "{master["Master"]["RelationshipStatus"]}"')
                    if master['Master']['AccountId'] != administrator_account:
                        print(f'{account} {region} - [GuardDuty] Master account "{master["Master"]["AccountId"]}" is different from "{administrator_account}"')
                else:
                    # Not a member of any master, delegated is not set
                    print(f'{account} {region} - [GuardDuty] Master not found, delegated administrator not set')
            else:
                # Admin account
                organization_configuration = guardduty.describe_organization_configuration(DetectorId=detector_id)
                if not organization_configuration['AutoEnable']:
                    print(f'{account} {region} - [GuardDuty] Organization Auto-Enable is "False"')
                if organization_configuration['MemberAccountLimitReached']:
                    print(f'{account} {region} - [GuardDuty] Member account limit reached "False"')
                if not organization_configuration['DataSources']['S3Logs']['AutoEnable']:
                    print(f'{account} {region} - [GuardDuty] S3Logs Auto-Enable is "False"')

                members_not_enabled: Dict[str, str] = {}
                all_members: List[str] = []

                paginator = guardduty.get_paginator('list_members')
                response_iterator = paginator.paginate(DetectorId=detector_id)
                for members in response_iterator:
                    for member in members['Members']:
                        all_members.append(member['AccountId'])
                        if member['RelationshipStatus'] != 'Enabled':
                            members_not_enabled[member['AccountId']] = member['RelationshipStatus']
                    
                if members_not_enabled:
                    for member_account_id, member_status in sorted(members_not_enabled):
                        print(f'{account} {region} - [GuardDuty] Member "{member_account_id}" relationship status is "{member_status}"')
                
                for org_account in org_accounts:
                    if not org_account.is_administrator:
                        if org_account.id not in all_members:
                            print(f'{account} {region} - [GuardDuty] Organization account "{org_account.id}" is not a member of admin')
    except Exception as e:
        print(f'{account} {region} - [GuardDuty] {e}')

def check_securityhub(session: boto3.Session, account: str, region: str, finding_aggregation_region: str, administrator_account: str, org_accounts: List[Account], standards_enabled_by_default: List[Tuple[str, str]]) -> NoReturn:
    try:
        securityhub = session.client('securityhub', region_name=region)

        try:
            hub = securityhub.describe_hub()
        except ClientError as e:
            if 'is not subscribed to AWS Security Hub'.lower() in e.response['Error']['Message'].lower():
                print(f'{account} {region} - [SecurityHub] {e.response["Error"]["Message"]}')
            else:
                raise
        else:
            # It is subscribed to AWS Security Hub
            if not hub['AutoEnableControls']:
                print(f'{account} {region} - [SecurityHub] Auto-enable new controls for standards I have enabled is "False"')
            
            standards_subscriptions_dict: Dict[str, str] = {}
            standards_subscriptions = securityhub.get_enabled_standards()
            for standard_subscription in standards_subscriptions['StandardsSubscriptions']:
                standards_subscriptions_dict[standard_subscription['StandardsArn']] = standard_subscription['StandardsStatus']
            for standard_arn, standard_name in standards_enabled_by_default:
                if standard_arn not in standards_subscriptions_dict:
                    print(f'{account} {region} - [SecurityHub] Standards "{standard_name}" is not enable')
                else:
                    if standards_subscriptions_dict[standard_arn] != 'READY':
                        print(f'{account} {region} - [SecurityHub] Standards "{standard_name}" status is "{standards_subscriptions_dict[standard_arn]}"')

            products_for_import_enabled_by_default: List[str] = [
                f"arn:aws:securityhub:{region}:{account}:product-subscription/aws/access-analyzer",
                f"arn:aws:securityhub:{region}:{account}:product-subscription/aws/guardduty",
                f"arn:aws:securityhub:{region}:{account}:product-subscription/aws/firewall-manager",
                f"arn:aws:securityhub:{region}:{account}:product-subscription/aws/inspector",
                f"arn:aws:securityhub:{region}:{account}:product-subscription/aws/macie",
                f"arn:aws:securityhub:{region}:{account}:product-subscription/aws/ssm-patch-manager",
                f"arn:aws:securityhub:{region}:{account}:product-subscription/aws/securityhub"
            ]
            product_subscriptions: List[str] = []
            paginator = securityhub.get_paginator('list_enabled_products_for_import')
            response_iterator = paginator.paginate()
            for page in response_iterator:
                product_subscriptions.extend(page['ProductSubscriptions'])
            for product_for_import in products_for_import_enabled_by_default:
                if product_for_import not in product_subscriptions:
                    print(f'{account} {region} - [SecurityHub] Product for import "{product_for_import}" not enable')

            # Aggregator
            found = False
            finding_aggregators = securityhub.list_finding_aggregators()
            for finding_aggregator in finding_aggregators['FindingAggregators']:
                aggregator_arn = finding_aggregator['FindingAggregatorArn']
                aggregator = securityhub.get_finding_aggregator(FindingAggregatorArn=aggregator_arn)
                if aggregator['FindingAggregationRegion'] == finding_aggregation_region and aggregator['RegionLinkingMode'] == 'ALL_REGIONS':
                    found = True
                    break
            if not found:
                print(f'{account} {region} - [SecurityHub] Finding aggregator for "All Regions" in "{finding_aggregation_region}" not found')

            if account != administrator_account:
                # Member account
                admin_account = securityhub.get_administrator_account()
                if 'Administrator' in admin_account:
                    # Member account
                    if admin_account['Administrator']['MemberStatus'] != 'Enabled':
                        print(f'{account} {region} - [SecurityHub] Member status is "{admin_account["Administrator"]["MemberStatus"]}"')
                    if admin_account['Administrator']['AccountId'] != administrator_account:
                        print(f'{account} {region} - [SecurityHub] Administrator account "{admin_account["Administrator"]["AccountId"]}" is different from "{administrator_account}"')
                else:
                    # Not a member of any administator account, delegated is not set
                    print(f'{account} {region} - [SecurityHub] Administrator account not found, delegated administrator not set')
            else:
                # Admin account
                org_config = securityhub.describe_organization_configuration()
                if not org_config['AutoEnable']:
                    print(f'{account} {region} - [SecurityHub] Accounts Auto-Enable is "False"')
                if org_config['MemberAccountLimitReached']:
                    print(f'{account} {region} - [SecurityHub] Member account limit reached')

                members_not_enabled: Dict[str, str] = {}
                all_members: List[str] = []

                paginator = securityhub.get_paginator('list_members')
                response_iterator = paginator.paginate()
                for members in response_iterator:
                    for member in members['Members']:
                        all_members.append(member['AccountId'])
                        if member['MemberStatus'] != 'Enabled':
                            members_not_enabled[member['AccountId']] = member['MemberStatus']
                    
                if members_not_enabled:
                    for member_account_id, member_status in sorted(members_not_enabled):
                        print(f'{account} {region} - [SecurityHub] Member "{member_account_id}" status is "{member_status}"')

                for org_account in org_accounts:
                    if not org_account.is_administrator:
                        if org_account.id not in all_members:
                            print(f'{account} {region} - [GuardDuty] Organization account "{org_account.id}" is not a member of admin')
    except Exception as e:
        print(f'{account} {region} - [SecurityHub] {e}')

def check_organization(session: boto3.Session, account: str, administrator_account: str, is_administator_at_organization_account: bool) -> NoReturn:
    try:
        org = session.client('organizations')
        
        service_principals: List[str] = []
        services = org.list_aws_service_access_for_organization()
        for enabled_service_principal in services['EnabledServicePrincipals']:
            service_principals.append(enabled_service_principal['ServicePrincipal'])
        
        if not is_administator_at_organization_account:
            service_principals_to_check: List[str] = [
                'config.amazonaws.com',
                'config-multiaccountsetup.amazonaws.com',
                'guardduty.amazonaws.com',
                'securityhub.amazonaws.com'
            ]
        else:
            service_principals_to_check: List[str] = [
                'guardduty.amazonaws.com',
                'securityhub.amazonaws.com'
            ]

        for service_principal in service_principals_to_check:
            if service_principal not in service_principals:
                print(f'{account} - - [Organizations] Service principal "{service_principal}" not enabled')
            else:
                delegated_found = None
                delegated_administrators = org.list_delegated_administrators(ServicePrincipal=service_principal)
                for delegated_administrator in delegated_administrators['DelegatedAdministrators']:
                    if delegated_administrator['Id'] == administrator_account:
                        delegated_found = delegated_administrator
                        break
                if not delegated_found:
                    print(f'{account} - - [Organizations] Delegated administrator account "{administrator_account}" not found for service principal "{service_principal}"')
                else:
                    if delegated_found['Status'] != 'ACTIVE':
                        print(f'{account} - - [Organizations] Delegated administrator account "{administrator_account}" status is "{delegated_found["Status"]}"')
    except Exception as e:
        print(f'{account} - - [Organizations] {e}')

def validate(account: Account, regions: List[str], administrator_aggregator_region: str, administrator_account: str, org_accounts: List[Account], standards_enabled_by_default_per_region: Dict[str, List[Tuple[str, str]]]) -> NoReturn:
    if account.role_to_assume:
        session = assume_role(account.id, account.role_to_assume, account.role_external_id)
    else:
        session = boto3.session.Session()
    
    ### AWS Config
    for region in regions:
        check_config(session, account.id, region, account.is_administrator)

    # Check if Service-Linked role exists
    # As it is a global resource we just need to check once
    exists_service_linked_role = exists_role_by_path_prefix(session, '/aws-service-role/config.amazonaws.com/', 'AWSServiceRoleForConfig')
    if not exists_service_linked_role:
        print(f'{account} - - [Config] Default service-linked role "AWSServiceRoleForConfig" not found')

    ### GuardDuty
    for region in regions:
        check_guardduty(session, account.id, region, administrator_account, org_accounts)

    # Check if Service-Linked role exists
    # As it is a global resource we just need to check once
    exists_service_linked_role = exists_role_by_path_prefix(session, '/aws-service-role/guardduty.amazonaws.com/', 'AWSServiceRoleForAmazonGuardDuty')
    if not exists_service_linked_role:
        print(f'{account} - - [GuardDuty] Default service-linked role "AWSServiceRoleForAmazonGuardDuty" not found')

    ### Security Hub    
    for region in regions:
        check_securityhub(session, account.id, region, administrator_aggregator_region, administrator_account, org_accounts, standards_enabled_by_default_per_region[region])

    # Check if Service-Linked role exists
    # As it is a global resource we just need to check once
    exists_service_linked_role = exists_role_by_path_prefix(session, '/aws-service-role/securityhub.amazonaws.com/', 'AWSServiceRoleForSecurityHub')
    if not exists_service_linked_role:
        print(f'{account.id} - - [SecurityHub] Default service-linked role "AWSServiceRoleForSecurityHub" not found')

def main() -> NoReturn:
    try:
        sts_client = boto3.client('sts')
        current_account = sts_client.get_caller_identity()['Account']

        description = """Validate security services for all account using standard/recommended configurations."""

        parser = argparse.ArgumentParser(description=description)
        parser.add_argument("--regions", required=True, help="Regions to validate. If not informed will validate ALL regions available to services.", nargs="*")
        parser.add_argument("--role-to-assume", required=True, help="Role to assume on each account")
        parser.add_argument("--role-external-id", help="Role External ID to use when assume role. Can only be used together with 'role-to-assume'")

        group_organization = parser.add_argument_group("Organization", f"Organization account.")
        group_organization.add_argument("--organization-account", required=True, help="Organization account number")
        group_organization.add_argument("--organization-role-to-assume", help="Role to assume at Organization account")
        group_organization.add_argument("--organization-role-external-id", help="External ID used to assume role at Organization account. Can only be used together with 'organization-role-to-assume'")

        group_administrator = parser.add_argument_group("Administrator", f"Delegated administrator account for organization.")
        group_administrator.add_argument("--administrator-account", required=True, help="Delegated administrator account number.")
        group_administrator.add_argument("--administrator-role-to-assume", help="Role to assume at administrator account")
        group_administrator.add_argument("--administrator-role-external-id", help="External ID used to assume role at administrator account. Can only be used together with 'administrator-role-to-assume'")
        group_administrator.add_argument("--administrator-aggregator-region", required=True, help="Region where security services will aggregate information")

        args = parser.parse_args()
        if not args.regions:
            print("IMPORTANT: Parameter \"regions\" not informed. Will validate ALL regions supported by service.")

        if args.role_external_id and not args.role_to_assume:
            parser.error("Parameter \"role-external-id\" must be used together with \"role-to-assume\".")

        # Organization
        if not re.match(r'[0-9]{12}', args.organization_account):
            print(f'Parameter "organization-account" is invalid')
        if (current_account != args.organization_account) and not args.organization_role_to_assume:
            parser.error("Parameter \"organization-role-to-assume\" must be informed when not running or organization account.")
        if args.organization_role_external_id and not args.organization_role_to_assume:
            parser.error("Parameter \"organization-role-external-id\" must be used together with \"organization-role-to-assume\".")

        # Administrator
        if not re.match(r'[0-9]{12}', args.administrator_account):
            print(f'Parameter "administrator-account" is invalid')
        if (current_account != args.administrator_account) and not args.administrator_role_to_assume:
            parser.error("Parameter \"administrator-role-to-assume\" must be informed when not running on administrator account.")
        if args.administrator_role_external_id and not args.administrator_role_to_assume:
            parser.error("Parameter \"administrator-role-external-id\" must be used together with \"administrator-role-to-assume\".")

        # print("#####################################")
        # print(args)
        # print("#####################################")
        #return

        if args.organization_role_to_assume:
            session = assume_role(args.organization_account, args.organization_role_to_assume, args.organization_role_external_id)
        else:
            session = boto3.session.Session()
        
        accounts: List[Account] = []
        org = session.client('organizations')
        paginator = org.get_paginator('list_accounts')
        response_iterator = paginator.paginate()
        for page in response_iterator:
            for account in page['Accounts']:
                if account['Status'] != 'ACTIVE':
                    print(f'Account "{account["Id"]} - {account["Name"]}" status is {account["Status"]}, will ignore it')
                else:
                    account_id = account['Id']
                    account_name = account['Name']
                    if account_id == args.administrator_account:
                        # Administrator account
                        account_obj = Account(account_id, account_name, args.administrator_role_to_assume, args.administrator_role_external_id, True)
                    else:
                        # Member account
                        account_obj = Account(account_id, account_name, args.role_to_assume, args.role_external_id, False)

                    accounts.append(account_obj)

        # Security Hub Standards enabled by default per region
        session = boto3.session.Session()
        standards_enabled_by_default_per_region: Dict[str, List[Tuple[str, str]]] = {}
        for region in args.regions:
            standards_enabled_by_default: List[Tuple[str, str]] = []
            securityhub = session.client('securityhub', region_name=region)
            standards = securityhub.describe_standards()
            for standard in standards['Standards']:
                if standard['EnabledByDefault']:
                    standards_enabled_by_default.append((standard['StandardsArn'], standard['Name']))
            standards_enabled_by_default_per_region[region] = standards_enabled_by_default

        # Check Organizations
        is_administrator_at_organization_account = (args.administrator_account == args.organization_account)
        check_organization(session, args.organization_account, args.administrator_account, is_administrator_at_organization_account)

        for account in accounts:
            #print(account)
            validate(account, args.regions, args.administrator_aggregator_region, args.administrator_account, accounts, standards_enabled_by_default_per_region)
    except (KeyboardInterrupt):
        print()
        sys.exit(0)
    except:
        raise

if __name__ == '__main__':
    main()
