# AWS Security Tools

## Welcome

This repository contains a script to validate common AWS Security tools, like, GuardDuty, AWS Config and Security Hub.

It will validate if those services are configured using a common best practice inside an AWS Organization.

It will do a lot of validations in all accounts from your organization, so please be patience!

It performs **ONLY** read-only actions, it will not add, change or configure anything.

For now it validates only the following services:
* AWS Config
* Amazon GuardDuty
* AWS Security Hub


## Pre-requisites

* [Python 3](https://www.python.org/downloads/)


## Usage

1. Clone this repository
1. Create python virtual environment
1. Install requirement packages

```shell
git clone https://github.com/lazize/aws-security-tools.git
cd aws-security-tools
python3 -m venv .env
source .env/bin/activate
pip install -r requirements.txt
```

```shell
$ ./validate-security-services.py --help
usage: validate-security-services.py [-h] --regions [REGIONS ...] --role-to-assume ROLE_TO_ASSUME [--role-external-id ROLE_EXTERNAL_ID] --organization-account ORGANIZATION_ACCOUNT
                                     [--organization-role-to-assume ORGANIZATION_ROLE_TO_ASSUME] [--organization-role-external-id ORGANIZATION_ROLE_EXTERNAL_ID] --administrator-account
                                     ADMINISTRATOR_ACCOUNT [--administrator-role-to-assume ADMINISTRATOR_ROLE_TO_ASSUME] [--administrator-role-external-id ADMINISTRATOR_ROLE_EXTERNAL_ID]
                                     --administrator-aggregator-region ADMINISTRATOR_AGGREGATOR_REGION

Validate security services for all account using standard/recommended configurations.

optional arguments:
  -h, --help            show this help message and exit
  --regions [REGIONS ...]
                        Regions to validate. If not informed will validate ALL regions available to services.
  --role-to-assume ROLE_TO_ASSUME
                        Role to assume on each account
  --role-external-id ROLE_EXTERNAL_ID
                        Role External ID to use when assume role. Can only be used together with 'role-to-assume'

Organization:
  Organization account.

  --organization-account ORGANIZATION_ACCOUNT
                        Organization account number
  --organization-role-to-assume ORGANIZATION_ROLE_TO_ASSUME
                        Role to assume at Organization account
  --organization-role-external-id ORGANIZATION_ROLE_EXTERNAL_ID
                        External ID used to assume role at Organization account. Can only be used together with 'organization-role-to-assume'

Administrator:
  Delegated administrator account for organization.

  --administrator-account ADMINISTRATOR_ACCOUNT
                        Delegated administrator account number.
  --administrator-role-to-assume ADMINISTRATOR_ROLE_TO_ASSUME
                        Role to assume at administrator account
  --administrator-role-external-id ADMINISTRATOR_ROLE_EXTERNAL_ID
                        External ID used to assume role at administrator account. Can only be used together with 'administrator-role-to-assume'
  --administrator-aggregator-region ADMINISTRATOR_AGGREGATOR_REGION
                        Region where security services will aggregate information
```

Preferably you should execute it from delegated security account, the one where you will have all your security services delegated inside your Organization. Also know as **administrator** account.

When you execute with credentials from **administrator** account, you don't need to inform `--administrator-role-to-assume` parameter.

```shell
$ ./validate-security-services.py --regions sa-east-1 --role-to-assume FromAdminAccount \
                                  --organization-account 123412341234 --organization-role-to-assume FromAdminAccount \
                                  --administrator-account 123456789012 --administrator-aggregator-region sa-east-1
```

If you don't see any output it means everything is configured as a common best practice.

Any output from this script means it is a deviation from a common best practice.

```shell
$ ./validate-security-services.py --regions sa-east-1 --role-to-assume FromAdminAccount \
                                  --organization-account 123412341234 --organization-role-to-assume FromAdminAccount \
                                  --administrator-account 123456789012 --administrator-aggregator-region sa-east-1
123456789012 sa-east-1 - [GuardDuty] Organization Auto-Enable is "False"
123456789012 sa-east-1 - [GuardDuty] S3Logs Auto-Enable is "False"
123456789012 sa-east-1 - [SecurityHub] Accounts Auto-Enable is "False"
```


## Security

See [CONTRIBUTING](CONTRIBUTING.md) for more information.


## License

This library is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file.


## Disclaimer

The opinions expressed in this repository are my own and not necessarily those of my employer (past, present and future).