# Cloud Custodian Repo

## How it Works

[Cloud Custodian](https://cloudcustodian.io) is a rules engine for managing AWS resources at scale. You define the rules that your resources should follow, and Cloud Custodian automatically provisions event sources and AWS Lambda functions to enforce those rules. Instead of writing custom serverless workflows, you can manage resources across all of your accounts via simple YAML files.

Cloud Custodian documentation: [here](https://cloudcustodian.io/docs/quickstart/index.html#)

## Prerequisites

- Python 3.8
- [pip](https://pip.pypa.io/en/stable/)
- [Pipenv](https://github.com/pypa/pipenv)

## Installation

Install Cloud Custodian by cloning and running the commands from this example repository:

``` bash
$ git clone https://github.com/avishayil/cloud-custodian-example
$ pipenv install
$ pipenv shell
$ custodian -h
```

## Run the Tests
You can use the associated GitHub action as a pipeline example, or run the following command on your machine:
``` bash
$ tox
```

## Credits
- @zscholl for providing the base code for these unit tests: https://medium.com/zendesk-engineering/validating-cloud-custodian-on-aws-with-moto-203a30ee5505
