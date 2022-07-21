#!/usr/bin/env python3

import base64
from inspect import Parameter
from pydoc import describe
from typing_extensions import Required
from urllib import response
from zipfile import ZipFile
import boto3
import logging
import json
from typing import Union
import zipfile
import sys
import argparse

AWS_REGION = "us-east-1"

# logger config
logger = logging.getLogger()
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s: %(levelname)s: %(message)s"
)


def clean_poc(
    stack_name: str, s3_config_del: list[str, list[str, str]], secret_name: str
) -> None:
    try:
        cfn = boto3.client("cloudformation")
        clean_stack = cfn.delete_stack(StackName=stack_name)
        logger.info(f"Cloudformation stack deleted")
        s3 = boto3.client("s3")
        del_objects = s3.delete_objects(
            Bucket=s3_config_del[0],
            Delete={
                "Objects": [
                    {"Key": f"{s3_config_del[1]}-{s3_config_del[2][0]}"},
                    {"Key": f"{s3_config_del[1]}-{s3_config_del[2][1]}"},
                ]
            },
        )
        del_bucket = s3.delete_bucket(Bucket=s3_config_del[0])
        logger.info(f"S3 objects and bucket deleted")
        secretsmanager = boto3.client(f"secretsmanager")
        destroy_secret = secretsmanager.delete_secret(
            SecretId=secret_name, ForceDeleteWithoutRecovery=True
        )
        logger.info(f"Secret has been destroyed")
    except:
        logger.error(
            f"Error deleting the POC, please delete it manually!!!", exc_info=True
        )


def create_lambda_stack(
    lambda_script_basename: str,
    s3_config_params: list,
    stack_name: str,
    secret_name: str,
    encrypted_secret: str,
    kms_key: str,
) -> None:

    try:
        cfn = boto3.client("cloudformation")
        run_cfn = cfn.create_stack(
            StackName=stack_name,
            TemplateURL=f"https://{s3_config_params[0]}.s3.amazonaws.com/{s3_config_params[1]}-{s3_config_params[2]}",
            Parameters=[
                {
                    "ParameterKey": "S3Key",
                    "ParameterValue": f"{s3_config_params[1]}-{lambda_script_basename}",
                },
                {"ParameterKey": "SecretName", "ParameterValue": f"{secret_name}"},
                {
                    "ParameterKey": "SecretKMSEncrypted",
                    "ParameterValue": f"{encrypted_secret}",
                },
                {"ParameterKey": "KMSKey", "ParameterValue": f"{kms_key}"},
            ],
            Capabilities=["CAPABILITY_IAM"],
        )
    except cfn.exceptions.AlreadyExistsException:
        run_cfn = cfn.update_stack(
            StackName=stack_name,
            TemplateURL=f"https://{s3_config_params[0]}.s3.amazonaws.com/{s3_config_params[1]}-{s3_config_params[2]}",
            Parameters=[
                {
                    "ParameterKey": "S3Key",
                    "ParameterValue": f"{s3_config_params[1]}-{lambda_script_basename}",
                },
                {"ParameterKey": "SecretName", "ParameterValue": f"{secret_name}"},
                {
                    "ParameterKey": "SecretKMSEncrypted",
                    "ParameterValue": f"{encrypted_secret}",
                },
                {"ParameterKey": "KMSKey", "ParameterValue": f"{kms_key}"},
            ],
            Capabilities=["CAPABILITY_IAM"],
        )
    else:
        pass


def createS3_and_upload(
    bucket_name: str,
    to_upload: list,
    s3_key_object: str,
) -> None:
    try:
        s3 = boto3.client("s3")
        logger.info(f"Creating bucket {bucket_name}")
        create_bucket = s3.create_bucket(
            ACL="private",
            Bucket=bucket_name,
            # CreateBucketConfiguration={"LocationConstraint": AWS_REGION},
        )

        logger.info(f"Creating zip file of the lambda function...")

        with ZipFile(f"{to_upload[0]}", "w") as myzip:
            myzip.write(f"{to_upload[0].replace('.zip','.py')}")

        for object in to_upload:
            upload_file = s3.upload_file(
                object, bucket_name, f"{s3_key_object}-{object}"
            )

        logger.info(
            f"The bucket {bucket_name} and the {to_upload[0]} and {to_upload[1]} were uploaded"
        )
    except:
        logger.error(f"Some error ocurred", exc_info=True)


def encrypt(secret_str: str, key_alias: str) -> str:
    """
    Encrypts plaintext into ciphertext by using a KMS key.
    """
    try:
        kms_client = boto3.client("kms", region_name=AWS_REGION)
        cipher_text = kms_client.encrypt(
            KeyId=key_alias,
            Plaintext=bytes(secret_str, encoding="utf8"),
        )
    except:
        logger.exception("Could not encrypt the string.")
        raise
    else:
        return base64.b64encode(cipher_text["CiphertextBlob"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Creates or deletes the POC stack")
    parser.add_argument(
        choices=["create", "destroy"],
        type=str,
        help="Indicates if a POC stack will be created or destroyed",
        dest="action_to_run",
    )
    parser.add_argument(
        "--legacy-pass",
        type=str,
        help="Example of legacy pass to simulate poc",
        dest="plain_text",
    )
    parser.add_argument(
        "--secret-name",
        type=str,
        required=True,
        help="Name of the secret to be created/destroyed in secrets manager",
        dest="secret_name",
    )

    args = parser.parse_args()

    stack_name = "dummypoc"
    lambda_script_basename = "secrets_manager_inyector.zip"
    template_cfn = "deploy_lambda.yml"
    s3bucket = "dummypoc"
    s3_key_object = "justapoc"
    key_alias = "alias/dummy-key"
    secret_name = args.secret_name
    plain_text = args.plain_text

    if args.action_to_run == "destroy":
        logger.info("Cleaning stack from POC...")
        clean_poc(
            stack_name,
            [s3bucket, s3_key_object, [lambda_script_basename, template_cfn]],
            secret_name,
        )
        logger.info("Stack from POC has been deleted!")
        sys.exit(0)
    elif args.action_to_run == "create" and plain_text:
        logger.info(
            f"The legacy password that will be used for this example is: {plain_text}"
        )
        logger.info(f"Encrypting password with KMS...")
        cipher_blob = encrypt(plain_text, key_alias).decode("utf-8")
        logger.info(
            f"The password encrypted with kms is (this will work as an example of a pass from a legacy system): {cipher_blob}"
        )
        logger.info(f"Creating S3 bucket for poc...")
        createS3_and_upload(
            s3bucket, [lambda_script_basename, template_cfn], s3_key_object
        )
        logger.info(f"Creating lambda stack with cloudformation...")
        create_lambda_stack(
            lambda_script_basename,
            [s3bucket, s3_key_object, template_cfn],
            stack_name,
            secret_name,
            cipher_blob,
            key_alias,
        )
        logger.info(f"Stack created...")
        logger.info(
            f"All set, please verify your s3, Cloudformation, go to lambda and test it!"
        )
    else:
        logger.error(f"When creating POC a legacy pass is required!", exc_info=True)
