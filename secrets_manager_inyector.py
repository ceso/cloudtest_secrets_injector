#!/usr/bin/env python3

import base64
import boto3
import logging
import json
import os
from typing import Union


AWS_REGION = "us-east-1"

# logger config
logger = logging.getLogger()
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s: %(levelname)s: %(message)s"
)


def update_secret(secret_name: str, secret_plain_text: str) -> str:
    """
    Updates a secret in Secrets Manager
    """
    secretsmanager = boto3.client("secretsmanager", region_name=AWS_REGION)
    try:
        response = secretsmanager.put_secret_value(
            SecretId=secret_name, SecretString=secret_plain_text
        )

        logger.info(f"The secret has been updated!")
    except:
        logger.error(f"There was an error updating the secret {secret_name}")
        raise


def create_secret(secret_name: str, secret_plain_text: str, key_alias: str) -> str:
    """
    Creates a secret in Secrets Manager with a given KMS key
    """
    secretsmanager = boto3.client("secretsmanager", region_name=AWS_REGION)
    try:
        response = secretsmanager.create_secret(
            Name=secret_name, SecretString=secret_plain_text, KmsKeyId=key_alias
        )
        logger.info(f"The secret {secret_name} has been created!")
    except:
        logger.error("Could not upload the secret to secrets manager")


def get_secret_arn(secret_name: str) -> Union[str, bool]:
    """
    Obtains the ARN of a given secret on Secrets Manager
    """
    try:
        secretsmanager = boto3.client("secretsmanager", region_name=AWS_REGION)
        arn = secretsmanager.describe_secret(SecretId=secret_name)
        logger.info(f"ARN of secret {secret_name} is: {arn['ARN']}")
        return arn["ARN"]
    except secretsmanager.exceptions.ResourceNotFoundException:
        logger.error(f"The secret {secret_name} doesn't exist")
        return False


def decrypt_secret(secret_str: str, key_alias: str) -> str:
    """
    Decrypts a secret encrypted with KMS
    """
    try:
        kms = boto3.client("kms", region_name=AWS_REGION)
        plain_text = kms.decrypt(
            KeyId=key_alias, CiphertextBlob=(base64.b64decode(secret_str))
        )
    except:
        logger.exception("Could not decrypt the string.")
        raise
    else:
        return plain_text["Plaintext"]


def main(event, context):
    str_kms_encrypted = os.environ["STR_KMS_ENCRYPTED"]
    secret_name = os.environ["SECRET_NAME"]
    kms_key_alias = os.environ["KMS_KEY_ALIAS"]

    logger.info("Decrypting secret...")
    secret_plain_text = decrypt_secret(str_kms_encrypted, kms_key_alias).decode("utf-8")

    logger.info(f"Trying to obtain ARN of {secret_name} secret...")
    secret_arn = get_secret_arn(secret_name)

    if secret_arn == False:
        create_secret(secret_name, secret_plain_text, kms_key_alias)
    else:
        update_secret(secret_name, secret_plain_text)
