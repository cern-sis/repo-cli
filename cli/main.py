#!/usr/bin/env python

import base64
import logging
import os
import subprocess
import sys

import click
import yaml
from git_root import git_root


def run_kubeseal(secret_file, namespace):
    logging.info("Starting to seal the updated secrets...")
    current_dir = os.getcwd()
    parent_path = os.path.dirname(secret_file)
    with open("tmp", "r") as read, open(secret_file, "w") as write:
        os.chdir(parent_path)
        pem_file = git_root("utils/certs/sealedsecret/sis-prod.pem")
        try:
            subprocess.run(
                [
                    "kubeseal",
                    "--cert",
                    pem_file,
                    "-n",
                    namespace,
                    "-o",
                    "yaml",
                ],
                stdin=read,
                stdout=write,
                check=True,
            )
            logging.info("Secret Updated and Sealed!")
        except subprocess.CalledProcessError:
            logging.info("Error occured while sealing secrets. Please try again!")

    # Remove the tmp file
    logging.info("Removing the tmp file...")
    os.chdir(current_dir)
    os.remove("tmp")


def get_base64data(namespace, secret_name):
    logging.info(f"{namespace} secret from {secret_name} is being extracted...")
    with open("tmp", "w") as tmp:
        subprocess.run(
            ["kubectl", "-n", namespace, "get", "secret", secret_name, "-o", "yaml"],
            stdout=tmp,
        )

    logging.info("Extracting requested base64 encoded secret..")
    with open("tmp", "r") as tmp:
        base64_data = yaml.safe_load(tmp)

    return base64_data


def validate_key(base64_data, secret_key):
    if secret_key in base64_data:
        return True
    logging.error(f"Invalid Secret Name: {secret_key}. Please check again!")
    return False


def update_key(base64_data, key, new_value):
    logging.info(f"Updating secret {key}...")
    new_secret_value = base64.b64encode(bytes(new_value, "utf-8"))
    base64_data["data"][key] = new_secret_value.decode("utf-8")
    logging.info(f"Updated => {key}:{new_secret_value}")
    return


@click.group()
def secret_manager():
    pass


@click.command()
@click.argument("secret_file", type=click.Path(exists=True))
@click.option(
    "-d", "--data", "view_data", type=click.STRING, multiple=True, default=None
)
def view_secret(secret_file, view_data):
    """Command to view sealed secrets.

    :option: data - Option for viewing a secret actual value by providing secret name

    Example: python cli/main.py view-secret cap/environments/cap-qa/sealedsecrets/cap-creds.yml
    Example: python cli/main.py view-secret cap/environments/cap-qa/sealedsecrets/cap-creds.yml -d FLOWER_USER -d FLOWER_PASSWORD
    """
    logging.info(
        "Reading yml file...",
    )
    with open(secret_file, "r") as tmp:
        data = yaml.safe_load(tmp)
    if not data:
        logging.error("No data present. Please check your secret file!")
        sys.exit(1)

    namespace = data.get("metadata").get("namespace")
    secret_name = data.get("metadata").get("name")
    base64_data = get_base64data(namespace, secret_name)
    base64_data_keys = base64_data.get("data").keys()

    if view_data:
        base64_data_keys = [
            key for key in view_data if validate_key(base64_data_keys, key)
        ]

    for key in base64_data_keys:
        secret_value = base64.b64decode(base64_data.get("data").get(key)).decode(
            "utf-8"
        )
        click.echo(f"{key}:{secret_value}")


@click.command()
@click.argument("secret_file", type=click.Path(exists=True))
@click.option(
    "-d", "--data", "update_data", type=click.STRING, multiple=True, default=None
)
def update_secret(secret_file, update_data):
    """Command to update sealed secrets.

    Update the Sealed secret with new value.
    :option: data - Option for updating a secret actual value by providing secret name in key value pair

    Example: python cli/main.py update-secret cap/environments/cap-qa/sealedsecrets/cap-creds.yml -d FLOWER_USER:NEW_VAL -d FLOWER_PASSWORD:MY_VAL
    """
    logging.info(
        "Reading yml file...",
    )
    with open(secret_file, "r") as tmp:
        data = yaml.safe_load(tmp)
    if not data:
        logging.error("No data present. Please check your secret file!")
        sys.exit(1)

    namespace = data.get("metadata").get("namespace")
    secret_name = data.get("metadata").get("name")
    base64_data = get_base64data(namespace, secret_name)
    base64_data_keys = base64_data.get("data").keys()

    if not update_data:
        logging.error("Please provide keys to update!")
        sys.exit(1)

    requested_change = dict(secret.split(":", 1) for secret in update_data)
    for k, v in requested_change.items():
        if not validate_key(base64_data_keys, k):
            sys.exit(1)
        update_key(base64_data, k, v)

    # Keeping required metadata only
    base64_data["metadata"] = {"name": secret_name, "namespace": namespace}
    base64_data.pop("type", None)

    with open("tmp", "w") as tmp:
        yaml.dump(base64_data, tmp)

    run_kubeseal(secret_file, namespace)


secret_manager.add_command(view_secret)
secret_manager.add_command(update_secret)


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    secret_manager()