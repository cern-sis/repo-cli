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


def get_realdata(base64_data, filename):
    base64_data_keys = base64_data.get("data", {}).keys()
    logging.info(f"Decoding base64 data...")
    for k in base64_data_keys:
        base64_data_value = base64_data.get("data", {}).get(k)
        base64_data["data"][k] = base64.b64decode(base64_data_value).decode("utf-8")

    with open(filename, "w") as tmp_real:
        yaml.dump(base64_data, tmp_real)

    logging.info(f"Decoded base64 data in tmp_real.")


def get_encoded_base64data(filename):
    with open(filename, "r") as tmp:
        real_updated_data = yaml.safe_load(tmp)

    data_keys = real_updated_data.get("data", {}).keys()
    logging.info("Encoding secrets to base64...")
    for k in data_keys:
        real_value = real_updated_data.get("data", {}).get(k)
        real_updated_data["data"][k] = base64.b64encode(bytes(real_value, "utf-8"))

    logging.info("Encoded secrets to base64...")
    return real_updated_data


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


def extract_data_from_file(secret_file):
    logging.info("Reading yml file...")
    with open(secret_file, "r") as tmp:
        data = yaml.safe_load(tmp)
    if not data:
        logging.error("No data present. Please check your secret file!")
        sys.exit(1)
    namespace = data.get("metadata", {}).get("namespace")
    secret_name = data.get("metadata", {}).get("name")
    if not namespace:
        logging.error("Namespace not present. Please check the yml file.")
        sys.exit(1)
    if not secret_name:
        logging.error("Secret name not present. Please check the yml file.")
        sys.exit(1)
    base64_data = get_base64data(namespace, secret_name)
    base64_data_keys = base64_data.get("data").keys()
    return namespace, secret_name, base64_data, base64_data_keys


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
    _, _, base64_data, base64_data_keys = extract_data_from_file(secret_file)

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
    namespace, secret_name, base64_data, base64_data_keys = extract_data_from_file(
        secret_file
    )

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


@click.command()
@click.argument("secret_file", type=click.Path(exists=True))
@click.option(
    "-d", "--data", "add_data", type=click.STRING, multiple=True, default=None
)
def add_secret(secret_file, add_data):
    """Command to add new keys to sealed secrets.

    :option: data - Option for adding a new secret value by providing secret name in key value pair

    Example: python cli/main.py add-secret cap/environments/cap-qa/sealedsecrets/cap-creds.yml -d FLOWER_USER:NEW_VAL -d FLOWER_PASSWORD:MY_VAL
    """
    namespace, secret_name, base64_data, base64_data_keys = extract_data_from_file(
        secret_file
    )

    if not add_data:
        logging.error("Please provide keys to add!")
        sys.exit(1)

    requested_addition = dict(secret.split(":", 1) for secret in add_data)
    for k, v in requested_addition.items():
        if validate_key(base64_data_keys, k):
            logging.error("Key {} already present. Please use update-secret command.")
            sys.exit(1)
        update_key(base64_data, k, v)

    # Keeping required metadata only
    base64_data["metadata"] = {"name": secret_name, "namespace": namespace}
    base64_data.pop("type", None)

    with open("tmp", "w") as tmp:
        yaml.dump(base64_data, tmp)

    run_kubeseal(secret_file, namespace)


@click.command()
@click.argument("secret_file", type=click.Path(exists=True))
def open_editor(secret_file):
    """Command to add/update new keys to sealed secrets interactively.

    Example: python cli/main.py open-editor cap/environments/cap-qa/sealedsecrets/cap-creds.yml
    """
    namespace, secret_name, base64_data, _ = extract_data_from_file(secret_file)

    get_realdata(base64_data, filename="tmp_real")
    click.edit(filename="tmp_real")

    # Encode the real data in base64
    base64_data = get_encoded_base64data(filename="tmp_real")
    os.remove("tmp_real")

    # Keeping required metadata only
    base64_data["metadata"] = {"name": secret_name, "namespace": namespace}
    base64_data.pop("type", None)

    with open("tmp", "w") as tmp:
        yaml.dump(base64_data, tmp)

    run_kubeseal(secret_file, namespace)


secret_manager.add_command(view_secret)
secret_manager.add_command(update_secret)
secret_manager.add_command(add_secret)
secret_manager.add_command(open_editor)


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    secret_manager()
