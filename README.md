# SIS K8S CLI

CLI tool for the K8s repository

### Installation

```
pip install -r requirements.txt
```

### Usage

```
# View secrets
python cli/main.py view-secret <path_to_secret_yaml>
python cli/main.py view-secret <path_to_secret_yaml> -d <SECRET_KEY_1> -d <SECRET_KEY_2>


# Update secrets
python cli/main.py update-secret <path_to_secret_yaml> -d <SECRET_KEY_1>:<SECRET_VALUE_1> -d <SECRET_KEY_2>::<SECRET_VALUE_2>


# Add secrets
python cli/main.py add-secret <path_to_secret_yaml> -d <SECRET_KEY_1>:<SECRET_VALUE_1> -d <SECRET_KEY_2>::<SECRET_VALUE_2>

```
