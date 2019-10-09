import base64
import datetime
import hashlib
import subprocess

try:
    import saml
    HAVE_SAML = True
except ImportError:
    pass


XML_HEADER = '''<?xml version="1.0" encoding="UTF-8"?>
'''

XML_SIGNEDINFO = '''<ds:SignedInfo{extra_namespace}>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>
            <ds:Reference URI="#{reference}">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                        <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"></ec:InclusiveNamespaces>
                    </ds:Transform>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>
                <ds:DigestValue>{digest}</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>'''

XML_SIGNATURE = '''<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        {signed_info}
        <ds:SignatureValue>{signature}</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>{certificate}</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>'''

SAML_RESPONSE = '''<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" Destination="https://signin.aws.amazon.com/saml" ID="response" IssueInstant="{issue_instant}" Version="2.0">
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{entity_id}</saml2:Issuer>
    {signature}
    <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></saml2p:StatusCode>
    </saml2p:Status>
    {assertion}
</saml2p:Response>'''

SAML_ASSERTION = '''<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" {extra_namespace}ID="assertion" IssueInstant="{issue_instant}" Version="2.0">
        <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{entity_id}</saml2:Issuer>
        {signature}
        <saml2:Subject>
            <saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified">{session_name}</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData NotOnOrAfter="{expiration}" Recipient="https://signin.aws.amazon.com/saml"></saml2:SubjectConfirmationData>
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="{issue_instant}" NotOnOrAfter="{expiration}">
            <saml2:AudienceRestriction>
                <saml2:Audience>urn:amazon:webservices</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="id1569607051744.1978947176">
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
        <saml2:AttributeStatement>
            <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{role_arn},{saml_provider_arn}</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
                <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{session_name}</saml2:AttributeValue>
            </saml2:Attribute>
        </saml2:AttributeStatement>
    </saml2:Assertion>'''


def get_sig(string, reference, certificate):
    """Return an XML signature string of the passed string."""
    h = hashlib.sha256()
    h.update(string.encode('utf-8'))
    signed_info = XML_SIGNEDINFO.format(
        digest=base64.b64encode(h.digest()).decode('utf-8'),
        extra_namespace=' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"',
        reference=reference)
    proc = subprocess.Popen(['openssl', 'dgst', '-sha256', '-sign', 'key.pem'],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    (stdout, stderr) = proc.communicate(signed_info.encode('utf-8'))
    if proc.returncode != 0:
        raise RuntimeError(f'openssl dgst failed: {stderr}')
    signed_info = XML_SIGNEDINFO.format(
        digest=base64.b64encode(h.digest()).decode('utf-8'),
        extra_namespace='',
        reference=reference)
    return XML_SIGNATURE.format(
        certificate=certificate,
        signed_info=signed_info,
        signature=base64.b64encode(stdout).decode('utf-8'))


def generate_saml_response(role_arn, provider_arn, session_name, certificate=None, entity_id='urn:PseudoSAMLServer):
    """Return base 64 encoded SAML response."""
    if certificate is None:
        if HAVE_SAML:
            certificate = saml.get_certificate()
        else:
            raise RuntimeError('certificate must be provided if saml is not present')

    now = datetime.datetime.utcnow()
    assertion_keys = {
        'entity_id': entity_id,
        'expiration': (now + datetime.timedelta(minutes=5)).isoformat() + 'Z',
        'issue_instant': now.isoformat() + 'Z',
        'role_arn': role_arn,
        'saml_provider_arn': provider_arn,
        'session_name': session_name,
    }
    unsigned_assertion = SAML_ASSERTION.format(
        extra_namespace='xmlns:xs="http://www.w3.org/2001/XMLSchema" ',
        signature='',
        **assertion_keys)
    assertion = SAML_ASSERTION.format(
        extra_namespace='',
        signature=get_sig(unsigned_assertion, 'assertion', certificate),
        **assertion_keys)
    unsigned_response = SAML_RESPONSE.format(
        assertion=assertion,
        issue_instant=now.isoformat() + 'Z',
        signature='')
    response = XML_HEADER + SAML_RESPONSE.format(
        assertion=assertion,
        issue_instant=now.isoformat() + 'Z',
        signature=get_sig(unsigned_response, 'response', certificate))
    return base64.b64encode(response.encode('utf-8')).decode('utf-8')
