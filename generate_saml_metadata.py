try:
    import saml
    HAVE_SAML = True
except ImportError:
    pass


XML_HEADER = '''<?xml version="1.0" encoding="UTF-8"?>
'''

SAML_METADATA = '''<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
    <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{certificate}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com"/>
    </md:IDPSSODescriptor>
</md:EntityDescriptor>'''


def generate_saml_metadata(certificate=None, entity_id='urn:PseudoSAMLServer'):
    """Return SAML metadata string."""
    if certificate is None:
        if HAVE_SAML:
            certificate = saml.get_certificate()
        else:
            raise RuntimeError('certificate must be provided if saml is not present')

    return XML_HEADER + SAML_METADATA.format(certificate=certificate, entity_id=entity_id)
