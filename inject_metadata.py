import xml.etree.ElementTree as ET


def inject_metadata(old, new):
    ET.register_namespace('ds', 'http://www.w3.org/2000/09/xmldsig#')
    ET.register_namespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata')
    ET.register_namespace('saml2', 'urn:oasis:names:tc:SAML:2.0:assertion')
    tree = ET.Element('{urn:oasis:names:tc:SAML:2.0:metadata}EntitiesDescriptor')
    tree.append(ET.fromstring(old))
    tree.append(ET.fromstring(new))
    return ET.tostring(tree)
