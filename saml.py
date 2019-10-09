import subprocess
import tempfile


OPENSSL_REQ_CONFIG = '''[req]
distinguished_name = dn
prompt = no

[dn]
CN=PseudoSAMLServer
'''

def generate_provider():
    """Generate key and cert."""
    with tempfile.NamedTemporaryFile() as config:
        config.write(OPENSSL_REQ_CONFIG.encode('utf-8'))
        config.flush()
        config.write(OPENSSL_REQ_CONFIG.encode('utf-8'))
        proc = subprocess.run(['openssl', 'req', '-x509',
                               '-newkey', 'rsa', '-keyout', 'key.pem',
                               '-nodes', '-out', 'cert.pem',
                               '-config', config.name])
    if proc.returncode != 0:
        raise RuntimeError('openssl genpkey failed')


def get_certificate():
    """Return the armored certificate."""
    with open('cert.pem', 'r') as cert_file:
        return '\n'.join(cert_file.read().split('\n')[1:-2])
