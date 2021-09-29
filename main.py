import argparse, sys, textwrap, logging
from acmepy import GetCertificate

DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='python3 main.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This python script helps to get signed TLS certificate from Let's Encrypt using the ACME protocol. 
            It will need to be run on the server and should have access to the private account key."""),
        epilog="Refer the documentation for full usage."
    )
    parser.add_argument("--account-key", required=True, help="path to  account private key")
    parser.add_argument("--csr", required=True, help="path to your certificate signing request")
    parser.add_argument("--acme-dir", required=True, help="path to the .well-known/acme-challenge/ directory")
    parser.add_argument("--log-level", choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'], default="INFO", help="log-level for the logs")
    args = parser.parse_args(argv)
    logger.setLevel(args.log_level)
    signed_crt = GetCertificate.get_cert(args.account_key, args.csr, args.acme_dir, logger)
    sys.stdout.write(signed_crt)

if __name__ == "__main__": 
    main(sys.argv[1:])
    