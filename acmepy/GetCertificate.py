from acmepy import UtilityFunctions as uf
import re, binascii, json, hashlib, os 

DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"

def get_cert(account_key, csr, acme_dir, logger, contact=None):
  directory, acct_headers, alg, jwk = None, None, None, None # global variables
  logger.info("Parsing account key...")
  out = uf._cmd(["openssl", "rsa", "-in", account_key, "-noout", "-text"], err_msg="OpenSSL Error")
  pub_pattern = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
  pub_hex, pub_exp = re.search(pub_pattern, out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
  pub_exp = "{0:x}".format(int(pub_exp))
  pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
  alg = "RS256"
  jwk = {
      "e": uf._b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
      "kty": "RSA",
      "n": uf._b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
  }
  accountkey_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
  thumbprint = uf._b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

  # find domains
  logger.info("Parsing CSR...")
  out = uf._cmd(["openssl", "req", "-in", csr, "-noout", "-text"], err_msg="Error loading {0}".format(csr))
  domains = set([])
  common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", out.decode('utf8'))
  if common_name is not None:
      domains.add(common_name.group(1))
  subject_alt_names = re.search(r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n", out.decode('utf8'), re.MULTILINE|re.DOTALL)
  if subject_alt_names is not None:
      for san in subject_alt_names.group(1).split(", "):
          if san.startswith("DNS:"):
              domains.add(san[4:])
  logger.info("Found domains: {0}".format(", ".join(domains)))

  # get the ACME directory of urls
  logger.info("Getting directory...")
  directory_url = DEFAULT_DIRECTORY_URL # backwards compatibility with deprecated CA kwarg
  directory, _, _ = uf._do_request(directory_url, err_msg="Error getting directory")
  logger.info("Directory found!")

  # create account, update contact details (if any), and set the global key identifier
  logger.info("Registering account...")
  reg_payload = {"termsOfServiceAgreed": True}
  account, code, acct_headers = uf._send_signed_request(directory['newAccount'], reg_payload, "Error registering")
  logger.info("Registered!" if code == 201 else "Already registered!")
  if contact is not None:
      account, _, _ = uf._send_signed_request(acct_headers['Location'], {"contact": contact}, "Error updating contact details")
      logger.info("Updated contact details:\n{0}".format("\n".join(account['contact'])))

  # create a new order
  logger.info("Creating new order...")
  order_payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
  order, _, order_headers = uf._send_signed_request(directory['newOrder'], order_payload, "Error creating new order")
  logger.info("Order created!")

  # get the authorizations that need to be completed
  for auth_url in order['authorizations']:
      authorization, _, _ = uf._send_signed_request(auth_url, None, "Error getting challenges")
      domain = authorization['identifier']['value']
      logger.info("Verifying {0}...".format(domain))

      # find the http-01 challenge and write the challenge file
      challenge = [c for c in authorization['challenges'] if c['type'] == "http-01"][0]
      token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
      keyauthorization = "{0}.{1}".format(token, thumbprint)
      wellknown_path = os.path.join(acme_dir, token)
      with open(wellknown_path, "w") as wellknown_file:
          wellknown_file.write(keyauthorization)

      # check that the file is in place
      try:
          wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
          assert (True or uf._do_request(wellknown_url)[0] == keyauthorization)
      except (AssertionError, ValueError) as e:
          raise ValueError("Wrote file to {0}, but couldn't download {1}: {2}".format(wellknown_path, wellknown_url, e))

      # say the challenge is done
      uf._send_signed_request(challenge['url'], {}, "Error submitting challenges: {0}".format(domain))
      authorization = uf._poll_until_not(auth_url, ["pending"], "Error checking challenge status for {0}".format(domain))
      if authorization['status'] != "valid":
          raise ValueError("Challenge did not pass for {0}: {1}".format(domain, authorization))
      os.remove(wellknown_path)
      logger.info("{0} verified!".format(domain))

  # finalize the order with the csr
  logger.info("Signing certificate...")
  csr_der = uf._cmd(["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error")
  uf._send_signed_request(order['finalize'], {"csr": uf._b64(csr_der)}, "Error finalizing order")

  # poll the order to monitor when it's done
  order = uf._poll_until_not(order_headers['Location'], ["pending", "processing"], "Error checking order status")
  if order['status'] != "valid":
      raise ValueError("Order failed: {0}".format(order))

  # download the certificate
  certificate_pem, _, _ = uf._send_signed_request(order['certificate'], None, "Certificate download failed")
  logger.info("Certificate signed!")
  return certificate_pem
