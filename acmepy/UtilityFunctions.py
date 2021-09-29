import base64, subprocess, json, time
from urllib.request import urlopen, Request

def _base64(text):
    """Encodes string as base64 as specified in the ACME RFC."""
    return base64.urlsafe_b64encode(text).decode("utf8").rstrip("=")

def _openssl(command, options, communicate=None):
    """Run openssl command line and raise IOError on non-zero return."""
    openssl = subprocess.Popen(["openssl", command] + options,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out, err = openssl.communicate(communicate)
    if openssl.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    return out

def _cmd(cmd_list, stdin=None, cmd_input=None, err_msg="Command Line Error"):
    """helper function - run external commands"""
    proc = subprocess.Popen(cmd_list, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(cmd_input)
    if proc.returncode != 0:
        raise IOError("{0}\n{1}".format(err_msg, err))
    return out

def _do_request(url, data=None, err_msg="Error", depth=0):
    """helper function - make request and automatically parse json response"""
    try:
        resp = urlopen(Request(url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "acme-tiny"}))
        resp_data, code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
    except IOError as e:
        resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
        code, headers = getattr(e, "code", None), {}
    try:
        resp_data = json.loads(resp_data) # try to parse json results
    except ValueError:
        pass # ignore json parsing errors
    if depth < 100 and code == 400 and resp_data['type'] == "urn:ietf:params:acme:error:badNonce":
        raise IndexError(resp_data) # allow 100 retrys for bad nonces
    if code not in [200, 201, 204]:
        raise ValueError("{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(err_msg, url, data, code, resp_data))
    return resp_data, code, headers

def _send_signed_request(url, payload, directory, alg, acct_headers, account_key, jwk, err_msg, depth=0):
    payload64 = "" if payload is None else _base64(json.dumps(payload).encode('utf8'))
    new_nonce = _do_request(directory['newNonce'])[2]['Replay-Nonce']
    protected = {"url": url, "alg": alg, "nonce": new_nonce}
    protected.update({"jwk": jwk} if acct_headers is None else {"kid": acct_headers['Location']})
    protected64 = _base64(json.dumps(protected).encode('utf8'))
    protected_input = "{0}.{1}".format(protected64, payload64).encode('utf8')
    out = _cmd(["openssl", "dgst", "-sha256", "-sign", account_key], stdin=subprocess.PIPE, cmd_input=protected_input, err_msg="OpenSSL Error")
    data = json.dumps({"protected": protected64, "payload": payload64, "signature": _base64(out)})
    try:
        return _do_request(url, data=data.encode('utf8'), err_msg=err_msg, depth=depth)
    except IndexError: # retry bad nonces (they raise IndexError)
        return _send_signed_request(url, payload, err_msg, depth=(depth + 1))

# helper function - poll until complete
def _poll_until_not(url, pending_statuses, err_msg):
    result, t0 = None, time.time()
    while result is None or result['status'] in pending_statuses:
        assert (time.time() - t0 < 3600), "Polling timeout" # 1 hour timeout
        time.sleep(0 if result is None else 2)
        result, _, _ = _send_signed_request(url, None, err_msg)
    return result