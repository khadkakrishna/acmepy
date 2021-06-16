import base64, subprocess, json
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