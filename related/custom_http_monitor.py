#!/usr/bin/env python

import re
import requests
import sys

def main(ipaddr, port, node, path, method, ssl, regex):
    try:
        request_function = getattr(requests, method.lower())
    except AttributeError:
        sys.stderr.write("Unsupported HTTP method: '%s'" % method)
        return 1
    url = "http%s://%s:%s%s" % (
        "s" if ssl == "yes" else "", ipaddr, port, path
    )
    print "Making %s request to %s" % (method.upper(), url)
    response = request_function(url, allow_redirects=False, verify=False)
    if re.match(regex, str(response.status_code)):
        print "Got status code %s - Success!" % response.status_code
        return 0
    print "Got status code %s - Failed!" % response.status_code
    return 1


if __name__ == "__main__":
    args = {arg.split("=")[0][2:]: arg.split("=")[1] for arg in sys.argv[1:]}
    sys.exit(main(**args))
