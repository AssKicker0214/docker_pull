"""
1. python debugger cannot use `172.16.1.245:8080` proxy, but python itself can. use localhost `port2port`
2. `requests` considers `http` and `https` as two different protocols, when using proxies
"""
import requests
import socket
import re
from typing import Tuple


# PROXIES = {'https': '172.16.1.245:8080', 'http': '172.16.1.245:8080'}
PROXIES = {'https': 'localhost:54321', 'http': 'localhost:54321'}

def parse_name(name):
    components = name.split("/")
    image_name, tag_name, *_ = components.pop().split(":") + ["latest"]

    if len(components) > 0 and ('.' in components[0] or ':' in components[0]):
        registry_name = components[0]
        repository_name = '/'.join(components[1:]) or "library"
    else:
        registry_name = "registry-1.docker.io"
        repository_name = '/'.join(components) or "library"

    return registry_name, repository_name, image_name, tag_name


def get_auth_header(registry_name, image_name, repository_name="library", protocol="https"):
    try:
        res = requests.get("%s://%s/v2" % (protocol, registry_name), proxies=PROXIES, verify=False)
        if res.status_code == 200:
            return {}   # no need for authentication, thus no auth header.
        if res.status_code == 401:  # 401 Unauthorized
            print("Authenticating... refer to https://docs.docker.com/registry/spec/auth/token/ ")

            """
            Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
            """
            www_authenticate = res.headers['WWW-Authenticate']
            ptn = re.compile(r'realm="(.*)".*service="(.*)"')
            m = ptn.search(www_authenticate)
            if m:
                auth_url = m.group(1)
                auth_svc = m.group(2)
                auth_res = requests.get(
                    "%s?service=%s&scope=repository:%s/%s:pull" % (auth_url, auth_svc, repository_name, image_name),
                    proxies=PROXIES,
                    verify=False
                )
                token = auth_res.json()['token']
                auth_header = {
                    'Authorization': 'Bearer ' + token,
                    'Accept': 'application/vnd.docker.distribution.manifest.v2+json'
                }
                return auth_header

        return None
    except requests.exceptions.SSLError as e:
        print(e)
        print("Switch to HTTP")
        return get_auth_header(registry_name, image_name, repository_name=repository_name, protocol="http")
    except Exception as e:
        print(e)
        print("Connection failed")
        return None


def get_image_digest(registry_name, repository_name, image_name, tag_name, auth_header: dict) -> dict:
    assert auth_header is not None
    res = requests.get(
        
    )


def pull(image: str):
    registry_name, repository_name, image_name, tag_name = parse_name(image)
    auth_hdr = get_auth_header(registry_name, image_name, repository_name=repository_name)

    if auth_hdr is None:
        print("Cannot access to registry: authentication is required but no token can be fetched")
        retrun False

    get_image_digest(registry_name, repository_name, image_name, tag_name, auth_hdr)
    

if __name__ == "__main__":
    """
    # test
    print(parse_name("docker.io/repo/alpine:2"))
    print(parse_name("docker.io/repo/alpine"))
    print(parse_name("docker.io/alpine:3"))
    print(parse_name("repo/alpine:4"))
    print(parse_name("alpine"))
    """

    hdr = get_auth_header("registry-1.docker.io", "alpine")
    print(hdr)
    # auth("172.21.54.98:5000")
