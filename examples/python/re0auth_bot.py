#!/usr/bin/env python3
"""Re0Auth 下游机器人最小样例：设备流授权 → 调网关取数 → 撤销。

只用标准库（urllib / json / time / argparse），对着一个本地实例就能跑完。
刻意不引入 HTTP 库：这份代码要能被一个陌生开发者在一屏内读完，而不是先学一套 SDK。

协议依据：
- RFC 8628 —— 设备授权流（设备码、轮询、authorization_pending / slow_down）
- RFC 6749 §5.2 —— OAuth 端点用扁平的 {"error", "error_description"}
- RFC 9457 —— 本服务的其它端点用 problem+json，稳定标识符是 "code"
- RFC 7009 —— 撤销
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


class ProtocolError(Exception):
    """服务端明确拒绝，且重试不会改变结果。"""


class Pending(Exception):
    """RFC 8628：用户还没批准，按 interval 继续轮询。"""


class SlowDown(Exception):
    """RFC 8628：轮询太快，间隔 +5 秒后继续。"""


def post_form(url, fields, token=None):
    data = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("content-type", "application/x-www-form-urlencoded")
    if token:
        request.add_header("authorization", f"Bearer {token}")
    return _send(request)


def get_json(url, token):
    request = urllib.request.Request(url, method="GET")
    request.add_header("authorization", f"Bearer {token}")
    return _send(request)


def _send(request):
    """发出请求并返回 (status, body)。4xx/5xx 也返回 body，由调用方判读。"""
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, _decode(response.read())
    except urllib.error.HTTPError as error:
        return error.code, _decode(error.read())


def _decode(raw):
    text = raw.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def oauth_error(body):
    """RFC 6749 的扁平错误体；不是就返回 None。"""
    if isinstance(body, dict) and "error" in body:
        return body["error"], body.get("error_description", "")
    return None


def problem(body):
    """RFC 9457 的 problem 体；稳定标识符是 code，不是 title。"""
    if isinstance(body, dict) and "code" in body and "status" in body:
        return body["code"], body.get("detail", "")
    return None


def describe(body):
    flat = oauth_error(body)
    if flat:
        return f"{flat[0]}: {flat[1]}"
    prob = problem(body)
    if prob:
        return f"{prob[0]}: {prob[1]}"
    return str(body)[:200]


def start_device_flow(issuer, client_id, client_secret, scope):
    fields = {"client_id": client_id, "scope": scope}
    if client_secret:
        fields["client_secret"] = client_secret
    status, body = post_form(f"{issuer}/oauth/device_authorization", fields)
    if status != 200:
        raise ProtocolError(f"device_authorization failed ({status}): {describe(body)}")
    return body


def poll_for_token(issuer, client_id, client_secret, device_code, interval, expires_in):
    """按服务端给的 interval 轮询。三种暂时性错误都是正常流程的一部分。"""
    wait = max(int(interval), 1)
    deadline = time.monotonic() + int(expires_in)
    fields = {"grant_type": DEVICE_GRANT, "device_code": device_code, "client_id": client_id}
    if client_secret:
        fields["client_secret"] = client_secret

    while time.monotonic() < deadline:
        time.sleep(wait)
        status, body = post_form(f"{issuer}/oauth/token", fields)
        if status == 200:
            return body
        flat = oauth_error(body)
        if flat and flat[0] == "authorization_pending":
            continue
        if flat and flat[0] == "slow_down":
            # RFC 8628 §3.5: 每次 slow_down 之后间隔加 5 秒，且这是唯一正确的反应。
            wait += 5
            continue
        raise ProtocolError(f"token exchange failed ({status}): {describe(body)}")
    raise ProtocolError("设备授权在用户批准前过期了")


def call_gateway(issuer, connector, resource, access_token, limit):
    url = f"{issuer}/api/v1/upstreams/{urllib.parse.quote(connector)}/{urllib.parse.quote(resource)}"
    if limit:
        url += "?" + urllib.parse.urlencode({"limit": limit})
    status, body = get_json(url, access_token)
    if status != 200:
        # 网关的错误是 problem 形状：code 才是稳定的分支依据。
        raise ProtocolError(f"gateway failed ({status}): {describe(body)}")
    return body


def revoke(issuer, client_id, client_secret, token):
    fields = {"token": token, "client_id": client_id}
    if client_secret:
        fields["client_secret"] = client_secret
    status, body = post_form(f"{issuer}/oauth/revoke", fields)
    # RFC 7009 §2.2: 未知令牌也回 200，否则这个端点就成了存在性探针。
    if status != 200:
        raise ProtocolError(f"revoke failed ({status}): {describe(body)}")


def main(argv):
    parser = argparse.ArgumentParser(description="Re0Auth 设备流 + 网关取数最小样例")
    parser.add_argument("--issuer", required=True, help="实例地址，例如 http://127.0.0.1:8080")
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--client-secret", default="", help="公开客户端留空")
    parser.add_argument("--scope", default="openid profile", help="空格分隔")
    parser.add_argument("--connector", required=True, help="连接器 id，例如 phihub")
    parser.add_argument("--resource", required=True, help="该连接器声明的资源名")
    parser.add_argument("--limit", type=int, default=5, help="列表资源每页条数")
    args = parser.parse_args(argv)

    issuer = args.issuer.rstrip("/")

    device = start_device_flow(issuer, args.client_id, args.client_secret, args.scope)
    print("1. 打开下面的地址，输入设备码：")
    print(f"   {device.get('verification_uri_complete') or device.get('verification_uri')}")
    print(f"   设备码：{device['user_code']}")
    print(f"   有效期：{device['expires_in']} 秒")

    token = poll_for_token(
        issuer,
        args.client_id,
        args.client_secret,
        device["device_code"],
        device.get("interval", 5),
        device["expires_in"],
    )
    print("2. 已拿到访问令牌（不打印，避免进日志）")

    envelope = call_gateway(
        issuer, args.connector, args.resource, token["access_token"], args.limit
    )
    print("3. 网关返回的归一化信封：")
    print(f"   upstream   = {envelope.get('upstream')}")
    print(f"   fetched_at = {envelope.get('fetched_at')}")
    print(f"   stability  = {envelope.get('stability')}")
    data = envelope.get("data")
    if isinstance(data, dict) and "items" in data:
        print(f"   items      = {len(data['items'])} 条，next_cursor = {data.get('next_cursor')}")
    else:
        print(f"   data       = {json.dumps(data, ensure_ascii=False)[:300]}")

    # 撤销刷新令牌，等于让这个应用再也换不出新令牌。用户侧对应账户页的「撤销」。
    revoke_target = token.get("refresh_token") or token["access_token"]
    revoke(issuer, args.client_id, args.client_secret, revoke_target)
    print("4. 已撤销令牌；再调用网关会得到 401 invalid_token")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ProtocolError as error:
        print(f"失败：{error}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
