"""Portal de acceso a Juice Shop.

GET  -> formulario de login (nombre + codigo).
POST -> valida el codigo contra los hashes guardados en SSM y, si es correcto,
        agrega la IP de origen (/32) al Security Group del portal.

Sin secretos en el codigo: la configuracion llega por variables de entorno y
las credenciales de AWS por el rol IAM de la funcion.
"""
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger()
log.setLevel(logging.INFO)

SG_ID = os.environ["SG_ID"]
PARAM_NAME = os.environ["PARAM_NAME"]
REDIRECT_URL = os.environ["REDIRECT_URL"]
PORT = int(os.environ.get("PORT", "3000"))
MAX_IPS = int(os.environ.get("MAX_IPS", "2"))      # IPs activas por persona
MAX_RULES = int(os.environ.get("MAX_RULES", "40"))  # tope total de reglas
CACHE_TTL = 300   # segundos; una rotacion de codigos tarda a lo sumo esto
FAIL_DELAY = 1.0  # demora fija ante cualquier fallo de autenticacion
PREFIX = "portal:"

ec2 = boto3.client("ec2")
ssm = boto3.client("ssm")

_b64 = lambda x: base64.b64encode(x).decode()
# Hash falso para igualar el tiempo de respuesta cuando el nombre no existe
_DUMMY = f"scrypt$16384$8$1${_b64(bytes(16))}${_b64(bytes(32))}"
_cache = {"t": 0.0, "v": {}}

SECURITY_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    ),
}

PAGE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{extra_head}<title>Acceso</title>
<style>
:root{{--bg:#fff;--fg:#1a1a1a;--mut:#666;--bd:#ccc;--ac:#1a56db;--er:#b42318}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16181d;--fg:#eee;--mut:#9aa0a6;--bd:#444;--ac:#6ea0ff;--er:#ff8a80}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:16px system-ui,sans-serif}}
main{{max-width:380px;margin:0 auto;padding:48px 16px}}
h1{{font-size:20px;margin:0 0 4px}}p{{color:var(--mut)}}
label{{display:block;margin:16px 0 4px;font-size:14px}}
input{{width:100%;box-sizing:border-box;padding:10px;font-size:16px;border:1px solid var(--bd);
border-radius:6px;background:transparent;color:var(--fg)}}
button{{margin-top:20px;width:100%;padding:12px;font-size:16px;border:0;border-radius:6px;
background:var(--ac);color:#fff}}
.err{{color:var(--er)}}a{{color:var(--ac)}}
</style></head><body><main>{body}</main></body></html>"""

FORM = """<h1>Acceso al laboratorio</h1>
<p>Ingresá tu nombre y tu código personal.</p>
{msg}
<form method="post" autocomplete="on">
<label for="n">Nombre</label>
<input id="n" name="nombre" autocomplete="username" maxlength="32" required>
<label for="c">Código</label>
<input id="c" name="codigo" type="password" autocomplete="current-password" maxlength="64" required>
<button type="submit">Entrar</button>
</form>"""


def respond(status, body, extra_head=""):
    return {
        "statusCode": status,
        "headers": SECURITY_HEADERS,
        "body": PAGE.format(body=body, extra_head=extra_head),
    }


def form(msg=""):
    return FORM.format(msg=f'<p class="err">{msg}</p>' if msg else "")


# ---------- autenticacion ----------

def get_hashes():
    if time.time() - _cache["t"] > CACHE_TTL:
        r = ssm.get_parameter(Name=PARAM_NAME, WithDecryption=True)
        data = json.loads(r["Parameter"]["Value"])
        _cache["v"] = {n.lower(): (n, h) for n, h in data.items()}
        _cache["t"] = time.time()
    return _cache["v"]


def verify(code, stored):
    _, n, r, p, salt, expected = stored.split("$")
    calc = hashlib.scrypt(code.encode(), salt=base64.b64decode(salt),
                          n=int(n), r=int(r), p=int(p), dklen=32)
    return hmac.compare_digest(calc, base64.b64decode(expected))


def check_login(name, code):
    entry = get_hashes().get(name.lower())
    ok = verify(code, entry[1] if entry else _DUMMY)  # siempre calcula el hash
    return entry[0] if (entry and ok) else None


# ---------- Security Group ----------

def list_rules():
    rules, token = [], None
    while True:
        kw = {"Filters": [{"Name": "group-id", "Values": [SG_ID]}], "MaxResults": 100}
        if token:
            kw["NextToken"] = token
        r = ec2.describe_security_group_rules(**kw)
        rules += [x for x in r["SecurityGroupRules"] if not x.get("IsEgress")]
        token = r.get("NextToken")
        if not token:
            return rules


def grant(name, ip):
    """Agrega ip/32 en PORT para `name`. Devuelve 'ya' si ya tenia acceso."""
    cidr = f"{ip}/32"
    rules = list_rules()
    if any(x.get("CidrIpv4") == cidr and x.get("IpProtocol") == "tcp"
           and x.get("FromPort") == PORT for x in rules):
        return "ya"

    mine = [x for x in rules if x.get("Description", "").startswith(f"{PREFIX}{name}:")]
    mine.sort(key=lambda x: x["Description"].split(":")[2])  # mas viejas primero
    to_revoke = mine[: max(0, len(mine) - MAX_IPS + 1)]
    if to_revoke:
        ec2.revoke_security_group_ingress(
            GroupId=SG_ID,
            SecurityGroupRuleIds=[x["SecurityGroupRuleId"] for x in to_revoke])
    if len(rules) - len(to_revoke) >= MAX_RULES:
        raise RuntimeError("tope de reglas alcanzado")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    try:
        ec2.authorize_security_group_ingress(
            GroupId=SG_ID,
            IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": PORT, "ToPort": PORT,
                "IpRanges": [{"CidrIp": cidr, "Description": f"{PREFIX}{name}:{stamp}"}],
            }])
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidPermission.Duplicate":
            raise
    return "nueva"


# ---------- handler ----------

def lambda_handler(event, context):
    http = event.get("requestContext", {}).get("http", {})
    method = http.get("method", "")
    ip = http.get("sourceIp", "")  # IP real del cliente, nunca lo que envia el usuario

    if method == "GET":
        return respond(200, form())
    if method != "POST":
        return respond(405, "<h1>Método no permitido</h1>")

    real_name = None
    try:
        body = event.get("body") or ""
        if event.get("isBase64Encoded"):
            body = base64.b64decode(body).decode("utf-8")
        if len(body) > 2048:
            raise ValueError("body demasiado grande")
        f = parse_qs(body, max_num_fields=6)
        name = f.get("nombre", [""])[0].strip()[:32]
        code = f.get("codigo", [""])[0].replace("-", "").replace(" ", "")[:64]
        real_name = check_login(name, code)
    except Exception as e:  # cualquier error se trata como fallo, sin detalles al cliente
        log.warning("LOGIN_ERROR ip=%s tipo=%s", ip, type(e).__name__)

    if not real_name:
        log.info("LOGIN_FAIL ip=%s", ip)
        time.sleep(FAIL_DELAY)
        return respond(401, form("Nombre o código incorrecto."))

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        addr = None
    if addr is None or not addr.is_global:
        log.error("IP_INVALIDA ip=%s", ip)
        return respond(500, form("No se pudo habilitar el acceso."))
    if addr.version != 4:
        log.info("IPV6 persona=%s ip=%s", real_name, ip)
        return respond(200, form("Tu red usa IPv6 y el servidor solo acepta IPv4. "
                                 "Probá desde otra red o con datos móviles."))

    try:
        result = grant(real_name, str(addr))
    except Exception as e:
        log.error("GRANT_ERROR persona=%s ip=%s tipo=%s", real_name, ip, type(e).__name__)
        return respond(500, form("No se pudo habilitar el acceso. Avisale al administrador."))

    log.info("ACCESO_OK persona=%s ip=%s resultado=%s", real_name, ip, result)
    url = html.escape(REDIRECT_URL, quote=True)
    return respond(
        200,
        f'<h1>Acceso habilitado</h1><p>Tu IP {html.escape(str(addr))} ya puede entrar. '
        f'Te llevamos a Juice Shop.</p><p><a href="{url}">Ir ahora</a></p>',
        extra_head=f'<meta http-equiv="refresh" content="2;url={url}">',
    )
