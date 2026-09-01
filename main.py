import json
import base64
import hashlib
import hmac
import os
import secrets
import ssl
import time
from datetime import date, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from fastapi import FastAPI, Header, HTTPException, Query, Request as FastApiRequest
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from cryptography.fernet import Fernet, InvalidToken


APP_VERSION = "render-free-auth-db-0.5"
FIREBASE_BASE_URL = os.getenv(
    "FIREBASE_BASE_URL",
    "https://base-otimizadora-default-rtdb.firebaseio.com",
).rstrip("/")
SNAPSHOT_PATH = os.getenv("SNAPSHOT_PATH", "snapshot").strip("/")
API_TOKEN = os.getenv("API_TOKEN", "").strip()
AUTH_TOKEN_SECRET = os.getenv("AUTH_TOKEN_SECRET", API_TOKEN).strip()
AUTH_USERS_JSON = os.getenv("AUTH_USERS_JSON", "").strip()
AUTH_TOKEN_TTL_HOURS = int(os.getenv("AUTH_TOKEN_TTL_HOURS", "12"))
AUTH_USER_DB_PATH = os.getenv("AUTH_USER_DB_PATH", "auth/usuarios_app").strip("/")
AUTH_USER_DB_SECRET = os.getenv("AUTH_USER_DB_SECRET", AUTH_TOKEN_SECRET).strip()
ALLOW_PUBLIC_READ = os.getenv("ALLOW_PUBLIC_READ", "true").strip().lower() in {
    "1",
    "true",
    "sim",
    "yes",
}
CACHE_SECONDS = int(os.getenv("CACHE_SECONDS", "10"))
FIREBASE_VERIFY_SSL = os.getenv("FIREBASE_VERIFY_SSL", "true").strip().lower() not in {
    "0",
    "false",
    "nao",
    "no",
}


app = FastAPI(title="API Otimizadora Millpar", version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)

_cache: dict[str, Any] = {"ts": 0.0, "snapshot": None}
_dados_cache: dict[str, Any] = {"ts": 0.0, "chave": "", "registros": [], "s4s": []}
_login_attempts: dict[str, list[float]] = {}

CLASSES_UTEIS = {"CLEAR", "PRIMED", "MULTIBLOCK", "ESMOADO", "SOLIDO", "TREAD", "POLEGADA"}
CLASSES_WASTE = {"WASTE", "LONG WASTE", "BLADE WASTE", "NO PAINEL", "RERIP WASTE", "FULL WASTE BOARD", "NO BAGS"}
CLASSES_NO = {"NO PAINEL", "NO BAGS"}
TURNOS_INFO = {
    "A": {"label": "Turno A", "horario": "06:00 - 15:48"},
    "B": {"label": "Turno B", "horario": "15:48 - 01:10"},
    "C": {"label": "Turno C", "horario": "01:10 - 06:00"},
}
PRODUTOS_FORA_PADRAO_COMPRIMENTO_BLOCKS = {
    'SOLIDO_NO_84 1/4"', 'CUT-STOCK 49"', 'TREAD', 'TREAD 37"', 'TREAD 43"',
    'TREAD 48" 1/2', 'TREAD 49"', 'TREAD 75``', 'TREAD_37"', 'TREAD_43"',
    'TREAD_44"', 'TREAD_49"', "ESTRADO 36'' 3/4'", "ESTRADO 37'",
    "ESTRADO 74'", 'ESTRADO DE CAMA 36 3/4"', 'ESTRADO DE CAMA 38 3/4"',
    'SOLIDO 36 ESTRADO"', 'SOLIDO 48 1/2"', 'SOLIDO 84 1/4"', 'SOLIDO 84"',
    'SOLIDO 85"', 'SOLIDO 43"', 'SOLIDO 48"3/4"', 'SOLIDO 49', 'SOLIDO 49"',
    'SOLIDO 85 1/4"', "SOLIDO 85''", "SOLIDO 85'' 1/4", "SOLIDO 87''",
    'KNOT_TEST', 'NO EMENDA', 'PALETS', 'PALETS FORA', 'BLANKS IND. 1850',
    'BLANKS IND. 2050', 'BLANKS IND. FORA', 'BLANKS INDONESIA', 'BLANKS NO PMVA',
    'BLANKS TURQ. 2450', 'PALETES', 'PALETES FORA',
}


class LoginPayload(BaseModel):
    usuario: str
    senha: str


class NovoUsuarioPayload(BaseModel):
    usuario: str
    senha: str
    nome: str | None = None
    role: str = "viewer"
    ativo: bool = True
    trocar_senha: bool = False


class SolicitarAcessoPayload(BaseModel):
    usuario: str
    senha: str
    nome: str | None = None


class AlterarSenhaPayload(BaseModel):
    senha_atual: str
    nova_senha: str


class ResetarSenhaPayload(BaseModel):
    nova_senha: str


class AtualizarUsuarioPayload(BaseModel):
    nome: str | None = None
    role: str | None = None
    ativo: bool | None = None
    trocar_senha: bool | None = None


def _json_b64(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64_decode_json(valor: str) -> dict[str, Any]:
    padding = "=" * (-len(valor) % 4)
    raw = base64.urlsafe_b64decode((valor + padding).encode("ascii"))
    return json.loads(raw.decode("utf-8"))


def _auth_users_env() -> tuple[dict[str, Any], bool]:
    if not AUTH_USERS_JSON:
        return {}, True
    try:
        users = json.loads(AUTH_USERS_JSON)
    except json.JSONDecodeError:
        return {}, False
    return users if isinstance(users, dict) else {}, isinstance(users, dict)


def _normalizar_usuario(usuario: str) -> str:
    return " ".join(str(usuario or "").strip().lower().split())


def _verify_password(senha: str, senha_hash: str) -> bool:
    partes = str(senha_hash or "").split("$")
    if len(partes) != 4 or partes[0] != "pbkdf2_sha256":
        return False
    try:
        iteracoes = int(partes[1])
        salt = bytes.fromhex(partes[2])
        esperado = bytes.fromhex(partes[3])
    except ValueError:
        return False
    recebido = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, iteracoes)
    return hmac.compare_digest(recebido, esperado)


def _hash_password(senha: str, iteracoes: int = 210_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, iteracoes)
    return f"pbkdf2_sha256${iteracoes}${salt.hex()}${digest.hex()}"


def _validar_senha_forte(senha: str) -> None:
    if len(senha or "") < 8:
        raise HTTPException(status_code=400, detail="A senha deve ter pelo menos 8 caracteres")


def _validar_role(role: str) -> str:
    role_norm = str(role or "viewer").strip().lower()
    if role_norm not in {"viewer", "admin"}:
        raise HTTPException(status_code=400, detail="Perfil invalido. Use viewer ou admin")
    return role_norm


def _firebase_url(path: str) -> str:
    safe_path = "/".join(quote(p, safe="") for p in path.strip("/").split("/") if p)
    return f"{FIREBASE_BASE_URL}/{safe_path}.json"


def _firebase_request(method: str, path: str, body: Any | None = None) -> Any:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(_firebase_url(path), data=data, headers=headers, method=method)
    context = None if FIREBASE_VERIFY_SSL else ssl._create_unverified_context()
    with urlopen(req, timeout=20, context=context) as resp:
        raw = resp.read().decode("utf-8")
    if not raw or raw == "null":
        return None
    return json.loads(raw)


def _firebase_set(path: str, body: Any) -> Any:
    return _firebase_request("PUT", path, body)


def _user_db_secret() -> str:
    secret = AUTH_USER_DB_SECRET or AUTH_TOKEN_SECRET or API_TOKEN
    if not secret:
        raise HTTPException(status_code=500, detail="AUTH_USER_DB_SECRET nao configurado")
    return secret


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(_user_db_secret().encode("utf-8")).digest())
    return Fernet(key)


def _auth_users_db_read() -> dict[str, Any]:
    db = _firebase_get(AUTH_USER_DB_PATH) or {}
    if not isinstance(db, dict) or not db.get("ciphertext"):
        return {}
    try:
        raw = _fernet().decrypt(str(db["ciphertext"]).encode("utf-8"), ttl=None)
        users = json.loads(raw.decode("utf-8"))
    except (InvalidToken, json.JSONDecodeError, ValueError, TypeError):
        raise HTTPException(status_code=500, detail="Banco de usuarios invalido ou segredo incorreto")
    return users if isinstance(users, dict) else {}


def _auth_users_db_write(users: dict[str, Any]) -> None:
    raw = json.dumps(users, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    token = _fernet().encrypt(raw).decode("utf-8")
    _firebase_set(
        AUTH_USER_DB_PATH,
        {
            "version": 1,
            "updated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "ciphertext": token,
        },
    )


def _auth_users() -> dict[str, Any]:
    env_users, _ = _auth_users_env()
    users: dict[str, Any] = {}
    for usuario, info in env_users.items():
        usuario_norm = _normalizar_usuario(usuario)
        if isinstance(info, dict):
            item = dict(info)
        else:
            item = {"senha_hash": str(info)}
        item.setdefault("nome", usuario_norm)
        item.setdefault("role", "viewer")
        item.setdefault("ativo", True)
        item.setdefault("origem", "env")
        users[usuario_norm] = item
    users.update(_auth_users_db_read())
    return users


def _public_user(usuario: str, info: dict[str, Any]) -> dict[str, Any]:
    return {
        "usuario": usuario,
        "nome": info.get("nome") or usuario,
        "role": info.get("role") or "viewer",
        "ativo": bool(info.get("ativo", True)),
        "trocar_senha": bool(info.get("trocar_senha", False)),
        "pendente": bool(info.get("pendente", False)),
        "origem": info.get("origem") or "db",
        "criado_em": info.get("criado_em"),
        "atualizado_em": info.get("atualizado_em"),
        "ultimo_login": info.get("ultimo_login"),
    }


def _registrar_falha_login(usuario: str) -> None:
    agora = time.time()
    janela = agora - 15 * 60
    tentativas = [t for t in _login_attempts.get(usuario, []) if t >= janela]
    tentativas.append(agora)
    _login_attempts[usuario] = tentativas


def _checar_limite_login(usuario: str) -> None:
    agora = time.time()
    janela = agora - 15 * 60
    tentativas = [t for t in _login_attempts.get(usuario, []) if t >= janela]
    _login_attempts[usuario] = tentativas
    if len(tentativas) >= 8:
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde alguns minutos")


def _limpar_falhas_login(usuario: str) -> None:
    _login_attempts.pop(usuario, None)


def _assinar_token(usuario: str, nome: str, role: str = "viewer") -> str:
    if not AUTH_TOKEN_SECRET:
        raise HTTPException(status_code=500, detail="AUTH_TOKEN_SECRET nao configurado no Render")
    agora = int(time.time())
    payload = {
        "sub": usuario,
        "nome": nome,
        "role": role,
        "iat": agora,
        "exp": agora + AUTH_TOKEN_TTL_HOURS * 3600,
    }
    corpo = _json_b64(payload)
    assinatura = hmac.new(AUTH_TOKEN_SECRET.encode("utf-8"), corpo.encode("ascii"), hashlib.sha256).digest()
    return corpo + "." + base64.urlsafe_b64encode(assinatura).decode("ascii").rstrip("=")


def _validar_token_sessao(token: str) -> dict[str, Any] | None:
    if not token or not AUTH_TOKEN_SECRET or "." not in token:
        return None
    corpo, assinatura_recebida = token.rsplit(".", 1)
    assinatura = hmac.new(AUTH_TOKEN_SECRET.encode("utf-8"), corpo.encode("ascii"), hashlib.sha256).digest()
    assinatura_ok = base64.urlsafe_b64encode(assinatura).decode("ascii").rstrip("=")
    if not hmac.compare_digest(assinatura_recebida, assinatura_ok):
        return None
    try:
        payload = _b64_decode_json(corpo)
    except Exception:
        return None
    if int(payload.get("exp") or 0) < int(time.time()):
        return None
    if str(payload.get("sub") or "") not in _auth_users():
        return None
    return payload


def _require_auth(x_api_token: str | None, authorization: str | None, x_auth_token: str | None = None) -> dict[str, Any]:
    if ALLOW_PUBLIC_READ:
        return {"sub": "public", "nome": "public", "role": "viewer"}

    bearer = _extrair_bearer(authorization, x_auth_token)
    if API_TOKEN and (x_api_token == API_TOKEN or bearer == API_TOKEN):
        return {"sub": "api_token", "nome": "API Token", "role": "admin"}

    payload = _validar_token_sessao(bearer)
    if payload:
        return payload

    raise HTTPException(status_code=401, detail="Token invalido ou ausente")


def _require_admin(x_api_token: str | None, authorization: str | None, x_auth_token: str | None = None) -> dict[str, Any]:
    payload = _require_auth(x_api_token, authorization, x_auth_token)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Acesso restrito ao administrador")
    return payload


def _extrair_bearer(authorization: str | None, x_auth_token: str | None = None) -> str:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return x_auth_token or ""


def _check_token(x_api_token: str | None, authorization: str | None, x_auth_token: str | None = None) -> None:
    _require_auth(x_api_token, authorization, x_auth_token)


def _firebase_get(path: str) -> Any:
    return _firebase_request("GET", path)


def _datas_periodo(data_inicio: str, data_fim: str) -> list[str]:
    di = datetime.strptime(data_inicio, "%Y-%m-%d").date()
    df = datetime.strptime(data_fim, "%Y-%m-%d").date()
    if df < di:
        di, df = df, di
    dias = []
    atual = di
    while atual <= df:
        dias.append(atual.isoformat())
        atual += timedelta(days=1)
    return dias


def _periodo_padrao(snap: dict[str, Any]) -> tuple[str, str]:
    periodo = snap.get("periodo") or {}
    hoje = date.today().isoformat()
    return periodo.get("data_inicio") or hoje, periodo.get("data_fim") or hoje


def _carregar_dados_detalhados(data_inicio: str, data_fim: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    chave = f"{data_inicio}|{data_fim}"
    now = time.time()
    if (
        _dados_cache["chave"] == chave
        and now - float(_dados_cache["ts"]) <= CACHE_SECONDS
    ):
        return _dados_cache["registros"], _dados_cache["s4s"]

    registros: list[dict[str, Any]] = []
    s4s: list[dict[str, Any]] = []
    for dia in _datas_periodo(data_inicio, data_fim):
        dados_dia = _firebase_get(f"dados_detalhados/{dia}") or {}
        if isinstance(dados_dia, dict):
            registros_diretos = dados_dia.get("registros") or []
            if registros_diretos:
                registros.extend(registros_diretos)
            else:
                chunks = dados_dia.get("registros_chunks") or {}
                if isinstance(chunks, dict):
                    for chave in sorted(chunks):
                        parte = chunks.get(chave) or []
                        if isinstance(parte, list):
                            registros.extend(parte)
            meta_s4s = dados_dia.get("s4s") or []
            if isinstance(meta_s4s, list):
                s4s.extend(meta_s4s)

    _dados_cache.update({"ts": now, "chave": chave, "registros": registros, "s4s": s4s})
    return registros, s4s


def _filtrar_registros(
    registros: list[dict[str, Any]],
    data_inicio: str,
    data_fim: str,
    turno: str = "",
    otimizadora: str = "",
    bitola: str = "",
    produto: str = "",
) -> list[dict[str, Any]]:
    out = []
    for r in registros:
        d = str(r.get("data") or "")
        if d < data_inicio or d > data_fim:
            continue
        if turno and str(r.get("turno") or "") != turno:
            continue
        if otimizadora and str(r.get("otimizadora") or "") != otimizadora:
            continue
        if bitola and str(r.get("bitola") or "") != bitola:
            continue
        if produto and str(r.get("nome_produto") or "") != produto:
            continue
        out.append(r)
    return out


def _normalizar_produto(valor: Any) -> str:
    return " ".join(str(valor or "").strip().upper().split())


def _mask_produto_refile(r: dict[str, Any]) -> bool:
    classe = str(r.get("classe") or "")
    nome = str(r.get("nome_produto") or "")
    if classe in CLASSES_NO:
        return False
    nome_low = nome.lower()
    return classe == "MULTIBLOCK" or "block" in nome_low or " mb " in f" {nome_low} " or "refile" in nome_low


def _mask_comprimento_blocks(r: dict[str, Any], produto: str = "") -> bool:
    classe = str(r.get("classe") or "")
    if classe not in CLASSES_UTEIS or classe in CLASSES_WASTE or classe in CLASSES_NO:
        return False
    if not produto and _normalizar_produto(r.get("nome_produto")) in PRODUTOS_FORA_PADRAO_COMPRIMENTO_BLOCKS:
        return False
    return True


def _volume(r: dict[str, Any]) -> float:
    try:
        return float(r.get("volume_m3") or 0)
    except (TypeError, ValueError):
        return 0.0


def _pecas(r: dict[str, Any]) -> int:
    try:
        return int(float(r.get("pecas") or 0))
    except (TypeError, ValueError):
        return 0


def _metros(r: dict[str, Any]) -> float:
    try:
        return float(r.get("comprimento_m") or 0)
    except (TypeError, ValueError):
        return 0.0


def _normalizar_bitola(valor: Any) -> str:
    txt = str(valor or "").strip().replace(" ", "")
    return txt.upper()


def _agrupar_s4s(s4s: list[dict[str, Any]], data_inicio: str, data_fim: str, turno: str = "", otimizadora: str = "", bitola: str = "") -> tuple[dict[str, Any], list[dict[str, Any]]]:
    por_bitola: dict[str, dict[str, Any]] = {}
    hist_total: dict[str, dict[str, float]] = {}
    bitola_alvo = _normalizar_bitola(bitola)
    total_boards = 0
    total_soma = 0.0

    for item in s4s:
        d = str(item.get("data") or "")
        if d < data_inicio or d > data_fim:
            continue
        if turno and str(item.get("turno") or "") != turno:
            continue
        if otimizadora and str(item.get("otimizadora") or "") != otimizadora:
            continue
        b = _normalizar_bitola(item.get("bitola"))
        if bitola_alvo and b != bitola_alvo:
            continue
        boards = int(item.get("boards") or 0)
        soma = float(item.get("soma_mm") or 0)
        total_boards += boards
        total_soma += soma
        acc = por_bitola.setdefault(b, {"boards": 0, "soma_mm": 0.0})
        acc["boards"] += boards
        acc["soma_mm"] += soma
        for medida, h in (item.get("histograma") or {}).items():
            ht = hist_total.setdefault(str(medida), {"boards": 0, "soma_mm": 0.0, "linhas": 0})
            ht["boards"] += int(h.get("boards") or 0)
            ht["soma_mm"] += float(h.get("soma_mm") or 0)
            ht["linhas"] += int(h.get("linhas") or 0)

    kpi = {
        "boards": total_boards,
        "soma_mm": round(total_soma, 2),
        "media_mm": round(total_soma / total_boards, 2) if total_boards else 0,
        "por_bitola": {
            b: {
                "boards": int(v["boards"]),
                "soma_mm": round(float(v["soma_mm"]), 2),
                "media_mm": round(float(v["soma_mm"]) / int(v["boards"]), 2) if int(v["boards"]) else 0,
            }
            for b, v in por_bitola.items()
        },
    }
    hist = []
    for medida, h in hist_total.items():
        boards = int(h["boards"])
        soma = float(h["soma_mm"])
        hist.append({
            "medida_mm": int(float(medida)),
            "label": str(int(float(medida))),
            "boards": boards,
            "linhas": int(h["linhas"]),
            "media_mm": round(soma / boards, 2) if boards else 0,
            "percentual_boards": round(boards / total_boards * 100, 2) if total_boards else 0,
        })
    hist.sort(key=lambda x: x["medida_mm"])
    return kpi, hist


def _calcular_metricas_cloud(registros: list[dict[str, Any]], s4s: list[dict[str, Any]], data_inicio: str, data_fim: str, turno: str = "", otimizadora: str = "", bitola: str = "", produto: str = "") -> dict[str, Any]:
    regs = _filtrar_registros(registros, data_inicio, data_fim, turno, otimizadora, bitola, produto)
    if not regs:
        return {"total_registros": 0, "volume_total": 0, "volume_util": 0, "volume_waste": 0, "top_produtos": [], "historico_diario": []}

    vols = [_volume(r) for r in regs]
    pecs = [_pecas(r) for r in regs]
    classes = [str(r.get("classe") or "") for r in regs]
    vol_total = sum(vols)
    mask_util = [c in CLASSES_UTEIS for c in classes]
    mask_waste = [c in CLASSES_WASTE for c in classes]
    mask_no = [c in CLASSES_NO for c in classes]
    vol_util = sum(v for v, ok in zip(vols, mask_util) if ok)
    vol_waste = sum(v for v, ok in zip(vols, mask_waste) if ok)
    vol_no = sum(v for v, ok in zip(vols, mask_no) if ok)
    pec_total = sum(pecs)
    pec_util = sum(p for p, ok in zip(pecs, mask_util) if ok)
    pec_no = sum(p for p, ok in zip(pecs, mask_no) if ok)

    def pct(a: float, b: float) -> float:
        return round(a / b * 100, 2) if b > 0 else 0

    por_classe: dict[str, dict[str, Any]] = {}
    por_turno: dict[str, dict[str, Any]] = {}
    por_otim: dict[str, dict[str, Any]] = {}
    produto_map: dict[tuple[str, str], dict[str, Any]] = {}
    diario_map: dict[str, dict[str, Any]] = {}
    turno_otim: dict[str, dict[str, dict[str, Any]]] = {}
    bitola_map: dict[str, dict[str, Any]] = {}

    blocks_pecas = 0
    blocks_metros = 0.0
    for r, v, p, cls in zip(regs, vols, pecs, classes):
        m = _metros(r)
        util = cls in CLASSES_UTEIS
        waste = cls in CLASSES_WASTE
        no = cls in CLASSES_NO
        t = str(r.get("turno") or "")
        o = str(r.get("otimizadora") or "")
        d = str(r.get("data") or "")
        b = str(r.get("bitola") or "")
        nome = str(r.get("nome_produto") or "")

        pc = por_classe.setdefault(cls, {"volume": 0.0, "pecas": 0, "metros": 0.0, "util": util, "waste": waste})
        pc["volume"] += v; pc["pecas"] += p; pc["metros"] += m

        pt = por_turno.setdefault(t, {"volume": 0.0, "volume_util": 0.0, "pecas": 0})
        pt["volume"] += v; pt["volume_util"] += v if util else 0; pt["pecas"] += p

        po = por_otim.setdefault(o, {"volume": 0.0, "volume_util": 0.0, "pecas": 0})
        po["volume"] += v; po["volume_util"] += v if util else 0; po["pecas"] += p

        pr = produto_map.setdefault((nome, cls), {"volume": 0.0, "pecas": 0, "metros": 0.0})
        pr["volume"] += v; pr["pecas"] += p; pr["metros"] += m

        dd = diario_map.setdefault(d, {"volume_total": 0.0, "volume_util": 0.0, "vol_waste": 0.0, "pecas": 0})
        dd["volume_total"] += v; dd["volume_util"] += v if util else 0; dd["vol_waste"] += v if waste else 0; dd["pecas"] += p

        to = turno_otim.setdefault(t, {}).setdefault(o, {"volume": 0.0, "volume_util": 0.0, "volume_no": 0.0, "pecas": 0})
        to["volume"] += v; to["volume_util"] += v if util else 0; to["volume_no"] += v if no else 0; to["pecas"] += p

        bm = bitola_map.setdefault(b, {"n": 0, "vt": 0.0, "vu": 0.0, "vmb": 0.0, "vno": 0.0, "cmp": 0.0, "pec": 0})
        bm["n"] += 1; bm["vt"] += v; bm["vu"] += v if util else 0; bm["vmb"] += v if cls == "MULTIBLOCK" else 0; bm["vno"] += v if no else 0
        if _mask_comprimento_blocks(r, produto):
            bm["cmp"] += m; bm["pec"] += p

        if _mask_comprimento_blocks(r, produto):
            blocks_pecas += p
            blocks_metros += m

    s4s_kpi, hist_s4s = _agrupar_s4s(s4s, data_inicio, data_fim, turno, otimizadora, bitola)
    s4s_por_bitola = s4s_kpi.pop("por_bitola", {})

    top_produtos = []
    for (nome, cls), v in sorted(produto_map.items(), key=lambda kv: kv[1]["volume"], reverse=True):
        top_produtos.append({
            "produto": nome, "classe": cls, "volume": round(v["volume"], 2), "pecas": int(v["pecas"]),
            "metros": round(v["metros"], 2),
            "comprimento_medio_mm": round(v["metros"] / v["pecas"] * 1000, 2) if v["pecas"] else 0,
            "perc_util": pct(v["volume"], vol_util),
        })

    historico_diario = []
    for d, v in sorted(diario_map.items()):
        historico_diario.append({
            "data_str": d, "volume_total": round(v["volume_total"], 2), "volume_util": round(v["volume_util"], 2),
            "vol_waste": round(v["vol_waste"], 2), "pecas": int(v["pecas"]),
            "aproveitamento": pct(v["volume_util"], v["volume_total"]),
        })

    comp_map: dict[str, dict[str, dict[str, float]]] = {}
    heat_map: dict[str, dict[str, dict[str, float]]] = {}
    for r, v, util in zip(regs, vols, mask_util):
        d = str(r.get("data") or "")
        o = str(r.get("otimizadora") or "")
        t = str(r.get("turno") or "")
        co = comp_map.setdefault(d, {}).setdefault(o, {"vt": 0.0, "vu": 0.0})
        co["vt"] += v; co["vu"] += v if util else 0
        ht = heat_map.setdefault(d, {}).setdefault(t, {"vt": 0.0, "vu": 0.0})
        ht["vt"] += v; ht["vu"] += v if util else 0

    comparativo_diario = []
    otims_unicas = sorted({str(r.get("otimizadora") or "") for r in regs if r.get("otimizadora")})
    for d in sorted(comp_map.keys(), reverse=True):
        linha: dict[str, Any] = {"data": d}
        for o in otims_unicas:
            valores = comp_map[d].get(o, {"vt": 0.0, "vu": 0.0})
            chave = o.replace(" ", "_").replace("/", "_")
            linha[f"{chave}_aprov"] = pct(valores["vu"], valores["vt"]) if valores["vt"] else None
            linha[f"{chave}_vol"] = round(valores["vt"], 2)
            linha[f"{chave}_util"] = round(valores["vu"], 2)
        if len(otims_unicas) == 2:
            k1 = otims_unicas[0].replace(" ", "_").replace("/", "_") + "_aprov"
            k2 = otims_unicas[1].replace(" ", "_").replace("/", "_") + "_aprov"
            a1, a2 = linha.get(k1), linha.get(k2)
            linha["diff"] = round(a1 - a2, 2) if a1 is not None and a2 is not None else None
        comparativo_diario.append(linha)

    mapa_celulas = {}
    for d, turnos in heat_map.items():
        for t, valores in turnos.items():
            mapa_celulas[f"{d}_{t}"] = pct(valores["vu"], valores["vt"]) if valores["vt"] > 0.1 else None

    por_classe_fmt = {
        k: {
            "volume": round(v["volume"], 2), "pecas": int(v["pecas"]), "metros": round(v["metros"], 2),
            "comprimento_medio_mm": round(v["metros"] / v["pecas"] * 1000, 2) if v["pecas"] else 0,
            "percentual": pct(v["volume"], vol_total), "util": bool(v["util"]), "waste": bool(v["waste"]),
        }
        for k, v in por_classe.items()
    }
    por_turno_fmt = {
        t: {
            "label": TURNOS_INFO.get(t, {}).get("label", f"Turno {t}"),
            "horario": TURNOS_INFO.get(t, {}).get("horario", ""),
            "volume": round(v["volume"], 2), "volume_util": round(v["volume_util"], 2),
            "aproveitamento": pct(v["volume_util"], v["volume"]), "pecas": int(v["pecas"]),
            "percentual": pct(v["volume"], vol_total),
        }
        for t, v in por_turno.items() if t
    }
    por_otim_fmt = {
        o: {
            "volume": round(v["volume"], 2), "volume_util": round(v["volume_util"], 2),
            "aproveitamento": pct(v["volume_util"], v["volume"]), "pecas": int(v["pecas"]),
            "percentual": pct(v["volume"], vol_total),
        }
        for o, v in sorted(por_otim.items())
    }
    turno_otim_fmt = {
        t: {
            o: {
                "volume": round(v["volume"], 2), "volume_util": round(v["volume_util"], 2),
                "volume_no": round(v["volume_no"], 2), "aproveitamento": pct(v["volume_util"], v["volume"]),
                "aprov_com_no": pct(v["volume_util"] + v["volume_no"], v["volume"]), "pecas": int(v["pecas"]),
            }
            for o, v in sorted(otims.items())
        }
        for t, otims in turno_otim.items()
    }
    analise_bitolas = []
    for b, v in bitola_map.items():
        if not b or v["n"] < 10 or v["vt"] <= 0:
            continue
        s4 = s4s_por_bitola.get(_normalizar_bitola(b), {"media_mm": 0, "boards": 0})
        analise_bitolas.append({
            "bitola": b, "volume_entrada": round(v["vt"], 2), "volume_producao": round(v["vu"], 2),
            "volume_refile": round(v["vmb"], 2), "volume_no": round(v["vno"], 2),
            "comprimento_medio_mm": round(v["cmp"] / v["pec"] * 1000, 2) if v["pec"] else 0,
            "comprimento_medio_blocks_mm": round(v["cmp"] / v["pec"] * 1000, 2) if v["pec"] else 0,
            "comprimento_medio_s4s_mm": s4.get("media_mm", 0), "boards_s4s_entrada": s4.get("boards", 0),
            "aproveitamento": pct(v["vu"], v["vt"]), "aprov_com_no": pct(v["vu"] + v["vno"], v["vt"]),
            "perc_util": pct(v["vu"], v["vt"]), "perc_waste": pct(v["vt"] - v["vu"], v["vt"]),
        })
    analise_bitolas.sort(key=lambda x: x["aproveitamento"], reverse=True)

    return {
        "total_registros": len(regs), "volume_total": round(vol_total, 2), "volume_util": round(vol_util, 2),
        "volume_waste": round(vol_waste, 2), "volume_no": round(vol_no, 2), "pecas_total": int(pec_total),
        "pecas_util": int(pec_util), "pecas_no": int(pec_no),
        "pecas_blocks": int(blocks_pecas), "metros_blocks": round(blocks_metros, 2),
        "boards_s4s_entrada": int(s4s_kpi["boards"]), "aproveitamento": pct(vol_util, vol_total),
        "aprov_com_no": pct(vol_util + vol_no, vol_total), "perc_waste": pct(vol_waste, vol_total),
        "perc_no": pct(vol_no, vol_total),
        "comprimento_medio_blocks_mm": round(blocks_metros / blocks_pecas * 1000, 2) if blocks_pecas else 0,
        "comprimento_medio_blocks_escopo": "cloud_detalhado_util_sem_waste_no_sem_fora_padrao",
        "comprimento_medio_s4s_entrada_mm": s4s_kpi["media_mm"],
        "soma_comprimento_s4s_entrada_mm": s4s_kpi["soma_mm"],
        "histograma_s4s": hist_s4s, "vol_outro": round(vol_total - vol_util - vol_waste, 2),
        "perc_outro": pct(vol_total - vol_util - vol_waste, vol_total),
        "por_classe": por_classe_fmt, "por_turno": por_turno_fmt, "por_otimizadora": por_otim_fmt,
        "top_produtos": top_produtos, "historico_diario": historico_diario,
        "analise_turno_otim": turno_otim_fmt, "comparativo_diario": comparativo_diario, "analise_bitolas": analise_bitolas,
        "mapa_calor": {"datas": sorted(diario_map), "turnos": ["A", "B", "C"], "celulas": mapa_celulas, "meta": 78.2},
        "fontes_dados": {"origem": "Firebase dados_detalhados", "modo": "calculo_na_api_render"},
    }


def _snapshot(force: bool = False) -> dict[str, Any]:
    now = time.time()
    if (
        not force
        and _cache["snapshot"] is not None
        and now - float(_cache["ts"]) <= CACHE_SECONDS
    ):
        return _cache["snapshot"]

    data = _firebase_get(SNAPSHOT_PATH)
    if not isinstance(data, dict):
        raise HTTPException(status_code=503, detail="Snapshot Firebase vazio ou invalido")

    _cache["snapshot"] = data
    _cache["ts"] = now
    return data


def _firebase_view_key(
    data_inicio: str | None,
    data_fim: str | None,
    turno: str,
    otimizadora: str,
    bitola: str,
    produto: str,
    snap: dict[str, Any],
) -> str:
    periodo = snap.get("periodo") or {}
    partes = {
        "data_inicio": data_inicio or periodo.get("data_inicio") or "",
        "data_fim": data_fim or periodo.get("data_fim") or "",
        "turno": turno or "",
        "otimizadora": otimizadora or "",
        "bitola": bitola or "",
        "produto": produto or "",
    }
    bruto = "|".join(f"{k}={v}" for k, v in partes.items())
    return (
        bruto.replace(".", "_")
        .replace("$", "_")
        .replace("#", "_")
        .replace("[", "_")
        .replace("]", "_")
        .replace("/", "_")
    )


def _with_runtime_fields(payload: dict[str, Any], snap: dict[str, Any]) -> dict[str, Any]:
    res = dict(payload or {})
    res["ultima_atualizacao"] = snap.get("ultima_atualizacao") or res.get("ultima_atualizacao")
    res["rede"] = snap.get("rede") or res.get("rede") or {}
    res["_api_render"] = {
        "versao": APP_VERSION,
        "origem": "render_free",
        "snapshot_gerado_em": snap.get("gerado_em"),
    }
    return res


@app.get("/", response_class=HTMLResponse)
def root() -> str:
    return """
    <html>
      <head><title>API Otimizadora Millpar</title></head>
      <body style="font-family:Arial,sans-serif;padding:24px">
        <h1>API Otimizadora Millpar</h1>
        <p>Status: operacional</p>
        <p>Endpoints principais: /api/status, /api/filtros, /api/dados</p>
      </body>
    </html>
    """


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "versao": APP_VERSION,
        "hora_servidor": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }


@app.get("/api/status")
def api_status(
    x_api_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _check_token(x_api_token, authorization)
    snap = _snapshot()
    return {
        "versao": APP_VERSION,
        "status": snap.get("status", "online"),
        "ultima_atualizacao": snap.get("ultima_atualizacao"),
        "gerado_em": snap.get("gerado_em"),
        "periodo": snap.get("periodo", {}),
        "rede": snap.get("rede", {}),
        "firebase_path": SNAPSHOT_PATH,
    }


@app.get("/api/filtros")
def api_filtros(
    data_inicio: str | None = Query(default=None),
    data_fim: str | None = Query(default=None),
    turno: str = Query(default=""),
    otimizadora: str = Query(default=""),
    bitola: str = Query(default=""),
    produto: str = Query(default=""),
    x_api_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _check_token(x_api_token, authorization)
    snap = _snapshot()
    data_inicio_calc = data_inicio or _periodo_padrao(snap)[0]
    data_fim_calc = data_fim or _periodo_padrao(snap)[1]
    registros, _ = _carregar_dados_detalhados(data_inicio_calc, data_fim_calc)
    if registros:
        regs = _filtrar_registros(registros, data_inicio_calc, data_fim_calc, turno, otimizadora, bitola, produto)
        return {
            "turnos": sorted({str(r.get("turno") or "") for r in regs if r.get("turno")}),
            "bitolas": sorted({str(r.get("bitola") or "") for r in regs if r.get("bitola")}),
            "produtos": sorted({str(r.get("nome_produto") or "") for r in regs if r.get("nome_produto")}),
            "otimizadoras": sorted({str(r.get("otimizadora") or "") for r in regs if r.get("otimizadora")}),
        }
    filtros = snap.get("filtros") or {}
    filtros.setdefault("turnos", ["A", "B", "C"])
    filtros.setdefault("bitolas", [])
    filtros.setdefault("produtos", [])
    filtros.setdefault("otimizadoras", [])
    return filtros


@app.get("/api/parametros")
def api_parametros(
    x_api_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _check_token(x_api_token, authorization)
    snap = _snapshot()
    return snap.get("parametros") or {}


@app.get("/api/dados")
def api_dados(
    data_inicio: str | None = Query(default=None),
    data_fim: str | None = Query(default=None),
    turno: str = Query(default=""),
    otimizadora: str = Query(default=""),
    bitola: str = Query(default=""),
    produto: str = Query(default=""),
    x_api_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _check_token(x_api_token, authorization)
    snap = _snapshot(force=True)
    data_inicio_calc = data_inicio or _periodo_padrao(snap)[0]
    data_fim_calc = data_fim or _periodo_padrao(snap)[1]
    registros, s4s = _carregar_dados_detalhados(data_inicio_calc, data_fim_calc)
    if registros:
        res = _calcular_metricas_cloud(
            registros, s4s, data_inicio_calc, data_fim_calc, turno, otimizadora, bitola, produto
        )
        res = _with_runtime_fields(res, snap)
        res["_origem_dados"] = "firebase_dados_detalhados"
        return res

    key = _firebase_view_key(data_inicio, data_fim, turno, otimizadora, bitola, produto, snap)
    views = snap.get("views") or {}
    if key in views:
        return _with_runtime_fields(views[key], snap)

    dados = snap.get("dashboard_dados") or {}
    res = _with_runtime_fields(dados, snap)
    res["_aviso_filtro"] = (
        "Filtro nao encontrado nas views do snapshot. "
        "Retornando painel geral publicado pelo coletor local."
    )
    res["_view_key_solicitada"] = key
    return res


@app.get("/api/historico-minuto")
def api_historico_minuto(
    data: str = Query(..., description="Data no formato YYYY-MM-DD"),
    x_api_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _check_token(x_api_token, authorization)
    historico = _firebase_get(f"historico_minuto/{data}") or {}
    return {"data": data, "historico": historico}


@app.get("/api/reprocessar")
def api_reprocessar(
    x_api_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _check_token(x_api_token, authorization)
    _snapshot(force=True)
    return {"sucesso": True, "origem": "render", "acao": "snapshot_recarregado"}


@app.get("/api/auth/ping")
def api_auth_ping() -> dict[str, Any]:
    _, env_valido = _auth_users_env()
    users = _auth_users()
    return {
        "ok": True,
        "origem": "render",
        "usuarios_configurados": bool(users),
        "auth_users_json_valido": env_valido,
        "banco_usuarios_configurado": bool(_auth_users_db_read()),
    }


@app.post("/api/auth/login")
def api_auth_login(payload: LoginPayload) -> dict[str, Any]:
    usuario = _normalizar_usuario(payload.usuario)
    _checar_limite_login(usuario)
    users = _auth_users()
    info = users.get(usuario) or {}
    senha_hash = info.get("senha_hash") if isinstance(info, dict) else info
    if not senha_hash or not _verify_password(payload.senha, str(senha_hash)):
        _registrar_falha_login(usuario)
        raise HTTPException(status_code=401, detail="Usuario ou senha invalidos")
    if isinstance(info, dict) and not bool(info.get("ativo", True)):
        raise HTTPException(status_code=403, detail="Usuario inativo ou aguardando aprovacao")
    _limpar_falhas_login(usuario)
    nome = str(info.get("nome") or usuario) if isinstance(info, dict) else usuario
    role = str(info.get("role") or "viewer") if isinstance(info, dict) else "viewer"
    db_users = _auth_users_db_read()
    if usuario in db_users:
        db_users[usuario]["ultimo_login"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        _auth_users_db_write(db_users)
    return {
        "ok": True,
        "usuario": nome,
        "role": role,
        "token": _assinar_token(usuario, nome, role),
        "expira_em_horas": AUTH_TOKEN_TTL_HOURS,
        "trocar_senha": bool(info.get("trocar_senha", False)) if isinstance(info, dict) else False,
    }


@app.post("/api/auth/solicitar-acesso")
def api_auth_solicitar_acesso(payload: SolicitarAcessoPayload) -> dict[str, Any]:
    usuario = _normalizar_usuario(payload.usuario)
    if not usuario:
        raise HTTPException(status_code=400, detail="Usuario obrigatorio")
    _validar_senha_forte(payload.senha)
    users = _auth_users()
    if usuario in users:
        raise HTTPException(status_code=409, detail="Usuario ja existe")
    db_users = _auth_users_db_read()
    agora = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    db_users[usuario] = {
        "nome": payload.nome or usuario,
        "role": "viewer",
        "senha_hash": _hash_password(payload.senha),
        "ativo": False,
        "pendente": True,
        "trocar_senha": False,
        "origem": "db",
        "criado_em": agora,
        "atualizado_em": agora,
    }
    _auth_users_db_write(db_users)
    return {"ok": True, "status": "pendente_aprovacao"}


@app.get("/api/auth/verificar")
def api_auth_verificar(
    x_auth_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    bearer = _extrair_bearer(authorization, x_auth_token)
    payload = _validar_token_sessao(bearer)
    if not payload:
        raise HTTPException(status_code=401, detail="Sessao invalida ou expirada")
    return {
        "ok": True,
        "usuario": payload.get("nome") or payload.get("sub"),
        "role": payload.get("role") or "viewer",
        "exp": payload.get("exp"),
    }


@app.post("/api/auth/alterar-senha")
def api_auth_alterar_senha(
    payload: AlterarSenhaPayload,
    x_auth_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    sessao = _require_auth(None, authorization, x_auth_token)
    usuario = str(sessao.get("sub") or "")
    db_users = _auth_users_db_read()
    info = db_users.get(usuario)
    if not isinstance(info, dict):
        raise HTTPException(status_code=400, detail="Senha deste usuario deve ser alterada pelo administrador")
    if not _verify_password(payload.senha_atual, str(info.get("senha_hash") or "")):
        raise HTTPException(status_code=401, detail="Senha atual invalida")
    _validar_senha_forte(payload.nova_senha)
    info["senha_hash"] = _hash_password(payload.nova_senha)
    info["trocar_senha"] = False
    info["atualizado_em"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    db_users[usuario] = info
    _auth_users_db_write(db_users)
    return {"ok": True}


@app.post("/api/auth/logout")
def api_auth_logout() -> dict[str, Any]:
    return {"ok": True}


@app.get("/api/admin/usuarios")
def api_admin_usuarios(
    x_api_token: str | None = Header(default=None),
    x_auth_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin(x_api_token, authorization, x_auth_token)
    users = _auth_users()
    return {"usuarios": [_public_user(usuario, info) for usuario, info in sorted(users.items())]}


@app.post("/api/admin/usuarios")
def api_admin_criar_usuario(
    payload: NovoUsuarioPayload,
    x_api_token: str | None = Header(default=None),
    x_auth_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    admin = _require_admin(x_api_token, authorization, x_auth_token)
    usuario = _normalizar_usuario(payload.usuario)
    if not usuario:
        raise HTTPException(status_code=400, detail="Usuario obrigatorio")
    _validar_senha_forte(payload.senha)
    role = _validar_role(payload.role)
    if usuario in _auth_users():
        raise HTTPException(status_code=409, detail="Usuario ja existe")
    db_users = _auth_users_db_read()
    agora = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    db_users[usuario] = {
        "nome": payload.nome or usuario,
        "role": role,
        "senha_hash": _hash_password(payload.senha),
        "ativo": bool(payload.ativo),
        "pendente": False,
        "trocar_senha": bool(payload.trocar_senha),
        "origem": "db",
        "criado_por": admin.get("sub"),
        "criado_em": agora,
        "atualizado_em": agora,
    }
    _auth_users_db_write(db_users)
    return {"ok": True, "usuario": _public_user(usuario, db_users[usuario])}


@app.patch("/api/admin/usuarios/{usuario}")
def api_admin_atualizar_usuario(
    usuario: str,
    payload: AtualizarUsuarioPayload,
    x_api_token: str | None = Header(default=None),
    x_auth_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin(x_api_token, authorization, x_auth_token)
    usuario_norm = _normalizar_usuario(usuario)
    db_users = _auth_users_db_read()
    info = db_users.get(usuario_norm)
    if not isinstance(info, dict):
        raise HTTPException(status_code=404, detail="Usuario nao encontrado no banco editavel")
    if payload.nome is not None:
        info["nome"] = payload.nome or usuario_norm
    if payload.role is not None:
        info["role"] = _validar_role(payload.role)
    if payload.ativo is not None:
        info["ativo"] = bool(payload.ativo)
    if payload.trocar_senha is not None:
        info["trocar_senha"] = bool(payload.trocar_senha)
    if bool(info.get("ativo", True)):
        info["pendente"] = False
    info["atualizado_em"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    db_users[usuario_norm] = info
    _auth_users_db_write(db_users)
    return {"ok": True, "usuario": _public_user(usuario_norm, info)}


@app.post("/api/admin/usuarios/{usuario}/resetar-senha")
def api_admin_resetar_senha(
    usuario: str,
    payload: ResetarSenhaPayload,
    x_api_token: str | None = Header(default=None),
    x_auth_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin(x_api_token, authorization, x_auth_token)
    usuario_norm = _normalizar_usuario(usuario)
    db_users = _auth_users_db_read()
    info = db_users.get(usuario_norm)
    if not isinstance(info, dict):
        raise HTTPException(status_code=404, detail="Usuario nao encontrado no banco editavel")
    _validar_senha_forte(payload.nova_senha)
    info["senha_hash"] = _hash_password(payload.nova_senha)
    info["trocar_senha"] = True
    info["atualizado_em"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    db_users[usuario_norm] = info
    _auth_users_db_write(db_users)
    return {"ok": True}


@app.get("/debug/snapshot-path")
def debug_snapshot_path(request: FastApiRequest) -> dict[str, Any]:
    token_configurado = bool(API_TOKEN)
    return {
        "firebase_base_url": FIREBASE_BASE_URL,
        "snapshot_path": SNAPSHOT_PATH,
        "cache_seconds": CACHE_SECONDS,
        "token_configurado": token_configurado,
        "allow_public_read": ALLOW_PUBLIC_READ,
        "auth_users_configurados": bool(_auth_users()),
        "firebase_verify_ssl": FIREBASE_VERIFY_SSL,
        "url_teste_dados": str(request.url_for("api_dados"))
        + "?"
        + urlencode({"data_inicio": "", "data_fim": ""}),
    }
