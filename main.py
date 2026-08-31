import json
import os
import ssl
import time
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from fastapi import FastAPI, Header, HTTPException, Query, Request as FastApiRequest
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse


APP_VERSION = "render-free-piloto-0.1"
FIREBASE_BASE_URL = os.getenv(
    "FIREBASE_BASE_URL",
    "https://base-otimizadora-default-rtdb.firebaseio.com",
).rstrip("/")
SNAPSHOT_PATH = os.getenv("SNAPSHOT_PATH", "snapshot").strip("/")
API_TOKEN = os.getenv("API_TOKEN", "").strip()
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
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

_cache: dict[str, Any] = {"ts": 0.0, "snapshot": None}


def _check_token(x_api_token: str | None, authorization: str | None) -> None:
    if not API_TOKEN or ALLOW_PUBLIC_READ:
        return

    bearer = ""
    if authorization and authorization.lower().startswith("bearer "):
        bearer = authorization[7:].strip()

    if x_api_token != API_TOKEN and bearer != API_TOKEN:
        raise HTTPException(status_code=401, detail="Token invalido ou ausente")


def _firebase_get(path: str) -> Any:
    safe_path = "/".join(quote(p, safe="") for p in path.strip("/").split("/") if p)
    url = f"{FIREBASE_BASE_URL}/{safe_path}.json"
    req = Request(url, headers={"Accept": "application/json"})
    context = None if FIREBASE_VERIFY_SSL else ssl._create_unverified_context()
    with urlopen(req, timeout=20, context=context) as resp:
        raw = resp.read().decode("utf-8")
    if not raw or raw == "null":
        return None
    return json.loads(raw)


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
    x_api_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _check_token(x_api_token, authorization)
    snap = _snapshot()
    return snap.get("filtros") or {"bitolas": [], "produtos": [], "otimizadoras": []}


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
    return {"ok": True, "origem": "render"}


@app.get("/debug/snapshot-path")
def debug_snapshot_path(request: FastApiRequest) -> dict[str, Any]:
    token_configurado = bool(API_TOKEN)
    return {
        "firebase_base_url": FIREBASE_BASE_URL,
        "snapshot_path": SNAPSHOT_PATH,
        "cache_seconds": CACHE_SECONDS,
        "token_configurado": token_configurado,
        "allow_public_read": ALLOW_PUBLIC_READ,
        "firebase_verify_ssl": FIREBASE_VERIFY_SSL,
        "url_teste_dados": str(request.url_for("api_dados"))
        + "?"
        + urlencode({"data_inicio": "", "data_fim": ""}),
    }
