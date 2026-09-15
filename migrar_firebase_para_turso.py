import json
import os
import ssl
import time
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

import libsql


FIREBASE_BASE_URL = os.getenv(
    "FIREBASE_BASE_URL",
    "https://base-otimizadora-default-rtdb.firebaseio.com",
).rstrip("/")
FIREBASE_AUTH_TOKEN = os.getenv("FIREBASE_AUTH_TOKEN", "").strip()
FIREBASE_AUTH_PARAM = os.getenv("FIREBASE_AUTH_PARAM", "auth").strip() or "auth"
FIREBASE_VERIFY_SSL = os.getenv("FIREBASE_VERIFY_SSL", "true").strip().lower() not in {
    "0",
    "false",
    "nao",
    "no",
}
SNAPSHOT_PATH = os.getenv("SNAPSHOT_PATH", "snapshot").strip("/")
AUTH_USER_DB_PATH = os.getenv("AUTH_USER_DB_PATH", "auth/usuarios_app").strip("/")
TURSO_DATABASE_URL = os.getenv("TURSO_DATABASE_URL", "").strip()
TURSO_AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN", "").strip()
RETRY_TOTAL = int(os.getenv("TURSO_MIGRATION_RETRY_TOTAL", "4"))


def firebase_url(path: str) -> str:
    safe_path = "/".join(quote(p, safe="") for p in path.strip("/").split("/") if p)
    url = f"{FIREBASE_BASE_URL}/{safe_path}.json"
    if FIREBASE_AUTH_TOKEN:
        url += "?" + urlencode({FIREBASE_AUTH_PARAM: FIREBASE_AUTH_TOKEN})
    return url


def firebase_get(path: str):
    req = Request(firebase_url(path), headers={"Accept": "application/json"}, method="GET")
    context = None if FIREBASE_VERIFY_SSL else ssl._create_unverified_context()
    with urlopen(req, timeout=60, context=context) as resp:
        raw = resp.read().decode("utf-8")
    if not raw or raw == "null":
        return None
    return json.loads(raw)


def conectar_turso():
    return libsql.connect(database=TURSO_DATABASE_URL, auth_token=TURSO_AUTH_TOKEN)


def salvar_json(chave: str, payload) -> None:
    payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    ultimo_erro: Exception | None = None
    for tentativa in range(1, RETRY_TOTAL + 1):
        conn = conectar_turso()
        try:
            conn.execute(
                """
                INSERT INTO app_json_store (chave, payload, updated_at)
                VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                ON CONFLICT(chave) DO UPDATE SET
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                (chave, payload_json),
            )
            conn.commit()
            return
        except Exception as exc:
            ultimo_erro = exc
            espera = min(2 * tentativa, 8)
            print(f"  retry {tentativa}/{RETRY_TOTAL}: {chave} ({exc})")
            time.sleep(espera)
        finally:
            conn.close()
    raise RuntimeError(f"Falha ao gravar {chave}") from ultimo_erro


def criar_schema(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS app_json_store (
            chave TEXT PRIMARY KEY NOT NULL,
            payload TEXT NOT NULL CHECK (json_valid(payload)),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_app_json_store_updated_at
        ON app_json_store (updated_at)
        """
    )
    conn.commit()


def main() -> None:
    if not TURSO_DATABASE_URL or not TURSO_AUTH_TOKEN:
        raise SystemExit("Configure TURSO_DATABASE_URL e TURSO_AUTH_TOKEN antes de migrar.")

    itens = [
        SNAPSHOT_PATH,
        AUTH_USER_DB_PATH,
        "dados_detalhados",
        "historico_minuto",
    ]

    conn = conectar_turso()
    try:
        criar_schema(conn)
    finally:
        conn.close()

    try:
        for path in itens:
            print(f"Lendo Firebase: {path}")
            payload = firebase_get(path)
            if payload is None:
                print(f"  vazio: {path}")
                continue

            if path in {"dados_detalhados", "historico_minuto"} and isinstance(payload, dict):
                for subchave, valor in sorted(payload.items()):
                    chave = f"{path}/{subchave}"
                    salvar_json(chave, valor)
                    print(f"  gravado: {chave}")
            else:
                salvar_json(path, payload)
                print(f"  gravado: {path}")
    except KeyboardInterrupt:
        raise SystemExit("Migracao interrompida pelo usuario.")

    print("Migracao para Turso concluida.")


if __name__ == "__main__":
    main()
