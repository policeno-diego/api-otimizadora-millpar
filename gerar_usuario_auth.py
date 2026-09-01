import getpass
import hashlib
import json
import secrets


def gerar_hash_senha(senha: str, iteracoes: int = 210_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, iteracoes)
    return f"pbkdf2_sha256${iteracoes}${salt.hex()}${digest.hex()}"


def main() -> None:
    usuario = input("Usuario: ").strip().lower()
    nome = input("Nome exibido: ").strip() or usuario
    role = input("Perfil [viewer/admin]: ").strip().lower() or "viewer"
    senha = getpass.getpass("Senha: ")
    confirmar = getpass.getpass("Confirmar senha: ")
    if senha != confirmar:
        raise SystemExit("Senhas diferentes. Nada gerado.")
    if len(senha) < 8:
        raise SystemExit("Use senha com pelo menos 8 caracteres.")

    users = {
        usuario: {
            "nome": nome,
            "role": role,
            "senha_hash": gerar_hash_senha(senha),
        }
    }
    print("\nCole este valor na variavel AUTH_USERS_JSON do Render:\n")
    print(json.dumps(users, ensure_ascii=False, separators=(",", ":")))
    print("\nSe precisar de um AUTH_TOKEN_SECRET manual, use:\n")
    print(secrets.token_urlsafe(48))


if __name__ == "__main__":
    main()
