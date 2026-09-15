# Modelo Gratuito Turso - Otimizadora Millpar

## Objetivo

Usar Turso como banco gratuito para o piloto do APK da Otimizadora, mantendo a API como camada de seguranca.

## Arquitetura

```text
PC publicador Otimizadora
  -> API FastAPI
    -> Turso
      -> APK / App Desktop / Dashboard
```

O APK nao acessa o Turso direto. Ele acessa somente a API.

## Por que Turso

- Plano gratuito com mais folga para piloto que Firebase/Supabase/Neon em muitos cenarios.
- Banco SQL baseado em SQLite/libSQL.
- Acesso remoto por URL + token.
- Simples para migracao inicial usando uma tabela JSON.

## Criacao da conta e banco

1. Entrar em `https://turso.tech`.
2. Criar conta.
3. Criar um banco chamado `otimizadora-teste`.
4. Copiar a URL do banco.
5. Criar/copiar o token de acesso do banco.

Variaveis que precisamos configurar:

```text
TURSO_DATABASE_URL=libsql://...
TURSO_AUTH_TOKEN=...
DATA_BACKEND=turso
```

## Schema

Rodar o conteudo de `turso_schema.sql` no banco Turso.

Tabela usada no piloto:

```text
app_json_store
  chave      -> caminho logico do dado, exemplo snapshot ou dados_detalhados/2026-09-15
  payload    -> JSON completo
  updated_at -> data/hora da ultima gravacao
```

## Migracao inicial

Com as variaveis `TURSO_DATABASE_URL` e `TURSO_AUTH_TOKEN` configuradas no ambiente:

```powershell
py migrar_firebase_para_turso.py
```

O script copia:

- `snapshot`
- `auth/usuarios_app`
- `dados_detalhados`
- `historico_minuto`

Nada e apagado do Firebase.

## Corte seguro

1. Criar Turso.
2. Rodar `turso_schema.sql`.
3. Rodar `migrar_firebase_para_turso.py`.
4. Subir API em teste com `DATA_BACKEND=turso`.
5. Testar login, status, filtros, dados e historico.
6. Se estiver correto, trocar producao para `DATA_BACKEND=turso`.
7. Manter Firebase por alguns dias como backup.

## Proximo refinamento

Este modelo usa JSON para migrar rapido sem quebrar o APK. Depois, podemos criar tabelas normalizadas para:

- producao por dia;
- producao por mes;
- no painel;
- perdas;
- turnos;
- otimizadora;
- logs do publicador.

Isso melhora performance e facilita relatorios.
