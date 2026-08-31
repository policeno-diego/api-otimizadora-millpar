# API Otimizadora Millpar no Render Free

Esta pasta contem uma API FastAPI para publicar no Render Free e servir o APK da Otimizadora.

## Arquitetura do teste

```text
PC da Otimizadora -> publicar_snapshot_firebase_otm.py -> Firebase RTDB
Render Free -> api_render/main.py -> le o Firebase por HTTPS
APK Android -> chama a API Render nos endpoints /api/*
```

O Render nao deve guardar arquivo local, porque o plano Free tem filesystem temporario. O historico continua no Firebase.

## Endpoints

- `GET /health`
- `GET /api/status`
- `GET /api/filtros`
- `GET /api/parametros`
- `GET /api/dados`
- `GET /api/historico-minuto?data=YYYY-MM-DD`

## Variaveis no Render

Obrigatorias/recomendadas:

```text
FIREBASE_BASE_URL=https://base-otimizadora-default-rtdb.firebaseio.com
SNAPSHOT_PATH=snapshot
CACHE_SECONDS=10
FIREBASE_VERIFY_SSL=true
ALLOW_PUBLIC_READ=true
API_TOKEN=<preencher depois para fechar o acesso>
```

Para o primeiro teste, `ALLOW_PUBLIC_READ=true` facilita validar no celular. Depois, para fechar acesso:

```text
ALLOW_PUBLIC_READ=false
API_TOKEN=<token forte>
```

Nesse caso o APK precisa enviar o mesmo token no header `X-API-Token`.

Observacao local: neste PC o Python pode falhar na verificacao SSL do Firebase por certificado corporativo. Para teste local somente, use `FIREBASE_VERIFY_SSL=false`. No Render manter `true`.

## Como subir no Render

1. Enviar esta pasta para um repositorio GitHub.
2. Render Dashboard -> New -> Web Service.
3. Selecionar o repositorio.
4. Root Directory: `01_PROJETOS/APK_Otimizadora_Firebase_Tempo_Real/api_render`.
5. Build Command: `pip install -r requirements.txt`.
6. Start Command: `uvicorn main:app --host 0.0.0.0 --port $PORT`.
7. Plan: Free.
8. Configurar as variaveis de ambiente acima.

## Limitacoes conhecidas do piloto

- O Render Free dorme apos periodo sem acesso. A primeira abertura pode demorar cerca de 1 minuto.
- Os filtros so ficam 100% iguais ao site quando o Firebase possuir a view calculada para aquele filtro.
- Para a versao definitiva, o ideal e a API calcular sob demanda em cima de dados detalhados no banco.
