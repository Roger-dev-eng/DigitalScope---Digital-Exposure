# DigitalScope - Digital Exposure

DigitalScope é um dashboard de exposição digital pessoal focado em evidências e privacidade. A ideia é analisar um e-mail e mostrar quais sinais de exposição existem na internet, com base em vazamentos conhecidos, serviços associados e explicações claras sobre confiança e origem dos dados.

## Objetivo

O produto deve responder perguntas como:

- Este e-mail apareceu em vazamentos conhecidos?
- Quais categorias de dados foram expostas?
- Há indícios de contas associadas a serviços?
- O sistema está apresentando conclusões baseadas em evidência ou em suposições?

## Princípios

- Privacidade por design
- Sem coleta de senhas
- Sem armazenamento de e-mail bruto quando puder ser evitado
- Evidências e confiança explícitas
- MVP enxuto, sem “score de segurança” inventado

## MVP inicial

A primeira versão vai focar em:

1. Validação do e-mail
2. Consulta de vazamentos por e-mail
3. Resumo de exposição
4. Dashboard simples com resultado estruturado

## Stack inicial

- Python
- FastAPI
- Pydantic
- pytest

## Como executar

```bash
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

A API expõe o endpoint:

```http
GET /api/exposure?email=user@example.com
```

## Provider de vazamentos

O projeto usa o XposedOrNot, uma API gratuita que não exige chave para a consulta básica. O arquivo `.env` local já está ignorado pelo Git.

```env
BREACH_PROVIDER=xposedornot
```

Para desenvolvimento sem chamadas externas, use `BREACH_PROVIDER=local`. Não inclua dados sensíveis ou credenciais em arquivos versionados.

## Estrutura esperada

```text
app/
  __init__.py
  main.py

tests/
  test_exposure_api.py
```

