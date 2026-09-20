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

## Provider opcional de vazamentos

Por padrão, o projeto não consulta serviços externos. Para habilitar dados reais do Have I Been Pwned, configure a chave da API apenas no ambiente local:

O arquivo `.env` local já está ignorado pelo Git. Preencha a variável nesse arquivo sem adicioná-lo ao repositório.

```powershell
$env:HIBP_API_KEY = "sua-chave-aqui"
python -m uvicorn app.main:app --reload
```

Não inclua a chave em arquivos versionados ou no GitHub. Sem `HIBP_API_KEY`, o sistema mantém o provider vazio e continua funcionando para desenvolvimento e testes.

## Estrutura esperada

```text
app/
  __init__.py
  main.py

tests/
  test_exposure_api.py
```

