# DigitalScope - Digital Exposure

Dashboard de exposição digital pessoal focado em evidências, privacidade e explicações claras sobre vazamentos associados a um e-mail.

## Índice

- [Visão geral](#visao-geral)
- [Princípios de privacidade](#principios-de-privacidade)
- [Funcionalidades atuais](#funcionalidades-atuais)
- [Tecnologias](#tecnologias)
- [Configuração](#configuracao)
- [Como executar](#como-executar)
- [Como usar](#como-usar)
- [API](#api)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Testes](#testes)
- [Limitações conhecidas](#limitacoes-conhecidas)
- [Próximos passos](#proximos-passos)

<a id="visao-geral"></a>
## Visão geral

O DigitalScope consulta um e-mail e apresenta sinais de exposição encontrados em bases públicas. O sistema mostra os incidentes, a data ou período informado, os tipos de dados e a fonte da consulta.

O projeto não afirma que uma conta foi invadida nem exibe dados privados recuperados de vazamentos.

<a id="principios-de-privacidade"></a>
## Princípios de privacidade

- Não solicitar ou armazenar senhas.
- Não exibir o conteúdo de dados vazados.
- Não armazenar e-mails consultados em banco de dados.
- Usar cache temporário com identificador derivado do e-mail.
- Informar a fonte dos resultados.
- Diferenciar evidência retornada pelo provider de interpretação do sistema.
- Evitar um “score de segurança” numérico sem fundamentação.

<a id="funcionalidades-atuais"></a>
## Funcionalidades atuais

- Validação de e-mail.
- Consulta pelo XposedOrNot.
- Modo local para desenvolvimento sem chamadas externas.
- Resumo de incidentes e severidade explicável.
- Alertas para credenciais, dados pessoais e exposição recorrente.
- Recomendações proporcionais à quantidade e ao tipo de exposição.
- Cartões de incidentes com origem, data, dados vazados e fonte.
- Tooltip para os tipos de dados, reduzindo poluição visual.
- Paginação de cinco incidentes por página.
- Cache temporário em memória.
- Rate limiting de 30 consultas por minuto por cliente.
- Headers básicos de segurança.
- Tratamento de falhas do provider com respostas `429` e `502`.

<a id="tecnologias"></a>
## Tecnologias

- Python 3.14+
- FastAPI
- Pydantic
- HTTPX
- python-dotenv
- pytest

<a id="configuracao"></a>
## Configuração

O arquivo `.env` é local e está protegido pelo `.gitignore`.

### Provider XposedOrNot

Configuração padrão para consultar a API gratuita:

```env
BREACH_PROVIDER=xposedornot
```

### Provider local

Para executar sem chamadas externas:

```env
BREACH_PROVIDER=local
```

Nesse modo, a consulta retorna uma lista vazia. Providers simulados também podem ser injetados nos testes através de `create_app(breach_provider=...)`.

Nunca adicione chaves, tokens ou dados pessoais ao GitHub.

<a id="como-executar"></a>
## Como executar

Instale as dependências:

```powershell
python -m pip install -r requirements.txt
```

Inicie o servidor:

```powershell
python -m uvicorn app.main:app --reload
```

Abra no navegador:

```text
http://127.0.0.1:8000/
```

<a id="como-usar"></a>
## Como usar

1. Digite um e-mail válido.
2. Clique em **Analisar**.
3. Aguarde a consulta ao provider.
4. Confira o resumo, os alertas e as recomendações.
5. Navegue pelos incidentes usando a paginação.
6. Passe o mouse sobre **Dados vazados** para ver as categorias.

<a id="api"></a>
## API

Endpoint de consulta:

```http
GET /api/exposure?email=user@example.com
```

Exemplo de resposta:

```json
{
  "email": "user@example.com",
  "breaches": [
    {
      "name": "ExampleBreach",
      "date": "2024",
      "data_classes": ["Email addresses", "Passwords"],
      "source": "XposedOrNot"
    }
  ],
  "alerts": [],
  "recommendations": ["Continuar monitorando este e-mail para novos vazamentos"],
  "summary": {
    "breach_count": 1,
    "severity": "low",
    "exposed_data_types": ["Email addresses", "Passwords"]
  }
}
```

Respostas de erro relevantes:

- `422`: e-mail inválido.
- `429`: limite local ou limite do provider atingido.
- `502`: provider externo indisponível ou recusou a consulta.

<a id="estrutura-do-projeto"></a>
## Estrutura do projeto

```text
app/
  __init__.py
  main.py
  breach_service.py
  static/
    dashboard.js
    styles.css
  templates/
    dashboard.html
tests/
  test_exposure_api.py
.env
.gitignore
requirements.txt
README.md
```

<a id="testes"></a>
## Testes

Execute a suíte com:

```powershell
python -m pytest -q
```

Os testes cobrem:

- validação do e-mail;
- normalização de dados;
- provider XposedOrNot simulado;
- provider local;
- cache;
- erros `429` e `502`;
- análise de severidade;
- alertas e recomendações;
- rate limiting;
- headers de segurança;
- entrega dos arquivos estáticos.

<a id="limitacoes-conhecidas"></a>
## Limitações conhecidas

- O XposedOrNot pode fornecer categorias e anos de forma agregada, sem data individual para cada incidente.
- O sistema não confirma quais campos específicos de um usuário foram efetivamente acessados.
- O modo local não representa dados reais.
- O cache atual existe apenas na memória do processo.
- Ainda não há autenticação, histórico persistente ou monitoramento automático.

<a id="proximos-passos"></a>
## Próximos passos

- Melhorar a precisão dos metadados individuais quando o provider disponibilizar esse nível de detalhe.
- Adicionar exportação segura do resultado.
- Criar autenticação caso o histórico seja implementado.
- Avaliar persistência somente após definir retenção e exclusão de dados.

