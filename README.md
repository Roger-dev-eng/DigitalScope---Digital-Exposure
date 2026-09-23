# DigitalScope - Digital Exposure

Dashboard de exposição digital pessoal focado em evidências, privacidade e explicações claras sobre vazamentos associados a um e-mail.
## Live Demo

https://digitalscope-api.jollysmoke-a1a46fbe.brazilsouth.azurecontainerapps.io
## Índice

- [Visão geral](#visao-geral)
- [Princípios de privacidade](#principios-de-privacidade)
- [Funcionalidades atuais](#funcionalidades-atuais)
- [Tecnologias](#tecnologias)
- [Configuração](#configuracao)
- [Como executar](#como-executar)
- [Como usar](#como-usar)
- [API](#api)
- [Deploy na Azure](#deploy-na-azure)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Testes](#testes)
- [Limitações conhecidas](#limitacoes-conhecidas)
- [Próximos passos](#proximos-passos)

<a id="visao-geral"></a>
## Visão geral

O DigitalScope consulta um e-mail e apresenta sinais de exposição encontrados em bases públicas. O sistema mostra os incidentes, a data ou período informado, os tipos de dados e a fonte da consulta. O projeto não afirma que uma conta foi invadida nem exibe dados privados recuperados de vazamentos.

<a id="principios-de-privacidade"></a>
## Princípios de privacidade

O DigitalScope segue os seguintes princípios de privacidade:

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


## Deploy na Azure


O projeto utiliza **GitHub Actions** para realizar o processo de CI/CD e publicar automaticamente a aplicação no **Microsoft Azure** sempre que ocorre um `push` na branch `main` ou quando o workflow é executado manualmente.

### Fluxo de Deploy

O workflow `.github/workflows/deploy.yml` realiza as seguintes etapas:

1. **Checkout do código**

   * Utiliza `actions/checkout@v4` para obter o código-fonte do repositório.

2. **Autenticação no Azure**

   * Utiliza `azure/login@v2` com **OpenID Connect (OIDC)**.
   * A autenticação utiliza `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` e `AZURE_SUBSCRIPTION_ID`.
   * O acesso é realizado pela identidade `github-digitalscope-deploy`, evitando o armazenamento de credenciais tradicionais no GitHub.

3. **Provisionamento da infraestrutura**

   * Utiliza **Azure CLI** e **Bicep** para criar ou atualizar os recursos necessários.
   * O template `infra/main.bicep` é executado através de:
     `az deployment group create`.
   * Os parâmetros da aplicação são definidos por meio das variáveis do ambiente de produção.

4. **Build e publicação da imagem**

   * Utiliza `az acr build` para construir a imagem Docker diretamente no **Azure Container Registry (ACR)**.
   * A imagem é versionada utilizando o SHA do commit do GitHub:
     `digitalscope:${{ github.sha }}`.

5. **Deploy no Azure Container Apps**

   * O workflow obtém o endereço do ACR e executa o template `infra/container-app.bicep`.
   * A imagem correspondente ao commit atual é utilizada para atualizar a aplicação.
   * O parâmetro `breachProvider` é configurado como `xposedornot`.

6. **Exibição do endereço da aplicação**

   * Ao final do processo, o workflow consulta o FQDN do Azure Container App utilizando `az containerapp show`, permitindo identificar o endereço público da aplicação.

### Arquitetura do Deploy

```text
GitHub Repository
       │
       │ push → main
       ▼
GitHub Actions
       │
       │ OIDC
       ▼
Azure
       │
       ├── Resource Group
       │      └── rg-digitalscope-prod
       │
       ├── Bicep
       │      ├── main.bicep
       │      └── container-app.bicep
       │
       ├── Azure Container Registry
       │      └── digitalscope:<commit-sha>
       │
       └── Azure Container Apps
              └── DigitalScope
```

A infraestrutura é definida como código por meio do **Bicep**, enquanto o GitHub Actions automatiza autenticação, provisionamento, build da imagem e atualização da aplicação em produção.

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

<a id="limitacoes"></a>
## Limitações

- O XposedOrNot pode fornecer categorias e anos de forma agregada, sem data individual para cada incidente.
- O sistema não confirma quais campos específicos de um usuário foram efetivamente acessados.
- O modo local não representa dados reais.
- O cache atual existe apenas na memória do processo.
- Ainda não há autenticação, histórico persistente ou monitoramento automático.

<a id="proximos-passos"></a>
## Próximos passos

- Melhorar a precisão dos metadados individuais quando o provider disponibilizar esse nível de detalhe.
- Adicionar exportação segura do resultado.
- Incluir a funcionalidade de ver como seus dados eram usados, com base nos termos de serviços e políticas de privacidade da fonte do vazamento.
- Avaliar persistência somente após definir retenção e exclusão de dados.
