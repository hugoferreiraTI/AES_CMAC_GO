[English](README.md) | Português

# AES-128 CMAC em Go

Biblioteca pequena e reutilizável para gerar e verificar **AES-128 CMAC conforme
[a RFC 4493](https://www.rfc-editor.org/rfc/rfc4493.html)**. CMAC é um código de
autenticação de mensagem baseado em uma cifra de bloco simétrica, especificado
no [NIST SP 800-38B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf).
Ele fornece autenticidade e integridade, **não confidencialidade**: não
criptografa nem esconde a mensagem. Quem conhece a chave compartilhada pode gerar
MACs válidos.

## Requisitos e escopo

- Go 1.22 ou superior. Em produção, use uma versão com as correções de segurança
  aplicáveis.
- Apenas AES-128: chave de 16 bytes e MAC completo de 16 bytes, sem truncamento.
- A biblioteca em `cmac/` usa somente a standard library do Go, incluindo
  `crypto/aes`. O CLI de exemplo também usa `github.com/joho/godotenv` para
  carregar sua configuração local; a biblioteca não depende desse carregador.
- A biblioteca não lê variáveis de ambiente, arquivos ou `.env`. A aplicação
  consumidora obtém a chave e a passa à API.

## API pública

Importe `github.com/hugoferreiraTI/AES_CMAC_Go/cmac`:

```go
func Generate(keyHex, message string) (string, error)
func Verify(keyHex, message, tagHex string) (bool, error)
```

| Valor | Formato |
| --- | --- |
| Chave | Exatamente 32 caracteres hexadecimais, representando uma chave AES-128 de 16 bytes |
| Mensagem | String Go; seus bytes exatos são autenticados |
| MAC gerado | 32 caracteres hexadecimais minúsculos, representando 16 bytes |
| MAC recebido | Exatamente 32 caracteres hexadecimais, representando 16 bytes |

Chaves e MACs recebidos aceitam hexadecimal em maiúsculas e minúsculas. Prefixos
como `0x`, espaços, caracteres inválidos, chaves AES-192/AES-256 e MACs truncados
são rejeitados. Aceitar apenas AES-128 e MACs completos é uma decisão de escopo.

`Generate` retorna string vazia e erro para uma chave inválida. `Verify` retorna
`false` e erro para chave ou MAC malformado, `false, nil` para um MAC bem formado
que não corresponde à mensagem e à chave, e `true, nil` para um MAC válido.
Os tamanhos da chave e do MAC são validados antes do decode hexadecimal,
limitando o trabalho do decoder. Os erros não incluem a chave nem caracteres
retornados pelo decoder da chave.

## Bytes exatos da mensagem

A API usa `[]byte(message)` sem normalização, remoção de espaços, conversão de
caracteres ou decode hexadecimal automático. Textos UTF-8 usam seus bytes UTF-8,
mas strings Go também podem conter bytes binários arbitrários, que são
preservados. Espaços, bytes NUL, acentos e quebras de linha participam do MAC.
`\n` difere de `\r\n`; formas Unicode compostas e decompostas mantêm seus
próprios bytes.

Por exemplo, `"6bc1bee22e409f96e93d7e117393172a"` é uma mensagem de texto de 32
bytes. Ela é diferente dos 16 bytes representados pelo hexadecimal. Para
autenticar os bytes representados, a aplicação deve chamar `hex.DecodeString`,
tratar seu erro e passar `string(decoded)` à API.

## Instalação

O endereço definido do módulo é `github.com/hugoferreiraTI/AES_CMAC_Go`. Quando
o conteúdo do repositório estiver disponível nesse endereço, adicione o pacote
ao módulo consumidor com:

```sh
go get github.com/hugoferreiraTI/AES_CMAC_Go/cmac
```

A disponibilidade remota não foi verificada nesta preparação. O comando
documenta o endereço definido, sem pressupor uma tag ou release publicada.

### Desenvolvimento com uma cópia local

Para testar alterações locais ainda não publicadas, adicione o import ao código
da aplicação consumidora e execute estes comandos no módulo dela. Ajuste
`../AES_go` para o caminho da cópia local:

```sh
go mod edit -replace=github.com/hugoferreiraTI/AES_CMAC_Go=../AES_go
go mod tidy
```

O `replace` se aplica somente a esse consumidor. Para voltar à resolução remota:

```sh
go mod edit -dropreplace=github.com/hugoferreiraTI/AES_CMAC_Go
go mod tidy
```

## Exemplo com Generate e Verify

O exemplo pertence à aplicação consumidora. Ele obtém a chave de uma variável
de ambiente, chama `Generate` e chama `Verify`, tratando erros e também um MAC
com formato válido que falhe na verificação. Em uma integração, use a mensagem
e o MAC realmente recebidos.

```go
package main

import (
    "fmt"
    "os"

    "github.com/hugoferreiraTI/AES_CMAC_Go/cmac"
)

func main() {
    keyHex := os.Getenv("AES_CMAC_KEY")
    message := "Hello, world!"

    tagHex, err := cmac.Generate(keyHex, message)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    fmt.Println("MAC:", tagHex)

    // In a real application, replace this with the received MAC.
    receivedTagHex := tagHex
    valid, err := cmac.Verify(keyHex, message, receivedTagHex)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    if !valid {
        fmt.Fprintln(os.Stderr, "Invalid MAC")
        os.Exit(1)
    }
    fmt.Println("MAC valid")
}
```

## Ambiente e CLI

Para demonstrações locais, defina uma chave **apenas de exemplo**:

```sh
# Public example key only. Never use this value as a production secret.
export AES_CMAC_KEY=00112233445566778899aabbccddeeff
```

Mantenha chaves AES reais fora dos logs e do controle de versão. Em produção,
obtenha a chave de variáveis de ambiente, gerenciadores de segredos ou
configuração equivalente. Use `.env` somente no desenvolvimento local.

A entrada do CLI é `main()` em `cmd/cmac/main.go`. O CLI atual exige a existência
de `config/.env` e o carrega com `godotenv.Load`; variáveis de ambiente já
definidas têm precedência. Na raiz do repositório, crie o arquivo somente se
ele ainda não existir e execute o exemplo:

```sh
test -f config/.env || cp config/.env.example config/.env
go run ./cmd/cmac -message "Hello, world!"
```

O modelo contém uma chave deliberadamente pública de exemplo, nunca um segredo
de produção. O CLI imprime o MAC hexadecimal e, em seguida, o resultado da
verificação. A flag `-message` autentica os bytes exatos da string fornecida.
A mensagem padrão de exemplo é `Payment 2590|sale=42`. A biblioteca é independente
desse CLI e de sua exigência de arquivo. Consulte os
[detalhes de configuração](config/README.md).

## Estrutura do projeto e correspondência com a RFC

```text
AES_go/
├── cmd/cmac/main.go        # CLI entry point: main()
├── cmac/
│   ├── cmac.go             # Public API: Generate and Verify
│   ├── core.go             # Internal byte-oriented CMAC core
│   ├── subkeys.go          # K1 and K2 generation
│   ├── cmac_test.go        # External public API tests
│   └── core_test.go        # RFC vectors and internal tests
├── config/
│   ├── .env.example        # Public example configuration
│   └── README.md           # CLI configuration instructions
├── .gitignore
├── go.mod
├── go.sum
├── LICENSE
├── README.md               # English documentation
└── README.pt-BR.md          # Brazilian Portuguese documentation
```

| Arquivo | Responsabilidade | Seção da RFC 4493 |
| --- | --- | --- |
| `cmac/cmac.go` | API string/hexadecimal, validação e verificação do MAC | 2.5 |
| `cmac/core.go` | Núcleo em bytes, XOR, padding e encadeamento | 2.1 e 2.4 |
| `cmac/subkeys.go` | `L = AES(K, 0)`, shifts e K1/K2 com Rb `0x87` | 2.1 e 2.3 |
| `cmac/core_test.go` | Vetores oficiais, subchaves e limites de bloco | 4 |
| `cmac/cmac_test.go` | API pública, validações e preservação dos bytes | 2.5 e 4 |

O núcleo usa blocos de 16 bytes e estado inicial zerado. O último bloco completo
recebe XOR com K1. Um bloco incompleto, incluindo a mensagem vazia, recebe
`0x80` seguido de zeros e XOR com K2. O resultado é um MAC completo de 128 bits.
Não são necessárias interfaces próprias ou structs CMAC; a geração de subchaves
usa a interface `cipher.Block` da standard library.

## Orientações de segurança

- CMAC autentica os dados; não os criptografa nem oferece confidencialidade.
  Quem possui a chave pode gerar MACs válidos.
- Provisione chaves de 16 bytes na aplicação consumidora usando
  [`crypto/rand.Read`](https://pkg.go.dev/crypto/rand#Read), tratando erros.
  Mantenha chaves e subchaves secretas e use uma chave exclusiva para CMAC,
  conforme as [seções 5.2 e 5.3 do NIST SP 800-38B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf#page=10).
  Nunca registre ou versione chaves reais. Não use senhas diretamente como chaves
  nem reutilize chaves públicas de testes/exemplos como segredos de produção.
- Planeje a rotação conforme o volume de uso e os requisitos de segurança da
  aplicação, contabilizando todas as instâncias. Consulte o
  [apêndice B do NIST SP 800-38B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf#page=18).
  A biblioteca não impõe um limite universal nem controla o uso da chave.
- CMAC não impede replay automaticamente. Inclua um contador ou nonce **na
  mensagem autenticada** e controle sua reutilização ao aceitar mensagens.
  Consulte o [apêndice C do NIST SP 800-38B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf#page=19).
- Limite tamanhos de mensagens, volume de requisições e tentativas de verificação
  inválidas na aplicação consumidora. A rejeição antecipada de chaves/MACs
  grandes não substitui esses limites.
- Em produção, prefira variáveis de ambiente ou gerenciadores de segredos.
  Arquivos `.env` são configuração de desenvolvimento local e não uma exigência
  da biblioteca. Mantenha-os fora do controle de versão.

`Verify` compara os dois MACs decodificados de 16 bytes com
[`crypto/subtle.ConstantTimeCompare`](https://pkg.go.dev/crypto/subtle#ConstantTimeCompare),
cujo tempo independe do conteúdo para comprimentos iguais. Isso não torna toda
a operação universalmente constante: o tempo do AES depende da implementação
e da plataforma, conforme a documentação de [`crypto/aes`](https://pkg.go.dev/crypto/aes).

## Testes

Execute na raiz do repositório:

```sh
go test -v ./...
go test -race -cover ./...
go vet ./...
go test -v -run TestRFC4493 ./...
```

Os quatro vetores oficiais da RFC 4493 são testados tanto pelo núcleo interno
quanto pela API pública. As mensagens hexadecimais dos vetores são decodificadas
para bytes antes de serem convertidas em strings nos testes da API pública.
Os testes verbosos da RFC usam `t.Logf` para mostrar o caso, o tamanho da mensagem,
o MAC calculado e o esperado. Os testes de subchaves mostram também L, K1 e K2.

| Vetor oficial | Mensagem em bytes | MAC esperado |
| --- | ---: | --- |
| 1 | 0 | `bb1d6929e95937287fa37d129b756746` |
| 2 | 16 | `070a16b46b4d4144f79bdd9dd04a287c` |
| 3 | 40 | `dfa66747de9ae63030ca32611497c827` |
| 4 | 64 | `51f0bebf7e3b9d92fc49741779363cfe` |

Os demais testes cobrem limites de bloco, formato da saída, determinismo, UTF-8
composto e decomposto, NUL, espaços, quebras de linha, texto hexadecimal como
mensagem, chaves/MACs inválidos, rejeição de AES-192/AES-256, truncamento e
entradas grandes de 1 MiB. Também verificam alterações de um byte na chave ou na
mensagem e de um nibble em cada byte do MAC. Textos em outros idiomas nas
mensagens dos testes são dados intencionais de preservação de bytes; esses casos
e seus resultados esperados permanecem intactos.

As respostas conhecidas adicionais foram conferidas com OpenSSL 3.0.13. Rodar
os testes não requer OpenSSL. O pacote externo `cmac_test` usa somente a API
pública. Se a ferramenta de desenvolvimento `govulncheck` estiver instalada,
execute `govulncheck ./...`; diferencie vulnerabilidades alcançáveis de alertas
sem caminho de chamada. A ausência da ferramenta não significa que uma análise
de vulnerabilidades tenha sido concluída.

## Licença

Este projeto está disponível sob a [licença MIT](LICENSE).
Copyright (c) 2026 Hugo Ferreira Ferro.

A aprovação nos vetores e testes demonstra o comportamento testado; não
constitui certificação nem validação NIST/FIPS.

## Referências

- [RFC 4493 — The AES-CMAC Algorithm](https://www.rfc-editor.org/rfc/rfc4493.html)
- [NIST SP 800-38B — The CMAC Mode for Authentication](https://csrc.nist.gov/pubs/sp/800/38/b/upd1/final)
  ([PDF oficial](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf))
- [FIPS 197 — Advanced Encryption Standard](https://csrc.nist.gov/pubs/fips/197/final)
