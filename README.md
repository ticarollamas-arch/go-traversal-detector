# Detector de Path Traversal em Go

Análise estática que localiza usos de `filepath.Join`, `os.Open` e afins que recebem caminho de origem não confiável — e verifica se a **mesma função** tem uma barreira de contenção (`strings.HasPrefix`, `filepath.Rel`, `os.Root`, `SecureJoin`, ou um helper interno como `doSafeMakeDir`).

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Licença](https://img.shields.io/badge/licen%C3%A7a-MIT-green)

> **O que esta ferramenta NÃO faz:** não executa código, não prova exploração, não gera PoC. Ela aponta *candidatos a revisão manual*. Um achado é um ponto para você ir ler o código — nunca uma vulnerabilidade confirmada. Essa restrição é intencional e é o que torna a ferramenta confiável.

## Por que ela existe

Path traversal em Go quase sempre depende de uma coisa: o caminho montado com `filepath.Join` é contido dentro de um diretório base, ou não? A checagem costuma estar logo ao lado — mas às vezes numa função auxiliar. Um scanner ingênuo que só procura `filepath.Join` gera falso positivo em todo projeto. Este verifica a contenção antes de gritar.

## Uso

```bash
python3 gotraversal.py ./projeto-go
python3 gotraversal.py arquivo.go
python3 gotraversal.py --test
```

## Como classifica

- **revisar** — o sink recebe entrada suspeita e **nenhuma barreira** aparece na função. Vá ler o código e as funções que ela chama.
- **provavelmente-seguro** — há uma barreira de contenção na função. Ainda vale conferir se ela cobre o caminho específico.

## O caso que ensina

Rodado contra o `SafeMakeDir` do Kubernetes (`pkg/volume/util/subpath/subpath_linux.go`), o detector marca a função como **provavelmente-seguro** — porque ela delega para `doSafeMakeDir`, que contém a checagem de contenção. Um scanner que só olhasse a linha do `filepath.Join` concluiria "vulnerável" e geraria um report que seria fechado como não-aplicável. A diferença entre as duas ferramentas é a diferença entre um report aceito e um rejeitado.

## Limitações

- Análise por função, dentro de um arquivo — não segue a barreira se ela estiver em outro arquivo/pacote.
- Reconhece um conjunto conhecido de barreiras; padrões incomuns de sanitização podem gerar "revisar" indevido.
- É ponto de partida para leitura humana, não veredito.

## Licença

MIT
