# v11 Windows Agent vs Nidhogg

Data: 2026-04-21
Escopo: leitura de `v11/repo/agent-windows/` e `partnership/Nidhogg/` para mapear arquitetura, overlap de capabilities, gaps estruturais e prioridades de alinhamento.

Este documento e um report de arquitetura e organizacao. Nao descreve integracao operacional nem implementacao passo a passo.

---

## Resumo executivo

`Nidhogg` e um projeto Windows de duas camadas:

- driver kernel C++ com superficie ampla de IOCTL;
- client userland C++ para operar essa superficie.

O `Bat v11 agent-windows` e um agente userland Go, separado do Linux, com C2, persistencia, execucao de comandos, algumas TTPs Windows e bypasses locais em memoria.

A diferenca central nao e "falta de feature isolada". E diferenca de classe arquitetural:

- `Nidhogg` e um subsistema kernel-first com API local de controle.
- `Bat agent-windows` e um agente C2-first userland, sem driver, sem broker local de capabilities e sem camada de compatibilidade para funcoes de kernel.

Conclusao objetiva:

- o `agent-windows` nao esta pronto para absorver o `Nidhogg` como se fosse um modulo simples;
- o alinhamento exigiria primeiro um contrato de arquitetura, nao um porte direto de features;
- hoje o melhor uso do `Nidhogg` como referencia e orientar desenho de extensibilidade e taxonomia de capabilities do `agent-windows`, nao acoplamento imediato.

---

## Fontes lidas

Bat:
- `v11/repo/agent-windows/cmd/bat-agent/main.go`
- `v11/repo/agent-windows/Makefile`
- `v11/repo/agent-windows/internal/ttp/*.go`

Nidhogg:
- `partnership/Nidhogg/README.md`
- `partnership/Nidhogg/Nidhogg/IoctlShared.h`
- `partnership/Nidhogg/Nidhogg/NidhoggCommon.h`
- `partnership/Nidhogg/Nidhogg/Nidhogg.h`
- `partnership/Nidhogg/Nidhogg/IrpHandlers.cpp`
- `partnership/Nidhogg/Nidhogg/ProcessHandler.h`
- `partnership/Nidhogg/Nidhogg/RegistryHandler.h`
- `partnership/Nidhogg/Nidhogg/NetworkHandler.h`
- `partnership/Nidhogg/NidhoggClient/NidhoggInterface.h`

---

## Estado atual do Bat agent-windows

Arquitetura observada:

- `cmd/bat-agent/main.go` implementa loop simples de beacon, retry, fallback e dispatch.
- `internal/ttp/dispatch.go` expoe um conjunto curto de TTPs:
  - `1` masquerade
  - `2` revshell
  - `4` shell exec
  - `5` beacon extra
  - `6/40` persist
  - `7/41` creddump
  - `42` lateral
  - `43` AMSI bypass
  - `44` ETW bypass
  - `99/222` kill/destruct
- `internal/ttp/k_series_stub.go` declara explicitamente que Windows esta sem camada equivalente ao K-series:
  - `LocalStealthStatus() -> [stealth_skip: windows]`
  - `StartKSeries()` noop
- `internal/ttp/beacon.go` usa HTTP/TLS userland, sem broker local de device/driver.
- `Makefile` builda apenas um binario userland.

Leitura arquitetural:

- o agente Windows atual e monolitico e fino;
- a extensibilidade ocorre por `dispatch.go`, nao por capability bus;
- nao existe subsistema local separado para stealth, protecao de processo, registry mediation, port mediation ou driver lifecycle.

---

## Estado atual do Nidhogg

Arquitetura observada:

- driver kernel exposto por `\\.\Nidhogg`;
- cliente userland separado, com interface de comandos;
- grande superficie de IOCTL definida em `IoctlShared.h`;
- features parametrizadas por flags em `EnabledFeatures`;
- handlers dedicados por dominio:
  - `ProcessHandler`
  - `ThreadHandler`
  - `FileHandler`
  - `RegistryHandler`
  - `NetworkHandler`
  - `MemoryHandler`
  - `AntiAnalysisHandler`

Capacidades observadas no material lido:

- esconder, proteger e elevar processo;
- esconder e proteger thread;
- proteger arquivo;
- proteger e esconder chave/valor de registry;
- esconder portas;
- listar callbacks, routines e itens protegidos/ocultos;
- alterar assinatura de processo;
- patching, injection, dump de credenciais;
- controle de ETW providers;
- hide/unhide de modulo e driver;
- execucao de objeto COFF em kernel.

Leitura arquitetural:

- `Nidhogg` nao e um "set de tecnicas" apenas;
- ele e uma API local de kernel organizada por dominios;
- o client e um front-end para essa API.

---

## Diferenca arquitetural principal

### Bat agent-windows

- um processo Go;
- foco em C2 remoto;
- dispatch por numero de TTP;
- sem driver;
- sem camada local de mediacao;
- sem estado local sofisticado de capabilities.

### Nidhogg

- sistema em duas camadas;
- kernel como plano principal de enforcement;
- client userland apenas como operador local;
- API estruturada por IOCTL e handlers dedicados;
- estado persistente de itens protegidos/ocultos.

Implicacao:

O `agent-windows` atual nao tem pontos naturais para "absorver" o `Nidhogg`. O modelo de extensao do Bat hoje e adicionar funcoes em `dispatch.go`; o modelo do `Nidhogg` e expor dominios de kernel por API local.

---

## Mapa de overlap de capability

### Overlap direto

Existe overlap conceitual nestas areas:

- AMSI bypass
- ETW tampering
- cred dump
- injecao em processo
- alguma forma de protecao/stealth desejada no target Windows

Mas o overlap e superficial. O mecanismo subjacente e diferente:

- no Bat atual, AMSI/ETW sao patch local in-process em `bypass.go`;
- no `Nidhogg`, varias capacidades dependem de driver, callback handling e hooks/mediation no kernel.

### Overlap indireto

Areas onde o `Nidhogg` expande a taxonomia do problema, mas nao encaixa direto:

- process protection
- thread protection
- file protection
- registry hiding/protection
- port hiding
- callback inventory and tampering
- driver/module lifecycle

Essas capacidades nao tem contraparte estrutural no Bat Windows atual.

---

## Gaps precisos do Bat agent-windows em relacao ao Nidhogg

## G1. Falta uma camada de capability broker local

Hoje:
- `dispatch.go` chama funcoes diretamente.

No `Nidhogg`:
- o client conversa com um device bem definido;
- ha contratos por IOCTL e structs de dominio.

Impacto:
- qualquer crescimento do `agent-windows` tende a virar `dispatch.go` inchado;
- nao ha boundary claro entre orchestration C2 e capability execution.

Recomendacao:
- separar orchestration do C2 de uma camada local de capabilities, mesmo que inicialmente continue userland.

## G2. Falta taxonomia de dominios no lado Windows

Hoje:
- TTPs Windows estao agregadas em arquivos utilitarios.

No `Nidhogg`:
- processo, thread, arquivo, registry, rede e memoria sao dominios de primeira classe.

Impacto:
- o agente atual e funcionalmente disperso;
- nao ha mapa formal de capacidades Windows.

Recomendacao:
- reorganizar o `agent-windows` em dominios internos claros:
  - `process`
  - `thread`
  - `registry`
  - `network`
  - `memory`
  - `identity/persistence`

## G3. Sem contrato de extensibilidade para features nao-userland

Hoje:
- `k_series_stub.go` apenas marca skip.

Impacto:
- o servidor recebe somente um `stealth_skip`, sem semantica rica;
- nao existe ponto de encaixe para capability providers futuros.

Recomendacao:
- definir um contrato interno de provider Windows, mesmo vazio no `v11`:
  - status
  - inventory
  - capability availability
  - failure reason

## G4. Dispatch Windows esta atrasado em relacao ao Linux v11

Evidencia:
- nao ha `case 30/31/32/34/35/36/50/51` em `internal/ttp/dispatch.go`.

Impacto:
- assimetria funcional entre Linux e Windows;
- o Windows agent fica fora da taxonomia real do `v11`.

Recomendacao:
- antes de qualquer sofisticacao externa, fechar primeiro a paridade documental com o backlog do `v11`;
- distinguir no backlog o que e:
  - implementado
  - planejado
  - explicitamente fora do `v11` Windows

## G5. Env fingerprint Windows e fraco

Hoje:
- `env_fingerprint.go` reutiliza campos Linux (`PtraceScope`, `SELinuxMode`) para sinalizar informacoes Windows.

Impacto:
- semantica do protocolo fica distorcida;
- diagnostico do host Windows perde precisao.

Recomendacao:
- criar representacao Windows-explicita no protocolo, em vez de reutilizar chaves Linux.

## G6. Sem lifecycle local para componentes auxiliares

No `Nidhogg`:
- ha conceitos de features enabled/disabled, reflective load tradeoffs e lifecycle do driver.

No Bat Windows atual:
- nao existe lifecycle manager alem do proprio processo.

Impacto:
- qualquer futura camada adicional tende a acoplar diretamente no `main.go`.

Recomendacao:
- introduzir um bootstrap local com inventario de componentes e status.

---

## Gaps organizacionais para qualquer colaboracao futura com Nidhogg

## O1. Linguagem e toolchain diferentes

Bat Windows:
- Go

Nidhogg:
- C++ userland + C++ kernel driver + Visual Studio/WDK

Impacto:
- pipelines, build, artifacts e debug sao diferentes;
- o `Makefile` atual do Bat nao descreve esse mundo.

## O2. Modelo de entrega diferente

Bat Windows:
- um `.exe` unico.

Nidhogg:
- pelo menos driver + client, com device local e lifecycle proprio.

Impacto:
- a embalagem atual do Bat nao acomoda artefatos multiplos nem estados de componente.

## O3. Contrato de servidor insuficiente

O `bat-server` hoje entende um agente Windows, nao uma pilha Windows multi-componente.

Impacto:
- mesmo sem falar de integracao, o servidor hoje nao tem linguagem para inventariar capacidades por provider.

---

## O que vale a pena absorver conceitualmente do Nidhogg

Sem falar de porte direto, estas ideias de desenho sao valiosas:

- separar orchestration de capability execution;
- tratar processo/thread/registro/rede como dominios;
- ter uma API local clara entre controle e capability provider;
- inventariar features disponiveis e indisponiveis com motivo;
- modelar lifecycle e degradacao de capacidade explicitamente.

Esses principios melhorariam o `agent-windows` mesmo que nenhuma feature do `Nidhogg` fosse portada.

---

## O que nao esta pronto no Bat para qualquer alinhamento serio

### 1. Contrato interno de capability provider

Sem isso, qualquer colaboracao externa vira acoplamento ad hoc.

### 2. Paridade minima com o proprio v11

O Windows agent ainda nao acompanha a taxonomia do `v11` Linux em varias TTPs.

### 3. Semantica correta de fingerprint e inventory

Hoje o protocolo ainda carrega vi ses Linux-centric.

### 4. Build e packaging multiplos

O build atual so contempla um `.exe` userland.

---

## Prioridades recomendadas

## P1. Fechar a arquitetura do agent-windows antes de expandir

Objetivo:
- parar de crescer por acumulacao de funcoes em `dispatch.go`.

Ajustes:
- introduzir uma camada interna de capabilities;
- reorganizar modulos por dominio;
- separar orchestration do beacon de execution local.

## P2. Corrigir o contrato do protocolo para Windows

Objetivo:
- remover sobrecarga semantica de campos Linux.

Ajustes:
- definir fingerprint e inventory Windows-first;
- expor status de capability de forma tipada.

## P3. Fechar a paridade declarativa do v11

Objetivo:
- fazer o Windows agent caber corretamente no backlog e no session plan.

Ajustes:
- declarar o que esta dentro e fora do `v11`;
- marcar gaps objetivos no dispatch.

## P4. Definir modelo de componentes futuros

Objetivo:
- preparar o projeto para multiplos providers locais.

Ajustes:
- um manifesto simples de componentes:
  - `beacon/orchestrator`
  - `capability provider`
  - `inventory/status`
  - `artifact/build contract`

---

## Julgamento final

`Nidhogg` e uma boa referencia de maturidade de superficie Windows, mas o `Bat agent-windows` ainda esta uma geracao arquitetural atras em termos de modelagem local.

O problema principal nao e ausencia de uma ou outra feature. E ausencia de uma moldura interna onde features dessa classe fariam sentido.

Em termos objetivos:

- `Nidhogg` pode servir como referencia de taxonomia e desenho de dominios;
- o `agent-windows` atual ainda precisa de reorganizacao interna antes de qualquer alinhamento profundo;
- a melhor proxima etapa para o Bat nao e copiar capability, e fechar arquitetura.

---

## Proxima sessao recomendada

Titulo:
- `agent-windows architecture cleanup and capability model`

Escopo sugerido:
- documentar dominios internos do Windows agent;
- definir inventario de capability/status;
- mapear backlog real do Windows no `v11`;
- preparar o repositorio para evolucao modular.

Nao misturar com:
- alteracoes no Linux agent;
- saneamento do relay;
- mudancas grandes de protocolo sem documento previo.
