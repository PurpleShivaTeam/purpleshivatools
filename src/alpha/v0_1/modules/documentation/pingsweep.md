
# Ping Sweep Tool

Ferramenta para varredura de hosts em redes locais via ICMP (Ping Sweep), com relatório em PDF/JSON/XML e recomendações de segurança integradas.

---

## ✨ Visão Geral

Este script faz um Ping Sweep em uma faixa de IPs (CIDR), identifica quais hosts estão ativos respondendo a pacotes ICMP Echo Request, exibe progresso em tempo real com cronômetro, e gera relatórios detalhados incluindo recomendações de segurança.

---

## ⚖️ Funcionalidades

- Varredura paralelizada usando `ThreadPoolExecutor`  
- Progresso em tempo real com cronômetro  
- Formatos de relatório:
  - **XML**
  - **JSON**
  - **PDF** (ReportLab)  
- Recomendações de segurança embutidas para ICMP  
- Interface:
  - **Modo Interativo** (prompt)
  - **Modo CLI** com flags `-i/--ip_range` e `-f/--format`  
- Checagem de privilégio de root (raw sockets)

---

## 📝 Requisitos

- **Python 3.6+**  
- **Permissões de root** para enviar pacotes ICMP  
- Bibliotecas Python:
  ```bash
  pip install scapy reportlab
  ```

---

## 🕹️ Como Usar

### Modo Interativo

```bash
sudo python3 pingsweep.py
```

Você será solicitado a inserir:

- Faixa de IP (ex: `192.168.1.0/24`)  
- Formato de relatório desejado (`xml`, `json`, `pdf`)

### Modo CLI

```bash
sudo python3 pingsweep.py -i 10.0.0.0/24 -f pdf
```

Parâmetros:

- `-i`, `--ip_range`: Faixa de IP em notação CIDR  
- `-f`, `--format`: Formato do relatório: `xml`, `json` ou `pdf`

---

## 🔎 O que o Script Faz

1. Verifica se está sendo executado como root.  
2. Converte a faixa CIDR em lista de IPs.  
3. Dispara pacotes ICMP Echo Request para cada IP (paralelamente).  
4. Coleta respostas e marca hosts ativos.  
5. Atualiza e exibe progresso percentualmente com host atual e tempo.  
6. Após concluir, lista hosts ativos no console.  
7. Gera relatório no formato escolhido:
   - **XML**: Estrutura com timestamp, total de hosts e recomendações.
   - **JSON**: Objeto com metadados e lista de hosts.
   - **PDF**: Relatório formatado com título, data, lista de hosts e recomendações.
8. Salva logs em `/var/log/purpleshivatoolslog` com timestamp no nome do arquivo.

---

## 🚧 Recomendações de Segurança Embutidas

- **ICMP Rate Limiting** (High)  
  - Limita respostas ICMP para mitigar escaneamentos em massa.  
  - Métricas: `max_icmp_per_sec: 100`, `dropped_icmp_ratio ≥ 95%`.

- **Firewall ICMP Filtering** (Medium)  
  - Regras para permitir ICMP apenas de sub-redes confiáveis.  
  - Métricas: `filtered_hosts`, `trusted_zone_coverage`.

- **Network Segmentation** (Low)  
  - Isola ativos críticos em VLANs/sub-redes menores.  
  - Métricas: `segments_deployed`, `attack_surface_reduction`.

Essas recomendações são incluídas automaticamente em todos os relatórios.

---

## 📂 Estrutura dos Relatórios

### XML

```xml
<PingSweepLog>
  <Timestamp>2025-04-19T14:22:10</Timestamp>
  <TotalHosts>254</TotalHosts>
  <Hosts>
    <Host>10.0.0.1</Host>
    <Host>10.0.0.5</Host>
    …
  </Hosts>
  <SecurityRecommendations>
    <Recommendation>
      <ID>1</ID>
      <Title>ICMP Rate Limiting</Title>
      <Severity>High</Severity>
      <Description>Limit the rate of ICMP Echo Replies…</Description>
    </Recommendation>
    …
  </SecurityRecommendations>
</PingSweepLog>
```

### JSON

```json
{
  "timestamp": "2025-04-19T14:22:10",
  "total_hosts": 254,
  "hosts": ["10.0.0.1", "10.0.0.5", …],
  "security_recommendations": [
    {
      "id": 1,
      "title": "ICMP Rate Limiting",
      "severity": "High",
      "description": "Limit the rate of ICMP Echo Replies…"
    },
    …
  ]
}
```

### PDF

O PDF inclui:

- Cabeçalho com título e data  
- Total de hosts ativos  
- Lista de endereços IP  
- Seção de Recomendações de Segurança  

---

## ❌ Encerramento Seguro

- `Ctrl+C` dispara `signal_handler`  
- O cronômetro é finalizado e threads são encerradas graciosamente.

---

## 🚀 Casos de Uso

- Testes de penetração internos  
- Mapeamento rápido de hosts ativos  
- Simulações de Purple Team  
- Validação de isolamento de rede

---

## 📄 Licença

Parte da suite **Purple Shiva Tools**.

> ⚠️ Utilize esta ferramenta **com responsabilidade** e **apenas** em redes autorizadas.  