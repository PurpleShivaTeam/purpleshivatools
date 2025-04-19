# ARP Scan

Ferramenta para varredura de redes locais via ARP, com detecção de spoofing, relatórios em PDF/JSON/XML e recomendações de segurança integradas.

---

## ✨ Visão Geral

Este script realiza uma varredura ARP (Address Resolution Protocol) sobre uma rede local (LAN), identifica dispositivos conectados, detecta possíveis tentativas de spoofing (MAC duplicados), e gera relatórios com recomendações de segurança.

---

## ⚖️ Funcionalidades

- Escaneamento ARP paralelizado (ThreadPoolExecutor)
- Progresso em tempo real com cronômetro
- Detecção de spoofing ARP por MAC duplicado
- Relatórios gerados em:
  - **XML**
  - **JSON**
  - **PDF (ReportLab)**
- Recomendações de segurança embutidas (DAI, DHCP Snooping, VLAN, Port Security)

---

## 📝 Requisitos

- Python 3.6+
- Permissões de root para enviar pacotes ARP

### Bibliotecas:

```bash
pip install scapy reportlab
```

---

## 🕹️ Como Usar

### Modo Interativo

```bash
sudo python3 arpscan.py
```

Você será solicitado a inserir:

- Faixa de IP (ex: `192.168.0.0/24`)
- Formato de relatório desejado (`xml`, `json`, `pdf`)

### Modo Terminal (CLI)

```bash
sudo python3 arpscan.py -i 192.168.0.0/24 -f pdf
```

Parâmetros:

- `-i`, `--ip_range`: Faixa de IP (CIDR)
- `-f`, `--format`: Formato do relatório: `xml`, `json` ou `pdf`

---

## 🔎 O que o Script Faz

1. Valida se está sendo executado como root
2. Recebe uma faixa CIDR e a converte em endereços IP
3. Dispara requisições ARP para todos os IPs
4. Coleta MACs respondentes
5. Detecta MACs duplicados (spoofing)
6. Mostra resultados na tela com cores e tempo
7. Gera relatório no formato escolhido (xml, json, pdf)
8. Salva logs em `/var/log/purpleshivatoolslog`

---

## 🚧 Recomendações de Segurança Embutidas

- **Dynamic ARP Inspection (DAI)**
  - Intercepta e invalida ARPs suspeitos
  - Taxa padrão: 15 ARPs por segundo
- **DHCP Snooping**
  - Mantém tabela de DHCPs confiáveis
  - Bloqueia servidores DHCP não autorizados
- **Port Security**
  - Limita MACs por porta
  - Pode desativar porta ao detectar dispositivo não autorizado
- **VLAN Segmentation**
  - Reduz superfície de ataque
  - Separa domínios de broadcast

Essas recomendações são automaticamente adicionadas aos relatórios.

---

## 📂 Estrutura dos Relatórios

### XML

```xml
<ARPScanLog>
  <Summary>
    <TotalHostsFound>5</TotalHostsFound>
    <ScanStatus>Success</ScanStatus>
  </Summary>
  <Hosts>
    <Host>
      <IP>192.168.0.10</IP>
      <MAC>aa:bb:cc:dd:ee:ff</MAC>
    </Host>
    ...
  </Hosts>
  <SecurityRecommendations>
    <Recommendation>Dynamic ARP Inspection (DAI)</Recommendation>
    ...
  </SecurityRecommendations>
</ARPScanLog>
```

### JSON

```json
{
  "TotalHostsFound": 5,
  "Hosts": [
    {"ip": "192.168.0.10", "mac": "aa:bb:cc:dd:ee:ff"},
    ...
  ],
  "SecurityRecommendations": [
    "Dynamic ARP Inspection (DAI)",
    "DHCP Snooping",
    ...
  ]
}
```

### PDF

Relatório formatado com:
- Título, Data
- Total de hosts encontrados
- Lista de IPs e MACs
- Lista de recomendações

---

## ⚠️ Detecção de Spoofing

A ferramenta identifica quando um MAC aparece em mais de um IP:

```
[!] Possible ARP spoofing: MAC aa:bb:cc:dd:ee:ff seen for IPs 192.168.0.10 and 192.168.0.20
```

---

## 📅 Logs

Gerados com timestamp em:

```
/var/log/purpleshivatoolslog/
```

Exemplo:

- `arpscanlog_20250419_103001.json`

---

## ❌ Encerramento Seguro

- `Ctrl+C` invoca `signalHandler`
- O cronômetro e as threads são finalizados corretamente

---

## 🚀 Casos de Uso

- Testes de penetração internos
- Detecção de dispositivos não autorizados
- Simulações Purple Team
- Monitoramento de redes LAN

---

## 📄 Licença

Parte da suite **Purple Shiva Tools**.

> ⚠️ Utilize esta ferramenta com responsabilidade e apenas em redes que você tem autorização para auditar.

