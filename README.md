# NODE SCRIPT FOR REVERSE_PROXY ([by cortez24rus](https://github.com/cortez24rus/marz-reverse-proxy))

-----

### Нода использует ТОЛЬКО VLESS-TCP-REALITY (Steal from yourself), если вам нужен XTLS, etc. придется внести изменения в код скрипта
Этот Bash-скрипт автоматизирует установку и настройку Marzban Node вместе с несколькими важными системными компонентами. Он выполняет обновление системы, устанавливает необходимые пакеты, при необходимости устанавливает BBR, Xanmod для повышения производительности сети, настраивает Nginx с SSL через Certbot и Cloudflare, а также настраивает UFW и SSH.

> [!IMPORTANT]
>  Tested only on Ubuntu 24.04


-----

### Настройка Cloudflare
   - Привяжите ваш домен к Cloudflare.
   - Добавьте следующие DNS-записи:

| Type  | Name             | Content          | Proxy status  |
| ----- | ---------------- | ---------------- | ------------- |
| A     | subdomain_name   | node_ip          | DNS only      |
| A     | domain_name      | master_node_ip   | DNS only      |
| CNAME | www              | domain_name      | DNS only      |
   
Настройки SSL/TLS в Cloudflare:
   - Перейдите в раздел SSL/TLS > Overview и выберите опцию Full для настройки.
   - Установите минимальную версию TLS на TLS 1.3.
   - В разделе Edge Certificates включите TLS 1.3 (true).

-----

### Установка:

Чтобы начать настройку сервера, просто выполните следующую команду в терминале:
```sh
bash <(curl -Ls https://github.com/hzhexee/reverse-marz-node/raw/main/marz-node-script.sh)
```
В панели Marzban мастер-сервера требуется внести изменения в конфигурацию ядра xray, в inbound с TCP-REALITY нужно добавить serverName ноды по следующему примеру:

```
"serverNames": [
   "domain.com",
   "node.domain.com"
]
```

Также не забудьте добавить новый хост ноды:

![image](https://github.com/user-attachments/assets/d3c8c238-2df1-4cee-ad58-d5564bdc2693)
