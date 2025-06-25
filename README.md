# NODE SCRIPT FOR REVERSE_PROXY ([by cortez24rus](https://github.com/cortez24rus/marz-reverse-proxy))

Все благодарности и звезды направлять автору оригинального скрипта - https://github.com/blagodaren/reverse-marz-node

-----

### Нода использует ТОЛЬКО VLESS-TCP-REALITY (Steal from yourself), если вам нужен XTLS, etc. придется внести изменения в код скрипта
Этот Bash-скрипт автоматизирует установку и настройку Marzban Node вместе с несколькими важными системными компонентами. Он выполняет обновление системы, устанавливает необходимые пакеты, при необходимости устанавливает BBR, Xanmod для повышения производительности сети, настраивает Caddy, а также настраивает UFW и SSH.

> [!IMPORTANT]
>  Tested only on Ubuntu 24.04


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
