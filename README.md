# NODE SCRIPT FOR REVERSE_PROXY ([by cortez24rus](https://github.com/cortez24rus/marz-reverse-proxy))

-----

### Node using VLESS-TCP-REALITY (Steal from yourself) ONLY, if you want use XTLS, etc. make sure to make some edits
This Bash script automates the installation and configuration of a Marzban Node along with several essential system components. It performs system updates, installs necessary packages, optionally installs BBR, Xanmod for improved network performance, configures Nginx with SSL via Certbot and Cloudflare, and sets up UFW and SSH.

> [!IMPORTANT]
>  Tested only on Ubuntu 24.04


-----

### Setting up cloudflare
1. Upgrade the system and reboot the server.
2. Configure Cloudflare:
   - Bind your domain to Cloudflare.
   - Add the following DNS records:

| Type  | Name             | Content          | Proxy status  |
| ----- | ---------------- | ---------------- | ------------- |
| A     | subdomain_name   | node_ip          | DNS only      |
| A     | domain_name      | master_node_ip   | DNS only      |
| CNAME | www              | domain_name      | DNS only      |
   
3. SSL/TLS settings in Cloudflare:
   - Go to SSL/TLS > Overview and select Full for the Configure option.
   - Set the Minimum TLS Version to TLS 1.3.
   - Enable TLS 1.3 (true) under Edge Certificates.

-----

### Installation:

To begin configuring the server, simply run the following command in a terminal:
```sh
bash <(curl -Ls https://github.com/blagodaren/reverse-marz-node/raw/main/marz-node-script.sh)
```
