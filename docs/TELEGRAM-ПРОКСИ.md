# Прокси для Telegram на своём сервере

MTProto и WEB-прокси для Telegram ставятся на тот же VPS, что и VPN.
Мешают друг другу они только на порту 443 — об этом ниже.

**Зачем.** Бесплатный прокси работает как воронка: человек подключается
через него, видит ваш канал, а в канале — ваш VPN. Телеграм показывает
канал владельца прокси выше остальных: это встроенная плата за то, что вы
подняли своё железо. Отдельно рекламу платить не нужно.

---

## Что есть два вида

| | MTProto | WEB-прокси |
|---|---|---|
| Ссылка | `tg://proxy?...` | `tg://webproxy?...` |
| Где работает | телефон, десктоп | приложения с WebView |
| Приложение | AmneziaVPN, Nginxim | встроенный клиент Telegram |
| Программа | `mtproto-proxy` | `tproxy-server` |

Оба настраиваются независимо. Можно поставить один.

---

## Часть 1. MTProto

Это старый и самый совместимый способ. Работает везде.

### Установка

```bash
mkdir -p /opt/MTProxy && cd /opt/MTProxy
git clone https://github.com/TelegramMessenger/MTProxy.git .
make
```

### Генерация секрета

Секрет — это то, что делает прокси бесплатным для случайного человека:
без него порт не отвечает как прокси.

```bash
python3 -c "import secrets; print(secrets.token_hex(16))"
```

Запишите результат. Он понадобится в ссылке.

### Служба

```bash
cat > /etc/systemd/system/mtproxy.service <<'UNIT'
[Unit]
Description=MTProxy (Telegram)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/MTProxy
ExecStart=/opt/MTProxy/objs/bin/mtproto-proxy \
  -u nobody -p 8888 -H 443 \
  -S ВАШ_СЕКРЕТ \
  /opt/MTProxy/proxy-multi.conf -M 1
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable mtproxy
systemctl start mtproxy
systemctl status mtproxy
```

**Проверьте, что порт занят и служба жива:**

```bash
ss -tlnp | grep :443
systemctl is-active mtproxy
```

### Ссылка для раздачи

```
tg://proxy?server=ВАШ_АДРЕС&port=443&secret=ВАШ_СЕКРЕТ&bot=@ВАШ_БОТ&channel=@ВАШ_КАНАЛ
```

**Параметры `bot=` и `channel=` — не украшение.** Именно они заставляют
телеграм показывать ваш канал при подключении. Без них прокси работает,
но продвижения не будет.

**Проверка на телефоне:** нажмите ссылку в Telegram → «Подключить».
Должно появиться «Подключено» и адрес изменится.

---

## Часть 2. WEB-прокси

Схема сложнее, но у неё есть преимущество: она выглядит для сети как
обычный сайт по HTTPS.

```
телеграм → обычный сайт по HTTPS → релей → локальный MTProto → телеграм
```

По одному адресу одновременно живут и сайт, и прокси. Релей сам решает
по учётным данным: есть они — прокси, нет — обычная страница.

**Нужен домен с настоящим сертификатом.** Домен `sslip.io` годится для
проверки, но для боевого использования купите свой.

### Сборка

```bash
apt install -y golang
git clone --depth 1 https://github.com/telegramdesktop/tproxy-server.git
cd tproxy-server
go build -trimpath -o /usr/local/bin/tproxy-server ./cmd/tproxy-server
```

### Настройка

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin tproxy
mkdir -p /etc/tproxy-server
chown root:tproxy /etc/tproxy-server
chmod 0750 /etc/tproxy-server

cat > /etc/tproxy-server/config.json <<'JSON'
{
  "public_hostname": "ваш-домен",
  "listen": "127.0.0.1:8080",
  "admin_listen": "127.0.0.1:8081",
  "public_dir": "/var/www/ваш-сайт",
  "token_key_file": "/etc/tproxy-server/token.key",
  "static_routes": "exact",
  "profiles_file": "/etc/tproxy-server/profiles.json"
}
JSON

chown root:tproxy /etc/tproxy-server/config.json
chmod 0640 /etc/tproxy-server/config.json
```

**Ключ подписи — один раз, и он невосстановим:**

```bash
cd tproxy-server && bash deploy/ensure-token-key.sh
```

Потеряете — рассылка старых сессий перестанет работать. Сделайте копию
и положите в надёжное место.

### Профиль

```bash
cat > /etc/tproxy-server/profiles.json <<'JSON'
{
  "profiles": [{
    "name": "main",
    "secret": "СЕКРЕТ_ИЗ_ЧАСТИ_1",
    "backend": "127.0.0.1:443",
    "carrier_mode": "https"
  }]
}
JSON

chown tproxy:tproxy /etc/tproxy-server/profiles.json
chmod 0400 /etc/tproxy-server/profiles.json
```

### Служба

```bash
cat > /etc/systemd/system/tproxy.service <<'UNIT'
[Unit]
Description=tproxy-server (WEB proxy relay)
After=network.target mtproxy.service

[Service]
Type=simple
User=tproxy
Group=tproxy
ExecStart=/usr/local/bin/tproxy-server \
  -config /etc/tproxy-server/config.json \
  -profiles-file /etc/tproxy-server/profiles.json
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable tproxy
systemctl start tproxy
```

**Проверка:**

```bash
tproxy-server -config /etc/tproxy-server/config.json \
              -profiles-file /etc/tproxy-server/profiles.json -check
curl -s http://127.0.0.1:8081/healthz
```

Ожидаемо: `configuration is valid` и `ok`.

### Nginx перед релеем

```nginx
server {
    listen 8444 ssl;
    server_name ваш-домен;

    ssl_certificate     /etc/letsencrypt/live/ваш-домен/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ваш-домен/privkey.pem;

    client_max_body_size 4m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade           $http_upgrade;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}
```

**Не добавляйте сюда свои `X-Frame-Options` и CSP.** Мост приставляет свои
заголовки, и ваши могут помешать. Не отдавайте файлы сайта мимо релея —
на этом имени релей должен быть единственными воротами.

Проверка и применение:

```bash
nginx -t && systemctl reload nginx
curl -s https://ваш-домен:8444/ | head -3
```

### Ссылка

```
tg://webproxy?server=ваш-домен&port=8444&secret=СЕКРЕТ&bot=@ВАШ_БОТ&channel=@ВАШ_КАНАЛ
```

---

## Проблема с портом 443

Обе части хотят порт 443. Он может быть только один.

| Что отдать 443 | Что получить | Чем платим |
|---|---|---|
| **MTProxy** | работает везде, телефон и десктоп | WEB-прокси придётся ставить на 8444 |
| **WEB-релей** | WEB-прокси на стандартном порту | MTProxy придётся переносить |

**Обычно отдают 443 под MTProto** — он совместим со всеми клиентами, а
WEB-прокси на 8444 работает у тех, кто его поддерживает.

**Проверьте, не занял ли порт что-то ещё:**

```bash
ss -tlnp | grep :443
```

Если порт занят nginx — см. [Настройка nginx](#nginx-перед-релеем),
переведите nginx на свой порт.

---

## Честно о том, чего нет

### Нет маскировки FakeTLS

У крупных проектов секрет содержит в себе чужой домен — например, секрет
может выглядеть так, будто вы заходите на сайт банка. Их трафик
неотличим от обычного HTTPS.

**В базовой сборке этого нет.** Трафик пойдёт и будет выглядеть как
MTProto, а не как случайный заход на сайт.

Практически: **работать будет, но обнаружить и заблокировать проще.**

### WEB-прокси — не готовая вещь

Репозиторий сам называет свою работу proof-of-concept. Проверяйте на
реальном клиенте, а не по факту, что служба запустилась.

### Проверка порта с чужой машины ничего не значит

Если вы за VPN или прокси, соединение «устанавливается» **на любой
порт**, включая несуществующий. Проверьте:

```bash
nc -vz 8.8.8.8 9999        # такого порта не существует
```

Если пишет, что соединение есть — ваша проверка не работает вообще.
Единственный источник правды — `ss -tlnp` **на самом сервере**.

---

## Проверка, что всё работает

```bash
# на сервере
systemctl is-active mtproxy tproxy
ss -tlnp | grep -E ':443|:8444'
curl -s http://127.0.0.1:8081/healthz        # ожидается ok
curl -s http://127.0.0.1:8081/metrics | head  # счётчики сессий
```

**Настоящая проверка — с телефона.** Нажмите ссылку и посмотрите, есть
в приложении галочка и сменился ли адрес. Всё остальное проверяет, что
служба запущена, а не что прокси работает.

---

## Смена секрета

Секрет утекает легче, чем кажется. Сменить — минута:

```bash
NEW=$(python3 -c "import secrets; print(secrets.token_hex(16))")
sed -i "s/-S СТАРЫЙ_СЕКРЕТ/-S $NEW/" /etc/systemd/system/mtproxy.service
systemctl daemon-reload && systemctl restart mtproxy
grep -c "$NEW" /etc/systemd/system/mtproxy.service   # должно быть 1
```

**Не выводите секрет туда, где его увидят.** В чатах, в логах, в скриншотах.

**Если старый секрет где-то засветился** — это не «немного рискованно»,
это утечка: зная секрет, человек подключается к вашему серверу за ваш
счёт. Меняйте сразу.

Перед сменой убедитесь, что старый секрет не лежит в публичном месте:

```bash
grep -rl "СТАРЫЙ_СЕКРЕТ" /var/www /etc/sora
```

Ноль вхождений — можно менять спокойно.

---

## Что ещё почитать

- [README](../README.md) — про VPN
- [УСТАНОВКА-ПО-ШАГАМ.md](УСТАНОВКА-ПО-ШАГАМ.md) — если VPS ещё не настроен
- [СПРОСИ-ИИ.md](СПРОСИ-ИИ.md) — если что-то не получилось
- [MTProxy](https://github.com/TelegramMessenger/MTProxy)
- [tproxy-server](https://github.com/telegramdesktop/tproxy-server)