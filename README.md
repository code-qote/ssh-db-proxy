# SSH-DB-PROXY
### Прокси-модуль, обеспечивающий защищенный централизованный доступ к PostgreSQL с возможностью контроля и аудита действий пользователей.

<video src="files/readme.mov" width="640" height="480" controls></video>

## Быстрый старт

1. Перейдите в директорию generated
   ```shell
   cd dev/generated
   ```
2. Сгенерируйте SSH-сертификаты для db-proxy и пользователя.
    ```shell
    # host certificate
    ssh-keygen -t rsa -b 4096 -f host_ca -C host_ca && \
    ssh-keygen -f ssh_host_rsa_key -N '' -b 4096 -t rsa && \
    ssh-keygen -s host_ca -I example -h -n host.example.com -V +52w ssh_host_rsa_key.pub

    # user certificate
    ssh-keygen -t rsa -b 4096 -f user_ca -C user_ca && \
    ssh-keygen -f user-key -b 4096 -t rsa && \
    ssh-keygen -s user_ca -I username -n database_user1,database_user2 -V +365d user-key.pub
    ```
3. Сгенерируйте корневой CA
    ```shell
    openssl genrsa -out ca.key 2048 && \
    openssl req -new -x509 -days 365 -key ca.key -subj "/C=CN/ST=GD/L=SZ/O=DBProxy/CN=DBProxy Root CA" -out ca.pem
    ```
4. Сгенерируйте SSL-сертификат для PostgreSQL и CA db-proxy
    ```shell
    # PostgreSQL certificate 
    openssl req -newkey rsa:2048 -nodes -keyout server.key -subj "/C=CN/ST=GD/L=SZ/O=DBProxy/CN=host.example.com" -out server.csr && \
    echo "subjectAltName=DNS:host.example.com" > extfile.txt && \
    openssl x509 -req -extfile extfile.txt -days 365 -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.crt
   
    # db-proxy CA
    openssl genrsa -out proxy-ca.key 4096 && \
    openssl req -new -key proxy-ca.key -out proxy-ca.csr \
           -subj "/C=CN/ST=GD/L=SZ/O=DBProxy/CN=DBProxy" && \
    echo "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,digitalSignature,cRLSign, \
    keyCertSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer" > extfile.txt && \
    openssl x509 -req -in proxy-ca.csr -CA ca.pem -CAkey ca.key \
           -CAcreateserial -out proxy-ca.pem -days 3650 -sha256 \
           -extfile extfile.txt
    ```
5. Сгенерируйте TLS-сертификаты для авторизации аудитора в db-proxy
   ```shell
    openssl genrsa -out ca-key.pem 2048 && \
    openssl req -x509 -new -nodes -key ca-key.pem -days 365 -out ca-cert.pem -subj "/CN=myca" && \
    openssl genrsa -out server-key.pem 2048 && \
    openssl req -new -key server-key.pem -out server-csr.pem -subj "/CN=host.example.com" && \
    echo "subjectAltName=DNS:host.example.com" > extfile.txt && \
    openssl x509 -req -in server-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem \
     -days 365 -extfile extfile.txt && \
    openssl genrsa -out client-key.pem 2048 && \
    openssl req -new -key client-key.pem -out client-csr.pem -subj "/CN=example_auditor" && \
    openssl x509 -req -in client-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 365
   ```
6. Запустите docker образ
   ```shell
   cd .. && \
   docker-compose up --build
   ```

## Сборка
```shell
cd cmd/db-proxy && \
go build main.go -o db-proxy
```

## Подключение

1. Установить SSH-туннель
   ```shell
   ssh -N -L localhost:<local-port>:<db-address>:<db-port> <user>@<db-proxy-address> -p <db-proxy-port> -i user-key
   ```

2. Подключиться к PostgreSQL
   ```shell
   psql --username <user> --host localhost --port <local-port> --dbname <db-name>
   ```


## Получение аудитных событий
```shell
curl -X GET "https://<your-db-proxy-address>:<your-db-proxy-port>?count=<max-events-count>" \
--cert path/to/client/cert --key path/to/client/key --cacert path/to/ca/cert --silent | jq
```

## ABAC (Attribute-Based Access Control) условия

db-proxy использует ABAC для контроля доступа и аудита запросов к базе данных. Вот условия, которые вы можете использовать в конфигурации:

### IPCondition

Проверяет IP-адрес клиента относительно указанных подсетей.

**Пример:**
```yaml
rules:
  - conditions:
      - subnets:
          - "192.168.1.0/24"
          - "10.0.0.0/8"
        not: false  # опционально, по умолчанию false
    actions:
      not_permit: true
```
Запрещает доступ для клиентов из подсетей 192.168.1.0/24 и 10.0.0.0/8.

### DatabaseUsernameCondition

Проверяет имя пользователя базы данных по регулярным выражениям.

**Пример:**
```yaml
rules:
  - conditions:
      - regexps:
          - "admin.*"
          - "root"
        not: false
    actions:
       notify: true
       not_permit: true
```
Запрещает и уведомляет при попытках подключения с именами пользователей, начинающимися с "admin" или равными "root".

### DatabaseNameCondition

Проверяет имя базы данных по регулярным выражениям.

**Пример:**
```yaml
rules:
  - conditions:
      - regexps:
          - "production_.*"
        not: true
    actions:
       not_permit: true
```
Запрещает доступ к любой базе данных, кроме тех, которые начинаются с "production_".

### TimeCondition

Проверяет, происходит ли запрос в указанные временные интервалы.

**Пример:**
```yaml
rules:
  - conditions:
      - year:
          - from: 2023
            to: 2024
        month:
          - "january"
          - "december"
        day:
          - from: 1
            to: 15
        hour:
          - from: 9
            to: 17
        weekday:
          - "monday"
          - "tuesday"
          - "wednesday"
          - "thursday"
          - "friday"
        location: "Europe/London"
        not: false
    actions:
       not_permit: true
```
Отключает пользователей, которые пытаются получить доступ в рабочие дни с 9:00 до 17:00 в первой половине января или декабря 2023-2024 годов (по лондонскому времени).

### QueryCondition

Проверяет SQL-запросы на соответствие указанным типам операций, таблицам и столбцам.

**Пример:**
```yaml
rules:
  - conditions:
      - statement_type: "UPDATE"
        table_regexps:
          - "user.*"
        column_regexps:
          - "password"
          - "email"
        strict: true
        not: false
    actions:
       notify: true
       not_permit: true
       disconnect: true
```
Запрещает, отключает и уведомляет при попытках выполнить UPDATE-запросы к таблицам, начинающимся с "user", затрагивающим столбцы "password" или "email".

### Действия (Actions)

После обнаружения совпадения можно определить одно или несколько действий:

- **notify**: Отправляет уведомление
- **not_permit**: Запрещает выполнение запроса
- **disconnect**: Отключает пользователя

### Полный пример конфигурации

```yaml
rules:
  - conditions:
      - subnets:
          - "192.168.2.0/24"
        not: true
      - regexps:
          - "admin"
        not: false
    actions:
       notify: true
       not_permit: true
       disconnect: true
  
  - conditions:
      - statement_type: "DELETE"
        table_regexps:
          - ".*"
        strict: true
      - weekday:
          - "saturday"
          - "sunday"
        hour:
          - from: 0
            to: 8
        location: "UTC"
    actions:
       notify: true
```
Эта конфигурация:
1. Запрещает, отключает и уведомляет при попытках доступа пользователя "admin" из любой подсети, кроме 192.168.2.0/24
2. Запрещает выполнение DELETE-запросов в выходные дни с 00:00 до 08:00 UTC

Вы можете комбинировать различные условия для создания детальных правил доступа к вашей базе данных.