# Оригинальный Sherlock — upstream integration

Этот репозиторий использует официальный проект [sherlock-project/sherlock](https://github.com/sherlock-project/sherlock) как upstream для движка и каталога сайтов.

- Upstream: https://github.com/sherlock-project/sherlock
- Каталог: `sherlock_project/resources/data.json`
- Лицензия upstream: MIT. Оригинальные copyright/license notices должны сохраняться при распространении исходного кода.
- Синхронизация каталога выполняется workflow `.github/workflows/sync-sherlock-data.yml`.
- Android APK собирается workflow `.github/workflows/android-apk.yml`.

Каталог — это определения публичных сайтов и правила проверки username, а не база пользователей. Официальный Python CLI Sherlock запускается в среде Python; Android APK в этом репозитории является интерфейсной оболочкой и требует настроенного backend URL для сетевого сканирования. Не обходите CAPTCHA, авторизацию и антибот-защиту.