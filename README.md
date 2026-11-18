# Spotify IP Search

Скрипт для Windows ищет IPv4 для доменов Spotify и проверяет доступ по HTTPS.

1. Скачайте `spotify-ip-search-windows.zip` из [Releases](https://github.com/inihan36-tech/spotify-ip-search/releases/latest) и полностью распакуйте архив.
2. Запустите `start_spotify_search.cmd` и подтвердите запрос Windows на права администратора.
3. Если IP прошёл минимум 9 из 17 проверок, скрипт обновит `hosts`, очистит веб-кэш Spotify и сбросит кэш DNS. Затем перезапустите Spotify.

Нужны Python 3.9+ с командой `py`, `curl` 7.84+ и Windows PowerShell.

Чтобы только проверить адреса и увидеть готовые строки для `hosts`, запустите в папке со скриптом `py -3 find_spotify_ip.py`. Добавьте `--verbose` для подробного вывода.

Когда на GitHub появится новая версия, скрипт покажет ссылку на неё в конце запуска.
