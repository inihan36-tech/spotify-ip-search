# Spotify IP Search

Программа для Windows x64 ищет IPv4 для доменов Spotify и проверяет доступ по HTTPS.

1. Скачайте `SpotifyIpSearch.exe` из [Releases](https://github.com/inihan36-tech/spotify-ip-search/releases/latest) и запустите двойным щелчком.
2. Если IP пройдёт хотя бы 9 из 17 проверок, подтвердите запрос Windows. Программа обновит `hosts`, очистит веб-кэш Spotify и сбросит кэш DNS.
3. Перезапустите Spotify.

Для EXE ничего дополнительно устанавливать не нужно. Чтобы только проверить адреса, запустите `SpotifyIpSearch.exe --preview` в командной строке. Для подробностей добавьте `--verbose`.

Когда на GitHub появится новая версия, программа покажет ссылку на неё в конце запуска.

[Версия на Python](https://github.com/inihan36-tech/spotify-ip-search/releases/tag/v1.0.0) · [Лицензии компонентов EXE](cmd/spotify-ip-search/third-party-notices.txt)
