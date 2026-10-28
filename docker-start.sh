#!/bin/sh
# Container entrypoint. Hosting disks (Render, Railway volumes) are mounted owned by root, so when
# UPLOAD_DIR is set we start as root, hand that folder to appuser, then drop privileges for the app.
set -e

if [ "$(id -u)" = "0" ]; then
    if [ -n "$UPLOAD_DIR" ]; then
        mkdir -p "$UPLOAD_DIR"
        chown -R appuser:appuser "$UPLOAD_DIR"
    fi
    exec python -c '
import os, pwd, sys
user = pwd.getpwnam("appuser")
os.setgroups([])
os.setgid(user.pw_gid)
os.setuid(user.pw_uid)
os.environ["HOME"] = user.pw_dir
os.execvp("waitress-serve", ["waitress-serve", "--url-scheme=https", "--host=0.0.0.0", "--port=" + os.environ.get("PORT", "8080"), "wsgi:application"])
'
fi

exec waitress-serve --url-scheme=https --host=0.0.0.0 --port="${PORT:-8080}" wsgi:application
