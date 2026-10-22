# php2shell detection rules

Interim detection only. Patching is the fix. These rules reduce exposure and
raise the cost of exploitation; they do not remove the vulnerability.

## ModSecurity / CRS

```apache
# 1. Flag upload-progress triggers (legit apps that need it must be allowlisted).
SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" \
  "id:2026101,phase:2,deny,status:403,log,msg:'php2shell: upload progress trigger field'"

# 2. Reject absurdly long form field names (MB-scale names are an exploit primitive).
SecRule ARGS_NAMES "@rx ^.{262144,}$" \
  "id:2026102,phase:2,deny,status:413,log,msg:'php2shell: oversized form field name'"

# 3. Reject multipart bodies with no usable Content-Length at the edge.
SecRule REQUEST_METHOD "@streq POST" \
  "id:2026103,phase:1,chain,deny,status:411,log,msg:'php2shell: POST without length'"
  SecRule &REQUEST_HEADERS:Content-Length "@eq 0"
  SecRule REQUEST_HEADERS:Transfer-Encoding "!@rx chunked"
```

## nginx

```nginx
# Hard caps. Tune to the application; smaller is better.
client_max_body_size 8m;
client_body_buffer_size 128k;
large_client_header_buffers 4 16k;
client_header_buffer_size 4k;

# Per-source POST rate limiting.
limit_req_zone $binary_remote_addr zone=php_post:10m rate=10r/s;
server {
    location ~ \.php$ {
        limit_req zone=php_post burst=20 nodelay;
        # If the app never uploads files, refuse multipart outright:
        # if ($http_content_type ~* "multipart/form-data") { return 415; }
    }
}
```

Log the pieces you need to hunt:

```nginx
log_format php2shell '$remote_addr - $remote_user [$time_local] "$request" '
                     '$status $body_bytes_sent "$http_user_agent" '
                     'ct="$content_type" cl="$content_length"';
```

## Suricata

```
alert http any any -> any any (msg:"php2shell upload-progress trigger field"; \
  flow:to_server,established; http.method; content:"POST"; \
  http.request_body; content:"PHP_SESSION_UPLOAD_PROGRESS"; nocase; \
  sid:2026110; rev:1;)

alert http any any -> any any (msg:"php2shell oversized form field name"; \
  flow:to_server,established; http.method; content:"POST"; \
  http.request_body; pcre:"/name=\"[^\"]{262144,}\"/"; \
  sid:2026111; rev:1;)
```

## PHP error log / Apache / FPM

```bash
# Failure during request init, before any script line.
grep -E 'Allowed memory size .* exhausted .* in Unknown on line 0' \
     /var/log/php*.log /var/log/apache2/error.log

# Worker crashes / churn.
grep -E 'AH00052|signal 11|segfault|SIGSEGV' /var/log/apache2/error.log
journalctl -u php*-fpm --since '-1h' | grep -Ei 'segfault|signal 11|restart'

# Suspicious web-user child processes (should normally be empty).
ps -eo pid,ppid,user,args | awk '$3 ~ /www-data|apache|nginx/ && $4 ~ /^(sh|bash|dash|curl|wget|nc|python3?)$/'
```

## Response-side oracle

```bash
# PHPSESSID values longer than the normal 26-32 bytes.
grep -oE 'PHPSESSID=[^;[:space:]]+' access.log \
  | awk -F= 'length($2) > 40 {print}' | sort | uniq -c | sort -rn
```

## Sigma (process ancestry)

See `sigma-web-worker-shell.yml`.
