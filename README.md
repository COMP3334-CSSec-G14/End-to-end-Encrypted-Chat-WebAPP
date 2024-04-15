# End-to-end Encrypted Chat WebAPP

An End-to-end Encrypted Chat Web Application

## Framework

- Backend
  - Python 3
  - Flask
- Frontend
  - HTML + CSS + JS
- Database
  - MySQL
- Web Server
  - Nginx
- Container
  - Docker
  

## Server TLS Key & Cert Generate

```bash
openssl ecparam -genkey -name secp384r1 -out server.key
openssl req -new -key server.key -out server.csr -config csr.conf
openssl x509 -req -in server.csr -CA cacert.crt -CAkey cakey.pem -CAcreateserial -out server.crt -days 90 -sha384 -extfile v3.ext
```
