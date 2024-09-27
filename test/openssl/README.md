
```bash
# create a key
openssl genrsa -out new.key 2048

# create a csr
openssl req -new -key new.key -config request.cnf -out new.csr

# sign with scepclient
scepclient \
    -server-url=http://127.0.0.1:2016/scep \
    -challenge=secret \
    -certificate=new_with_challenge.csr \
    -private-key new.key \
    -debug
```
