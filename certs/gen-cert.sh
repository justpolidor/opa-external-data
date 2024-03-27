openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -subj "/O=My Org/CN=External Data Provider CA" -out ca.crt
openssl genrsa -out server.key 2048
openssl req -newkey rsa:2048 -nodes -keyout server.key -subj "/CN=opa-external-data.gatekeeper-system" -out server.csr
openssl x509 -req -extfile <(printf "subjectAltName=DNS:opa-external-data.gatekeeper-system") -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt