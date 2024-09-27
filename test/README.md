We want to start a SCEP Server to test out our library.

For this refer to https://github.com/micromdm/scep

# Preparation

## Init the CA
```bash
scepserver ca -init \
    -country DE \
    -common_name "ACME Inc" \
    -organization "acme-ca" \
    -organizational_unit "ACME CA" \
    -years 10
```


## Start the server
```bash
scepserver \
    -depot depot \
    -http-addr :2016 \
    -challenge=secret \
    -allowrenew 0 \
    -crtvalid 365 \
    -debug \
    -log-json
```

# Out-Of-Cluster-Testing

Here we only test the scepclient. We do not test the cert-manager-scep-issuer.

why? Because we want to see that the SCEP Server works.

## Issue a certificate
```bash
scepclient \
    -server-url=http://127.0.0.1:2016/scep \
    -challenge=secret \
    -private-key client.key \
    -cn "my-client" \
    -country DE \
    -debug \
    -organization "acme-scep-ca" \
    -ou "ACME CA"
```

# In-cluster

Now we want to test the cert-manager-scep-issuer.

```bash
# create a cluster
k3d cluster create --config k3d.conf.yaml

# install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.9.1/cert-manager.yaml

# install crds
make install

## we do everything in the default namespace right now
# kubectl create namespace sandbox
# kubens sandbox

# create a secret for the SCEP Server
kubectl create -f issuer-secret.yaml

# create the SCEP issuer
kubectl create -f issuer.yaml

# start the issuer implementation
make run # or in VS Code hit F5

# create a certificate request
kubectl create -f csr.yaml

# check the status of the certificate request and note the name to approve
kubectl get certificaterequests.cert-manager.io

# approve the certificate request
kubectl cert-manager approve example-com-th2k4
```
