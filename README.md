# Cert-manager scep issuer

> Can be used to issue certificates from a SCEP server

## How does it work
- It is based on the [sample-external-issuer](https://github.com/cert-manager/sample-external-issuer)
- It uses the [scep go library](https://github.com/micromdm/scep) to communicate with the SCEP server

## Testing

See [tests/README.md](tests/README.md) for details.

The mentioned [scep go library](https://github.com/micromdm/scep) comes with independent runnable server and client. It was [forked](https://github.com/mheers/scep) to add step debugging (for VSCode) for the client to see how the client works.

## TODO
- [x] test with a running cert-manager
- [ ] add renewal process
- [ ] be able to work with the secrets and certs in multiple namespaces
- [ ] implement clusterissuer
- [x] get the Secret that is referenced in the IssuerSpec and read the value to be used as the challenge password
- [ ] write more unit tests
- [ ] write e2e tests
- [ ] add instructions on how to use it
- [ ] add instructions on how to deploy it
