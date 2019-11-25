# Really Simple CA

```
$ go build ./cmd/...
$ ./rsca --cacert=test/ca.cert --cakey=test/ca.key issue test/client.pub
```

```
$ ./rsca --cacert=test-data/ca.cert --cakey=test-data/ca.key rest
$ curl http://localhost:3000/issue --data-binary @test-data/client.pub
```
