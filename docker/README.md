Docker Server
=============

Run the following commands from the root of the repo:

```
$ docker build -t stf_server -f docker/Dockerfile.server .
$ docker run -p 8080:8080 stf_server
```

quick test from host:
```
# curl -X POST -H "Content-Type:text/plain" -d "1 1 + ." http://localhost:8080
2 %
```

stf_server example output:
```
2021/03/30 21:28:15 POST "1 1 + ."
2021/03/30 21:28:15 stf_eval rc: 0
2021/03/30 21:28:15 stf_eval stf_status: 0
2021/03/30 21:28:15 stf_eval retbuf: "2 "
```
