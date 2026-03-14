# ZTTP

Pure Zig (0.15) HTTP client/server library plus a thin CLI that I use for local testing and protocol experiments.

## Build and Test

### Normal build

```shell
zig build
zig build test
zig build smoke
```

### With the HTTP/3 code paths (still experimental)

```shell
zig build -Dhttp3=true
zig build test -Dhttp3=true
zig build run -Dhttp3=true -- request --http3 https://127.0.0.1:4433/health
```
