# Compiling

```
% git clone git@github.com:hannestschofenig/mbedtls.git mbedtls-eembc
% cd !$
% git git checkout --track origin/eembc-setup
```

```
% mkdir build
% cd build
% cmake .. -DENABLE_TESTING=OFF
```

# Running

```
% cd ../eembc
% ./launch_server.bash &
% ./launch_client.bash > l1.txt
% fg
% <ctl-c> // kill server
% ./contextualize.bash l1.txt > c1.txt
% ./analyze.pl c1.txt > a1.txt
```
