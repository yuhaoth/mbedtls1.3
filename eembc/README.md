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
% make
```

# Running

```
% cd ../eembc
% ./launch_server.bash &
% ./launch_client.bash > l1.txt
% fg
% <ctl-c> // kill server
% ./post-process-log.pl l1.txt > c1.txt
```


# Using `gprof`

To enable `gprof`, you need to first recompile with the GCC `-pg` options (this assumes you are using `gcc`):

```
% export CFLAGS=-pg
```

Then re-run `make` from the `build` folder.

Now that the `gprof` code has been installed into the binary, run the same steps above. The `ssl_client2` function will produce a file called `gmon.out` in the current working-directory. To create the `gprof` analysis report, run `gprof` with two arguments: the binary for the client, and the output file, like this:

```
gprof ./ssl/ssl_client2 gmon.out > analysis.txt
```

By default, `vim` should have syntax highlighting enabled for the analysis file, making it easier to read. The first table in the analysis file is the heatmap, followed by the static call charts. There is also a help file written into the analysis, which helps explain how to read the tables.


