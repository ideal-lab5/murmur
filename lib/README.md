# murmur-lib

This is middleware to allow easy integration of Murmur for various services. For example, it is used to build both the [murmur-cli](../cli/README.md) and the [murmur-api](todo).

Specifically, this library implements an IdentityBuilder for usage with the Ideal Network's core randomness beacon (produced with the ETF-Post-Finality Gadget). It also provides "plug-and-play" functions which can build data required to create and execute a murmur wallet (proxy) within the Ideal Network. 

## Generating metadata for the chain

``` shell
# clone and build the node
git clone git@github.com:ideal-lab5/etf.git
cd etf
cargo +stable build
# run a local node
./target/debug/node --dev
# use subxt to prepare metadata
cd /path/to/murmur/
mkdir artifacts
cargo install subxt-cli
# Download and save all of the metadata:
subxt metadata > ./artifacts/metadata.scale
```

