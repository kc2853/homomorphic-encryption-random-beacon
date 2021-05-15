# Networks and Mobile Systems - Spring 2021
Kevin Choi (kc2296)

### Distributed Randomness via HERB++
HERB (Homomorphic Encryption Random Beacon) is a [recent solution](https://eprint.iacr.org/2019/1320.pdf) dealing with distributed randomness. The idea is that nodes agree on a group key via DKG (distributed key generation), receive ciphertext shares every round (guaranteeing randomness from an information theoretical perspective), and decrypt the implicit group ciphertext in a way that requires threshold t number of nodes instead of all n nodes involved (hence tolerating up to n - t Byzantine nodes). These phases correspond to DKG phase, encryption phase, and decryption phase, respectively.

There exist two issues with the current HERB paper:
1. The correct encryption NIZK (for proving that an encryption has taken place correctly) seems to limit the message space of each entropy provider (assumed to be equal to key holders in this repository).
2. What happens if there is a huge asynchrony, e.g. when performing DKG? Could the DKG process (and perhaps elsewhere) be modified so that substantial asynchrony would be supported by the protocol?

We propose HERB++ via Elixir implementation:
1. Implemented is a new NIZK that resolves the prior restriction on a node's message space when chipping in its share of randomness into the protocol.
2. While each round's decryption phase follows encryption phase, it is able to occur concurrently alongside it, handling network asynchrony better in case some nodes proceed to the decryption phase earlier than others. Asynchronous DKG was explored but not implemented.

To replicate results, run:
```
mix deps.get
cd apps/herb
mix test
```