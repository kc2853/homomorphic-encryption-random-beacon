# Networks and Mobile Systems - Spring 2021
Kevin Choi (kc2296)

### Distributed Randomness via HERB++
HERB (Homomorphic Encryption Random Beacon) is a recent solution dealing with distributed randomness. The idea is that nodes agree on a group key via DKG (distributed key generation), receive ciphertext shares every round (guaranteeing randomness from an information theoretical perspective), and decrypt the implicit group ciphertext in a way that requires threshold t number of nodes instead of all n nodes involved.

There exist two issues with the current HERB paper:
1. The correct encryption NIZK (for proving that an encryption has taken place correctly) seems incorrect. Moreover, it is not even clear that this NIZK is essential to the protocol.
2. What happens if there is a huge asynchrony when performing DKG? Could the DKG process (and perhaps even the decryption process) be modified so that substantial asynchrony would be supported by the protocol?

We propose HERB++ via Elixir implementation.