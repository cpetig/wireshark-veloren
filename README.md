# This project contains a wireshark dissector for Veloren packets

The idea is to really make it verbose down to lower levels.
For this the individual streams need decoding, which isn't easy because they are
encoded twice in Rust (compress + bincode).
