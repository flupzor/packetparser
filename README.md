# packetparser

The packetparser library allows parsing and creating of IEEE 802.11 packets
embedded within a PCAP and/or Radiotap frame.

Currently support is limited to IEEE80211 Probe Request and Beacon frames. Only
IEEE80211 within Radiotap frames are supported at the moment.

OpenBSD implements radiotap a little bit differently by not padding the fields.
Currently padding is implemented and on by default, this means that for certain
devices radiotap frames on OpenBSD aren't parsed (properly)

On Linux/NetBSD and FreeBSD parsing should work properly.

In packetparser/tests/test_pcap.py there is a example on how to use the API.
