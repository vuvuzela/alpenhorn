# Alpenhorn

Alpenhorn is the first system for initiating an encrypted connection
between two users that provides strong privacy and forward secrecy
guarantees for **metadata**. Alpenhorn does not require out-of-band
communication other than knowing your friend's Alpenhorn username
(usually their email address). Alpenhorn's design, threat model, and
performance are described in our
[OSDI 2016 paper](https://davidlazar.org/papers/alpenhorn.pdf).

In short, Alpenhorn works well for bootstrapping conversations in
[Vuvuzela](https://github.com/vuvuzela/vuvuzela). Now users can start
chatting on Vuvuzela without having to exchange keys in person or over
some less secure channel.

A beta deployment of Alpenhorn and Vuvuzela is coming soon.
