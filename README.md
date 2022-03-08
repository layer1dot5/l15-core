# L15


Layer One dot Five (L15) is an open source, decentralized protocol over Bitcoin that utilizes a construct similar to the Lightning channel as a limited trustless lockbox for a sidechain.
It can also be described as a sidechain-enabled iteration of the Lightning Network,
where the Lightning commitment data is recorded in the sidechain.
Thus, L15 provides the ability to create Lightning-style transactions where the outcomes depend on the sidechain consensus rules.

Compared to the original two-way pegged sidechains, L15's Lightning-style approach mitigates the trustless lockbox issue, but it also imposes some limitations on the types of smart contracts it can support.
Just like a Lightning channel, a particular L15 contract, for example, can interact only with a predefined amount of Bitcoin.
Another useful feature is that L15 protocol allows payer nodes to go offline while their payment instructions are being honored, thus enabling trustless subscription payments.

A more complex example is to create a stablecoin minted by the L15 sidechain as a loan and collateralized by Bitcoin.
This can help resolve the emerging contradiction that the Lightning network has to face:
while Bitcoin is strengthening its position as a value-preserving "digital gold" that nobody wants to spend,
the Lightning Network is there to facilitate fast spontaneous transactions.
Making L15 is compatible with the Lightning network gives exiting opportunity:
Bitcoin from the Lightning network channels can be sent to L15 contracts as collateral.
The stablecoin generated as a result can be used for the Lightning payments,
thus both preserving the "store of value" paradigm for Bitcoin and supporting the Lightning transactional capabilities at the same time.
