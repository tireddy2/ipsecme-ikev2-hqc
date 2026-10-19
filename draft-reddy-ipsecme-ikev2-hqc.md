---
title: Post-Quantum Key Exchange with HQC in the Internet Key Exchange Protocol Version 2 (IKEv2)
abbrev: HQC in IKEv2
docname: draft-reddy-ipsecme-ikev2-hqc-latest
category: std
ipr: trust200902
submissiontype: IETF
v: 3
area: "Security"
workgroup: "IP Security Maintenance and Extensions"
keyword:
- HQC
- IKEv2
- KEM
- Post-Quantum Cryptography
author:
- fullname: Tirumaleswar Reddy
  organization: Nokia
  city: Bangalore
  region: Karnataka
  country: India
  email: kondtir@gmail.com
- fullname: Hannes Tschofenig
  organization: University of the Bundeswehr Munich
  abbrev: UniBw M.
  city: Neubiberg
  code: '85577'
  country: Germany
  email: hannes.tschofenig@gmx.net
normative:
  RFC7296:
  RFC7383:
  RFC9242:
  RFC9370:
  IKEV2-MLKEM: I-D.ietf-ipsecme-ikev2-mlkem
  HQC:
    title: "Hamming Quasi-Cyclic (HQC)"
    author:
    - org: HQC team
    date: 2025-08-22
    target: https://pqc-hqc.org/doc/hqc_specifications_2025_08_22.pdf
informative:
  RFC9329:
  RFC9794:
  RFC9958:
  IKEV2-RT: I-D.ietf-ipsecme-ikev2-reliable-transport
  IKEV2-DOWNGRADE: I-D.ietf-ipsecme-ikev2-downgrade-prevention

--- abstract

This document specifies how to use HQC, a code-based Key Encapsulation
Mechanism (KEM), in the Internet Key Exchange Protocol Version 2
(IKEv2). HQC can be used alone or together with a traditional key
exchange to derive IKE and Child SA keys that resist attacks by
quantum computers. This document registers three Key Exchange Method
identifiers.

--- middle

# Introduction

HQC {{HQC}} is a code-based KEM selected by NIST for standardization
as a backup to ML-KEM. It relies on a different hardness assumption
than ML-KEM.

> Editor's note: This document is based on the HQC specification of
> 2025-08-22. Before publication as an RFC, the parameter set names,
> key and ciphertext encodings and sizes, shared secret size, and
> recipient tests need to be checked against the final NIST HQC
> standard and updated as necessary. The normative HQC reference also
> needs to be updated. Remove this note before publication.

{{IKEV2-MLKEM}} defines ML-KEM key exchange in IKEv2 {{RFC7296}}. This
document defines HQC key exchange in IKEv2 in the same way. It defines
HQC-1, HQC-3, and HQC-5 as IKEv2 Key Exchange Methods.

HQC can be used alone or in a PQ/T hybrid {{RFC9794}} with a
traditional (EC)DH key exchange using the multiple key exchanges of
{{RFC9370}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the KEM functions KeyGen, Encaps, and Decaps of
{{HQC}}. `ek` is the HQC encapsulation key, `dk` is the HQC
decapsulation key, `ct` is the HQC ciphertext, and `K` is the shared
secret.

# HQC in IKEv2 {#hqc-ikev2}

## Key Exchange Method Transform IDs {#ids}

| Name | Transform ID | NIST Security Category |
|:-----|-------------:|-----------------------:|
| hqc-1 | TBD1 | 1 |
| hqc-3 | TBD2 | 3 |
| hqc-5 | TBD3 | 5 |
{: #ids-table title="HQC Key Exchange Methods"}

## Key Exchange Payload {#ke}

As in Section 2.2 of {{RFC7296}}, initiator and responder refer to
the roles in the exchange being described, rather than necessarily
the original roles of the IKE SA. Either peer can initiate a
CREATE_CHILD_SA exchange. The peer initiating that exchange generates
the HQC keypair, including for any associated IKE_FOLLOWUP_KE
exchanges, and the other peer performs encapsulation.

The initiator runs KeyGen to obtain `ek` and `dk`. The Key Exchange
Data of the initiator's KE payload is `ek`.

The responder runs Encaps on `ek` to obtain `K` and `ct`. The Key
Exchange Data of the responder's KE payload is `ct`.

The initiator runs Decaps on `ct` with `dk` to obtain `K`.

`ek` and `ct` are the byte strings defined in Sections 3.5 and 3.6 of
{{HQC}}. {{len-table}} gives their lengths and the resulting KE
payload lengths. The KE payload length includes the 8-octet KE
payload header.

| Name | `ek` | Initiator KE payload | `ct` | Responder KE payload |
|:-----|-----:|---------------------:|-----:|---------------------:|
| hqc-1 | 2241 | 2249 | 4433 | 4441 |
| hqc-3 | 4514 | 4522 | 8978 | 8986 |
| hqc-5 | 7237 | 7245 | 14421 | 14429 |
{: #len-table title="HQC KE payload lengths in octets"}

`K` is 32 octets. It is used as the shared secret in the key
derivation of {{RFC7296}} and {{RFC9370}}, in the same way as the
(EC)DH shared secret.

## Use in IKE Exchanges {#exchanges}

HQC KE payloads exceed the typical path MTU. IKE_SA_INIT messages
cannot be fragmented using {{RFC7383}}. Therefore, HQC SHOULD NOT be
used in IKE_SA_INIT, unless the IKE SA uses TCP {{RFC9329}} or
reliable transport {{IKEV2-RT}}.

HQC SHOULD be negotiated as an additional key exchange using
{{RFC9370}}. During initial IKE SA establishment, an additional HQC
key exchange is carried in IKE_INTERMEDIATE {{RFC9242}}. For IKE SA
rekeying and Child SA creation or rekeying, an additional HQC key
exchange is carried in IKE_FOLLOWUP_KE. These exchanges can be
fragmented using {{RFC7383}}. HQC can also be used as the first or
only key exchange in CREATE_CHILD_SA as specified in {{RFC9370}}.

## Recipient Tests {#tests}

Version 2025-08-22 of {{HQC}} does not define checks on a received
`ek` or `ct` beyond their lengths.

The responder MUST check that the length of `ek` matches
{{len-table}}. If the check fails, the responder MUST reject `ek` and
SHOULD return an INVALID_SYNTAX notification.

The initiator MUST check that the length of `ct` matches
{{len-table}}. If the check fails, the initiator MUST fail the
exchange as specified for a failed ciphertext check in Section 2.2 of
{{IKEV2-MLKEM}}. In particular, the initiator MUST reject the
ciphertext, log the error, and stop creating the SA, without initiating
IKE_AUTH or the next IKE_INTERMEDIATE exchange. If the error occurs
in CREATE_CHILD_SA or IKE_FOLLOWUP_KE, the initiator MUST delete the
existing IKE SA and send a Delete payload in a new INFORMATIONAL
exchange. Deleting the IKE SA also closes its remaining Child SAs,
as specified in Section 1.4.1 of {{RFC7296}}.

HQC Decaps uses implicit rejection. A modified `ct` yields a different
`K`, and the exchange fails when the peers authenticate or use the
derived keys.

# Security Considerations

The security considerations of {{RFC7296}}, {{RFC9242}}, {{RFC9370}},
and {{IKEV2-MLKEM}} apply.

PQ/T hybrid use of HQC with (EC)DH is RECOMMENDED, following Section
13.3.1 of {{RFC9958}}.

Each HQC key exchange MUST use a fresh `ek` and `dk`, and fresh
encapsulation randomness. In a PQ/T hybrid, the HQC and (EC)DH keys
MUST NOT be derived from the same seed.

HQC has a small decryption failure probability, given in Section 4.1
of {{HQC}}. On a decryption failure, Decaps returns a pseudorandom
`K` instead of an error. The peers then derive different keys, and
the resulting IKE SA or Child SA does not work.

An attacker can try to downgrade the peers to a traditional key
exchange. The downgrade considerations of {{IKEV2-MLKEM}} and
{{IKEV2-DOWNGRADE}} apply.

# IANA Considerations {#iana}

IANA is requested to add the following entries to the "Transform Type
4 - Key Exchange Method Transform IDs" registry.

| Number | Name | Recipient Tests | Reference |
|:-------|:-----|:----------------|:----------|
| TBD1 | hqc-1 | RFC XXXX, {{tests}} | RFC XXXX |
| TBD2 | hqc-3 | RFC XXXX, {{tests}} | RFC XXXX |
| TBD3 | hqc-5 | RFC XXXX, {{tests}} | RFC XXXX |
{: #iana-table title="HQC Key Exchange Method registrations"}

RFC Editor: Replace XXXX with the RFC number of this document.

--- back

# Acknowledgments
{:numbered="false"}

This document follows the structure of {{IKEV2-MLKEM}}.
