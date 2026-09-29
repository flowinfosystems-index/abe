# Trademarks

The following are trademarks of **Flow Information Systems** (https://flowinfo.co):

- **Flow Judgment Protocol™** and **FJP™**
- **Abe™** and **FJP Gate™**
- **FJP Compatible™** — the conformance mark (requires passing the FJP-CONF v0.1 Gate profile at Level 3)
- **FJP-CONF™** — the Flow Judgment Protocol Conformance standard
- **Judgment-Grounded Agent™** and **Judgment-Grounded™**
- **Flow™** and **Flow Information Systems™**
- The tagline **"DNS resolves location. Flow resolves importance."™**

The **™** symbol denotes a trademark claimed by Flow Information Systems. These
marks may or may not be registered in your jurisdiction; absence of a registration
symbol (®) does not indicate absence of rights.

## Code license vs. trademark rights

The source code in this repository is licensed under the Apache License, Version
2.0 (see `LICENSE`). **That license covers the code only. It grants no rights in
the trademarks above.** Trademark rights are separate from copyright and are not
transferred by the code license.

## What you may do (permitted, no permission needed)

You may make **truthful, nominative references** to the standard — for example:

- State that your product or agent **"conforms to FJP-CONF v0.1, Level 2."**
- Refer to **"the Flow Judgment Protocol"** or **"FJP-CONF"** to identify this
  standard when describing your implementation.
- Link to the canonical specification and this repository.

Such references must be accurate (e.g., only claim a conformance level your
implementation actually passes) and must not imply that Flow Information Systems
sponsors, endorses, or is affiliated with your product.

## What you may not do (requires written permission)

- Use **"FJP-CONF," "Flow Judgment Protocol," "FJP," "Judgment-Grounded Agent,"**
  or any confusingly similar term **as the name of your own product, service,
  standard, fork, or company.**
- Use any of these marks in a **logo, domain name, app name, or brand** in a way
  likely to cause confusion as to source, sponsorship, or affiliation.
- Modify the standard or the test suite and distribute the result **under the same
  name.** A modified version must carry a different name to avoid implying it is
  the authoritative FJP-CONF.
- Represent that a modified or forked version **is** FJP-CONF, or that its results
  are official FJP-CONF conformance results.

## Certification

Authoritative conformance verification and any use of an FJP-CONF certification or
conformance mark are administered solely by Flow Information Systems. The open test
suite in this repository lets anyone self-check; it does not confer the right to
issue official certifications or to use any FJP-CONF certification mark.

## Contact

For trademark permissions or questions: https://flowinfo.co


## FJP Compatible

Any implementation — including independent, third-party ones — may state **"FJP Compatible"** or
**"Conforms to FJP-CONF v0.1 Gate profile, Level 3"** when it:

- accepts valid FJP v0.1 requests and returns ACT / BLOCK / ESCALATE with the defined semantics,
- emits valid Judgment-Grounded Records with standard reason codes and verifiable record hashes, and
- passes the published conformance fixtures (`abe conformance`) at Level 3.

The claim must name the version and level and be reproducible. It must not imply that Flow Information Systems
built, sponsors or endorses the implementation.
