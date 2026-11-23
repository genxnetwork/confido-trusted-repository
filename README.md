# GENXT Confido reference history

This repository retains GENXT's original reference files. New publisher
statements are issued from the reviewed `endorsement-requests/` records on
`master`; the reference bytes themselves are distributed by the public
[Teraveri registry](https://github.com/teraveri/attestation-references).

The `endorse-manifest` workflow fetches the registry manifest and reference
at the full commit in the request, checks both SHA-256 digests, and signs the
manifest digest using GitHub Artifact Attestations. The resulting Sigstore
bundle is a workflow artifact. Copy it to the corresponding registry entry's
`endorsements/genxt.sigstore.json` through review. The bundle says that GENXT
asserted this exact manifest; it does not promote a stage candidate to a
production-approved baseline. A consuming verifier must enforce its own
issuer, platform and registry-commit policy.

For the Genoa stage candidate, merge the registry's initial entry first,
then merge `endorsement-requests/genoa-stage-1071.json` into a protected
`master` branch and run **Endorse reference manifest** with request ID
`genoa-stage-1071` on `master`. Require review for changes to the request,
workflow and helper script. The workflow itself must remain in this GENXT
repository; a copy in another repository has a different signing identity.
