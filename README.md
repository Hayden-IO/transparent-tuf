# Transparent TUF Root Monitoring

This repository demonstrates how to apply cryptographic transparency to The Update Framework (TUF) to provide a globally consistent view of the TUF repository. As an example, this repository maintains a verifiable, append-only transparency log TUF root metadata for the [Sigstore](https://www.sigstore.dev/) project.

It automatically monitors Sigstore's TUF repository for new root versions, adds them to a transparency log stored in the repository, appends a proof of log inclusion to the TUF root metadata, and commits the updated log and root files back to this repository.

## Goal

The primary goal is to provide a globally consistent view of a TUF repository. By maintaining a transparent and verifiable log, anyone can audit the sequence of root updates and verify that the history has not been tampered with. The security of the TUF repository is dependent on the security of the root keys. For Sigstore, a compromise is highly unlikely due to the number of Sigstore TUF root key holders. However, for any repository, if a majority of key holders were compromised along with the serving infrastructure, a malicious actor could create a split-view, serving different TUF roots to callers. Using the transprency log in this repository, users can verify that they have been served the correct TUF root.

The purpose of this example repository is demonstrate how easy it is to integrate verifiable transparency into TUF. Transparency tooling has come a long way from when it first started, and with just a few simple tools, a transparency log can be distributed alongside TUF metadata. It would be trivial to integrate the example GitHub Actions workflow into [TUF-on-CI](https://github.com/theupdateframework/tuf-on-ci).

## How It Works

This example uses the Sigstore TUF repository, but this would work for any TUF repository distributed via GitHub. If the TUF repository was not maintained on GitHub, then the transparency log would need to be hosted separately.

A GitHub Actions workflow (`.github/workflows/monitor-tuf-root.yml`) runs on a daily schedule and can also be triggered manually. The process is as follows:

1. **Fetch New Roots**: The workflow checks the Sigstore TUF repository (`https://tuf-repo-cdn.sigstore.dev`) for new root metadata files (e.g., `1.root.json`, `2.root.json`, etc.) that are not yet present in this repository.

2. **Update Transparency Log**: If new root files are found, they are passed as entries to [Tessera POSIX one-shot tooling](https://github.com/transparency-dev/tessera/tree/main/cmd/examples/posix-oneshot). This program adds the new entries to the append-only log stored in the `tlog/` directory. TUF roots are appended as canonicalized JSON.

3. **Append Inclusion Proof**: After adding new entries, an [inclusion proof](https://c2sp.org/tlog-proof) is computed using the log and appended to the TUF root metadata under `tlog_proof`. TUF verification would be expected to require a valid inclusion proof, which would be verified without needing access to the log, only the log's public key.

4. **Demonstrate Entry Verification**: The inclusion proof included with the TUF root is verified using the log's public key.

5. **Demonstrate Verifying Log Integrity**: The workflow uses the [`tessera/fsck`](https://github.com/transparency-dev/tessera/tree/main/cmd/fsck) tool to verify the integrity of the entire log.

6. **Commit Changes**: If the verification is successful, the new root files are moved to their final destination (`tuf-roots/sigstore/`), and both the new roots and the updated log files (`tlog/*`) are committed back to the repository.

## Log Verification

Anyone can clone this repository, verify the integrity of the transparency log and inspect the contents. You will need to have Go installed.

1. **Run the verification tool**:

    Run the `fsck` (filesystem check) command from the `tessera` project, pointing it at the local server and the public key.

    ```sh
    go run github.com/transparency-dev/tessera/cmd/fsck@main \
      --storage_url="files:///$(pwd)/tlog" \
      --public_key=public.key \
      --ui=false
    ```

2. **See the contents of the log**:

    ```sh
    go run github.com/mhutchinson/woodpecker@main \
      --custom_log_type=tiles --custom_log_url=file:///$(pwd)/tlog/ \
      --custom_log_origin=github.com/Hayden-IO/transparent-tuf \
      --custom_log_vkey=$(cat public.key)
    ```

Log verification also could include verifying that entries are appended in the correct numerical order.

## Future Work

The goal of this repository is to demonstrate a straightforward and practical approach to integrating verifiable transparency into TUF. I plan to propose a TAP to standardize the format of the log entry (OLPC canonical JSON) and the inclusion proof ([C2SP tlog-proof](https://c2sp.org/tlog-proof) in a new `tlog_proof` field).

Transparency logs should be witnessed to prevent split-views, where different views of the log are presented to different callers, which would mean that the TUF metadata is not globally consistent. As the [public witness network](https://witness-network.org) matures, we could trivially integrate public TUF repositories into the network to be witnessed.

I'd like to integrate this directly into TUF-on-CI. There's very little code needed. We'd depend on the `posix-oneshot` tooling to create and maintain the log. We'd need a tool to compute an inclusion proof and append it to the TUF root metadata. Proof computation could likely be an output from `posix-oneshot`. Finally we'd need to update TUF clients that implement the proposed TAP to verify inclusion proofs when present.
