# Transparent TUF Root Monitoring for Sigstore

This repository provides a verifiable, append-only transparency log of The Update Framework (TUF) root metadata for the [Sigstore](https://www.sigstore.dev/) project.

It automatically monitors Sigstore's TUF repository for new root versions, adds them to a transparency log, and commits the updated log and root files back to this repository. This creates an independent, auditable history of Sigstore's root of trust, protecting against certain types of attacks on the TUF repository itself.

## 🎯 Goal

The primary goal is to provide a secondary source of truth for Sigstore's TUF root history. By maintaining a transparent and verifiable log, anyone can audit the sequence of root updates and verify that the history has not been tampered with. While highly unlikely due to the number of Sigstore TUF root key holders, if a majority of key holders were compromised along with the serving infrastructure, a malicious actor could create a split-view, serving different TUF roots to callers. Using the transprency log in this repository, users can verify that they have been served the correct TUF root.

## ⚙️ How It Works

A GitHub Actions workflow (`.github/workflows/monitor-tuf-root.yml`) runs on a daily schedule and can also be triggered manually. The process is as follows:

1. **Fetch New Roots**: The workflow checks the Sigstore TUF repository (`https://tuf-repo-cdn.sigstore.dev`) for new root metadata files (e.g., `1.root.json`, `2.root.json`, etc.) that are not yet present in this repository.

2. **Update Transparency Log**: If new root files are found, they are passed as entries to [Tessera POSIX one-shot tooling](https://github.com/transparency-dev/tessera/tree/main/cmd/examples/posix-oneshot). This program adds the new entries to the append-only log stored in the `tlog/` directory.

3. **Verify Log Integrity**: After adding new entries, the workflow uses the [`tessera/fsck`](https://github.com/transparency-dev/tessera/tree/main/cmd/fsck) tool to verify the integrity of the entire log.

4. **Commit Changes**: If the verification is successful, the new root files are moved to their final destination (`tuf-roots/sigstore/`), and both the new roots and the updated log files (`tlog/*`) are committed back to the repository.

## 🔍 Verification

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
      --custom_log_origin=github.com/haydentherapper/transparent-tuf \
      --custom_log_vkey=$(cat public.key)
    ```
