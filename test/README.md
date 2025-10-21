Integration test helper files for docker-compose-based tests.

Usage:

1. Generate test CA and server certificate:

   chmod +x ./test/generate-certs.sh
   ./test/generate-certs.sh

2. Ensure you have a Rust probe client binary at `test/bin/probe_client` (or replace the `rust-client` service in `docker-compose.yml` with your built image).

   The probe client should accept at least these flags:
     --server <host:port>
     --ca <path to ca.crt>
     --probe   (perform a single connect probe and exit 0 on success)
     --run-test (run the full integration scenario and return exit code)

3. Make runner executable and run docker-compose:

   chmod +x ./test/run-tests.sh
   docker-compose up --build --abort-on-container-exit

Notes:
- The server certificate SAN includes `vnt-control`, `localhost`, and `127.0.0.1`.
- By default the compose file contains a placeholder `rust-client` service; replace it with your client image or a built binary.
