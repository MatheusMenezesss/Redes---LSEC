# Sample Experiment: Baseline Link Reachability

## Objective

Validate baseline IP reachability between two lab nodes in the sample Containerlab topology.

## Hypothesis

If the topology boots correctly and interfaces are configured as documented, ICMP echo requests from `h1` to `r1` will succeed.

## Environment

- Topology: `infra/containerlab/topologies/lab-sample.clab.yml`
- Tooling: Containerlab, Docker, `tshark` (optional packet capture)

## Reproducibility steps

1. `make lab-up`
2. `docker exec -it clab-lab-sample-h1 ping -c 4 10.10.10.1`
3. (Optional) capture traffic with `tshark` on host or container interface.
4. `make lab-down`

## Expected results

- Ping packet loss below 100%
- Deterministic setup/teardown without orphan containers

## Notes

Store captures (`*.pcap`) and binary artifacts using Git LFS-tracked patterns.
