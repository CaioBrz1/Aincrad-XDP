# TODO: Aincrad XDP Firewall

## Technical Debt (Refactoring)
- **Remove unnecessary unsafe blocks:** Review `aincrad-ebpf/src/main.rs` to remove `unsafe` blocks that are no longer required by the compiler or the current Aya API.
- **Clean up compilation warnings:** Fix `unused_imports` and other compilation warnings to ensure a 100% clean build (zero warnings).

## Planned Features
-  **Decay Logic:** Implement automatic penalty (reputation score) decay over time.
-  **Blocking Integration:** Connect `ban_until` logic to perform `XDP_DROP` on packets in eBPF when the ban is active.
-  **Extended Monitoring:** Improve UserSpace display with more detailed logs per IP.
