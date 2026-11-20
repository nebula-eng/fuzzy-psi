## What this changes

<!-- One paragraph. If it moves a reported number, give the before and after. -->

## Kind

- [ ] Defect fix
- [ ] New protocol, parser or detector
- [ ] New measurement or experiment
- [ ] Documentation
- [ ] Refactor with no behaviour change

## Design rules

- [ ] Standard library only: `hashlib`, `hmac`, `secrets`, `pow`. A patch that adds a cryptography dependency changes the premise of the project.
- [ ] No network access beyond `127.0.0.1`. `demo` opens one loopback TCP socket and nothing else.
- [ ] Byte counts and match counts are deterministic. Wall-clock numbers are measurements and are labelled as such wherever they appear.
- [ ] Security is discussed as leakage, not asserted. The consistency proof's own leak is measured in `results/leakage.json`.

- [ ] `PYTHONPATH=src python -m unittest discover -s tests -v` passes
- [ ] Reported numbers regenerated from `results/results.json`, not hand-edited
- [ ] Documentation updated where behaviour is user-visible

## Evidence

<!-- For a new detector or measurement: the input that triggers it, and one that must
not. False positives matter as much as detections. -->

## Notes for review

<!-- Ordering assumptions, overlap policy, performance trade-offs. -->
