# Chaffing WF-Defense Status

**Status:** Interim, improved, not literature-grade

## Description of Current Behavior

The chaffing / WTF-PAD decoy layer currently uses 5 realistic domains (Wikipedia, Google, GitHub, Reddit, Amazon) at one fixed mean interval (10s) for decoy destinations. 

While this is a real improvement over the previous 3 hardcoded DNS resolvers (1.1.1.1/8.8.8.8/9.9.9.9) and is much harder to filter at a glance, it is still a small, fixed, identical-across-every-install list with one fixed timing distribution. 

According to WTF-PAD / Walkie-Talkie literature (e.g., Juarez et al. ESORICS 2016; Wang & Goldberg USENIX Security 2017), this approach is insufficient for full Website Fingerprinting (WF) defense. The destination and timing diversity need to scale with and resemble the real traffic distribution, rather than being a short, fixed list.

## Future Work

To reach literature-grade WF-defense, the system must undergo a full redesign as described in the original specifications: sampling decoy destinations from the same large, varied pool that real circuit traffic uses. Until that redesign is implemented, the current implementation should be considered an interim measure.
