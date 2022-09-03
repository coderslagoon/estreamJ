estreamJ 2.0.0
==============

Inspired by the [eSTREAM](https://www.cosic.esat.kuleuven.be/ecrypt/stream/) cipher project
at the time, the most promising algorithms got translated from their original
C sources into Java. Mostly for performance comparison, but also to see how
well they adapt to such a runtime.

AES and RC4 got implemented as well, mostly as reference points.

The Spritz algorithm, not part of the contest, joined in 2014

Test cases, using the official vectors, ensure that compatibility is maintained.
There's also a performance "lab" to check the speed of the algorithms.

It's a Maven project, so just:
```
mvn package
mvn install
```

Copyright 2006-2022 coderslagoon, Apache 2.0 License.
